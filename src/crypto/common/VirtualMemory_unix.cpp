/* XMRig
 * Copyright (c) 2018-2020 tevador     <tevador@gmail.com>
 * Copyright (c) 2018-2023 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2023 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto/common/VirtualMemory.h"
#include "backend/cpu/Cpu.h"
#include "crypto/common/portable/mm_malloc.h"


#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sys/mman.h>

#include <iostream>
#include <cstdio>

#include <unistd.h>
#include <fcntl.h>

#ifdef XMRIG_OS_APPLE
#   include <libkern/OSCacheControl.h>
#   include <mach/mach.h>
#   include <mach/vm_statistics.h>
#   include <pthread.h>
#   include <TargetConditionals.h>
#   if defined(XMRIG_IOS_DUAL_JIT)
extern "C" kern_return_t mach_vm_remap(
    vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance
);
#   endif
#   ifdef XMRIG_ARM
#       define MEXTRA MAP_JIT
#   else
#       define MEXTRA 0
#   endif
#else
#   define MEXTRA 0
#endif


#ifdef XMRIG_OS_LINUX
#   include "crypto/common/LinuxMemory.h"
#endif


#ifndef MAP_HUGE_SHIFT
#   define MAP_HUGE_SHIFT 26
#endif


#ifndef MAP_HUGE_MASK
#   define MAP_HUGE_MASK 0x3f
#endif

#ifdef XMRIG_OS_FREEBSD
#   ifndef MAP_ALIGNED_SUPER
#       define MAP_ALIGNED_SUPER 0
#   endif
#   ifndef MAP_PREFAULT_READ
#       define MAP_PREFAULT_READ 0
#   endif
#endif


#ifdef XMRIG_SECURE_JIT
#   define SECURE_PROT_EXEC 0
#else
#   define SECURE_PROT_EXEC PROT_EXEC
#endif


#if defined(XMRIG_OS_LINUX) || (!defined(XMRIG_OS_APPLE) && !defined(XMRIG_OS_FREEBSD))
static inline int hugePagesFlag(size_t size)
{
    return (static_cast<int>(log2(size)) & MAP_HUGE_MASK) << MAP_HUGE_SHIFT;
}
#endif


bool xmrig::VirtualMemory::isHugepagesAvailable()
{
#   ifdef XMRIG_OS_LINUX
    return std::ifstream("/proc/sys/vm/nr_hugepages").good() || std::ifstream("/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages").good();
#   elif defined(XMRIG_OS_MACOS) && defined(XMRIG_ARM)
    return false;
#   else
    return true;
#   endif
}


bool xmrig::VirtualMemory::isOneGbPagesAvailable()
{
#   ifdef XMRIG_OS_LINUX
    return Cpu::info()->hasOneGbPages();
#   else
    return false;
#   endif
}


bool xmrig::VirtualMemory::protectRW(void *p, size_t size)
{
    // this is macos JIT safety feature, not available on ios. Remove it for jailbroken/JIT-enabled devices and use the standard mprotect instead. same for other calls
//#   if defined(XMRIG_OS_APPLE) && defined(XMRIG_ARM)
    //pthread_jit_write_protect_np(false); 
//    return true;
//#   else
    return mprotect(p, size, PROT_READ | PROT_WRITE) == 0;
//#   endif
}


bool xmrig::VirtualMemory::protectRWX(void *p, size_t size)
{
    return mprotect(p, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}


bool xmrig::VirtualMemory::protectRX(void *p, size_t size)
{
    bool result = true;

//#   if defined(XMRIG_OS_APPLE) && defined(XMRIG_ARM)
    //pthread_jit_write_protect_np(true);
//#   else
    result = (mprotect(p, size, PROT_READ | PROT_EXEC) == 0);
//#   endif

#   if defined(XMRIG_ARM)
    flushInstructionCache(p, size);
#   endif

    return result;
}


#   if defined(XMRIG_IOS_DUAL_JIT)
namespace {

static void breakPrepareJitRegion(mach_vm_address_t addr, size_t len)
{
    asm volatile(
        "mov x0, %0\n"
        "mov x1, %1\n"
        "brk #0x69"
        :
        : "r"(addr), "r"(len)
        : "x0", "x1", "memory"
    );
}

} // namespace
#   endif


bool xmrig::VirtualMemory::allocateDualJitMemory(size_t size, void **rx, void **rw)
{
    if (!rx || !rw) {
        return false;
    }

#   if defined(XMRIG_IOS_DUAL_JIT)
    // iOS 26 JIT workaround: mmap RX, remap to buf_rx, register via brk #0x69, downgrade buf_rw to RW.
    // See jit_example_ios26.cpp in the project root.
    const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const size_t vmSize = (size + pageSize - 1) & ~(pageSize - 1);

    void *buf_rw = mmap(nullptr, vmSize, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf_rw == MAP_FAILED) {
        return false;
    }

    mach_vm_address_t buf_rx = 0;
    vm_prot_t cur_prot = 0;
    vm_prot_t max_prot = 0;

    const kern_return_t kr = mach_vm_remap(
        mach_task_self(),
        &buf_rx,
        vmSize,
        0,
        VM_FLAGS_ANYWHERE,
        mach_task_self(),
        reinterpret_cast<mach_vm_address_t>(buf_rw),
        FALSE,
        &cur_prot,
        &max_prot,
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        munmap(buf_rw, vmSize);
        return false;
    }

    breakPrepareJitRegion(buf_rx, vmSize);

    if (mprotect(buf_rw, vmSize, PROT_READ | PROT_WRITE) != 0) {
        munmap(buf_rw, vmSize);
        munmap(reinterpret_cast<void*>(buf_rx), vmSize);
        return false;
    }

    *rw = buf_rw;
    *rx = reinterpret_cast<void*>(buf_rx);
    return true;
#   else
    void *mem = allocateExecutableMemory(size, false);
    if (!mem) {
        return false;
    }

    *rx = mem;
    *rw = mem;
    return true;
#   endif
}


void xmrig::VirtualMemory::freeDualJitMemory(void *rx, void *rw, size_t size)
{
    if (!rx && !rw) {
        return;
    }

#   if defined(XMRIG_IOS_DUAL_JIT)
    const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const size_t vmSize = (size + pageSize - 1) & ~(pageSize - 1);

    if (rw) {
        munmap(rw, vmSize);
    }

    if (rx && rx != rw) {
        munmap(rx, vmSize);
    }
#   else
    (void) rx;
    freeLargePagesMemory(rw, size);
#   endif
}


void *xmrig::VirtualMemory::allocateExecutableMemory(size_t size, bool hugePages)
{
#   if defined(XMRIG_OS_APPLE)
    //std::cout<<"trying to allocate JIT memory, size = "<<size<<std::endl;
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0); //removed MEXTRA flag. it is defined as MAP_JIT, but that does not exist in ios

#   ifdef XMRIG_ARM
    //pthread_jit_write_protect_np(false);
#   endif
#   elif defined(XMRIG_OS_FREEBSD)
    void *mem = nullptr;

    if (hugePages) {
        mem = mmap(0, size, PROT_READ | PROT_WRITE | SECURE_PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED_SUPER | MAP_PREFAULT_READ, -1, 0);
    }

    if (!mem) {
        mem = mmap(0, size, PROT_READ | PROT_WRITE | SECURE_PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

#   else

    void *mem = nullptr;

    if (hugePages) {
        mem = mmap(0, align(size), PROT_READ | PROT_WRITE | SECURE_PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | hugePagesFlag(hugePageSize()), -1, 0);
    }

    if (!mem) {
        mem = mmap(0, size, PROT_READ | PROT_WRITE | SECURE_PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

#   endif

    //perror("mmap");
    //std::cout<<"mem = "<<mem<<std::endl;
    return mem == MAP_FAILED ? nullptr : mem;
}


void *xmrig::VirtualMemory::allocateLargePagesMemory(size_t size)
{
#   if defined(XMRIG_OS_APPLE)
    //std::cout<<"trying to allocate large page memory, size = "<<size<<std::endl;
    void *mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0); //removed VM_FLAGS_SUPERPAGE_SIZE_2MB which causes invalid argument on iOS
#   elif defined(XMRIG_OS_FREEBSD)
    void *mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED_SUPER | MAP_PREFAULT_READ, -1, 0);
#   else
    void *mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | hugePagesFlag(hugePageSize()), 0, 0);
#   endif

    //perror("mmap");
    //std::cout<<"mem = "<<mem<<std::endl;
    return mem == MAP_FAILED ? nullptr : mem;
}

std::string getDocumentsPath(const std::string& filename) {
    const char* home = getenv("HOME");
    if (home) {
        return std::string(home) + filename;
    }
    return "";
}

bool xmrig::VirtualMemory::allocateFileBackedMemory() {
    //std::cout<<"entering allocateFileBackedMemory, size="<<m_size<<std::endl;
    std::string path = getDocumentsPath("/Documents/cache.bin");
    //std::cout<<"cache file path is "<<path<<std::endl;
    //sleep(5);
    
    // 1. Create the file (O_CREAT) with Read/Write permissions (O_RDWR)
    // S_IRUSR | S_IWUSR gives the owner read/write access
    int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open failed");
        std::cout<<"allocateFileBackedMemory open failed"<<std::endl;
        return false;
    }

    // 2. CRITICAL STEP: Stretch the file to the desired size
    // If you skip this, writing to the memory later will cause SIGBUS.
    if (ftruncate(fd, m_size) == -1) {
        perror("ftruncate failed");
        std::cout<<"allocateFileBackedMemory ftruncate failed"<<std::endl;
        close(fd);
        return false;
    }

    // 3. Now map it
    void* addr = mmap(NULL, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    
    close(fd); // You can close fd now; the map stays alive

    if (addr == MAP_FAILED) {
        perror("allocateFileBackedMemory mmap failed");
        std::cout<<"allocateFileBackedMemory mmap failed"<<std::endl;
        return false;
    }

    m_scratchpad = static_cast<uint8_t*>(addr);
    return true;
}


void *xmrig::VirtualMemory::allocateOneGbPagesMemory(size_t size)
{
#   ifdef XMRIG_OS_LINUX
    if (isOneGbPagesAvailable()) {
        void *mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | hugePagesFlag(kOneGiB), 0, 0);

        return mem == MAP_FAILED ? nullptr : mem;
    }
#   endif

    return nullptr;
}


void xmrig::VirtualMemory::flushInstructionCache(void *p, size_t size)
{
#   if defined(XMRIG_OS_APPLE)
    sys_icache_invalidate(p, size);
#   elif defined (HAVE_BUILTIN_CLEAR_CACHE) || defined (__GNUC__)
    __builtin___clear_cache(reinterpret_cast<char*>(p), reinterpret_cast<char*>(p) + size);
#   endif
}


void xmrig::VirtualMemory::freeLargePagesMemory(void *p, size_t size)
{
    munmap(p, size);
}


void xmrig::VirtualMemory::osInit(size_t hugePageSize)
{
    if (hugePageSize) {
        m_hugePageSize = hugePageSize;
    }
}


bool xmrig::VirtualMemory::allocateLargePagesMemory()
{
#   ifdef XMRIG_OS_LINUX
    LinuxMemory::reserve(m_size, m_node, hugePageSize());
#   endif

    m_scratchpad = static_cast<uint8_t*>(allocateLargePagesMemory(m_size));
    if (m_scratchpad) {
        m_flags.set(FLAG_HUGEPAGES, true);

        madvise(m_scratchpad, m_size, MADV_RANDOM | MADV_WILLNEED);
        
        if (mlock(m_scratchpad, m_size) == 0) {
            m_flags.set(FLAG_LOCK, true);
        }

        return true;
    }

    return false;
}


bool xmrig::VirtualMemory::allocateOneGbPagesMemory()
{
#   ifdef XMRIG_OS_LINUX
    LinuxMemory::reserve(m_size, m_node, kOneGiB);
#   endif

    m_scratchpad = static_cast<uint8_t*>(allocateOneGbPagesMemory(m_size));
    if (m_scratchpad) {
        m_flags.set(FLAG_1GB_PAGES, true);

        madvise(m_scratchpad, m_size, MADV_RANDOM | MADV_WILLNEED);

        if (mlock(m_scratchpad, m_size) == 0) {
            m_flags.set(FLAG_LOCK, true);
        }

        return true;
    }

    return false;
}


void xmrig::VirtualMemory::freeLargePagesMemory()
{
    if (m_flags.test(FLAG_LOCK)) {
        munlock(m_scratchpad, m_size);
    }

    freeLargePagesMemory(m_scratchpad, m_size);
}
