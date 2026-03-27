//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "membase.h"

template <typename T>
inline bool memtool::base::is_physical_addr(T addr)
{
    mem_remote->iov_base = &page_present;
    mem_remote->iov_len = sizeof(page_present);

    auto page_offset = addr / PAGE_SIZE * sizeof(size_t);
    syscall(SYS_preadv, page_handle, mem_remote, 1, page_offset);
    return ((1UL << 63) & page_present);
}

template <class T>
inline size_t *memtool::base::check_physical_addr(T addr, size_t size)
{
    size_t *dat, len;

    len = ((addr + size) / PAGE_SIZE - addr / PAGE_SIZE + 1);
    dat = new size_t[len];
    
    mem_remote->iov_base = dat;
    mem_remote->iov_len = sizeof(size_t) * len;

    auto page_offset = addr / PAGE_SIZE * sizeof(size_t);
    syscall(SYS_preadv, page_handle, mem_remote, 1, page_offset);
    return dat;
    return dat;
}

template <class T>
inline long memtool::base::check_physical_addr(T addr, size_t size, void *data)
{
    mem_remote->iov_base = data;
    mem_remote->iov_len = sizeof(size_t) * ((addr + size) / PAGE_SIZE - addr / PAGE_SIZE + 1);

    auto page_offset = addr / PAGE_SIZE * sizeof(size_t);
    return syscall(SYS_preadv, page_handle, mem_remote, 1, page_offset);
}

template <typename T, typename S>
inline T memtool::base::readv(S addr)
{
    T temp;
    mem_local->iov_base = &temp;
    mem_local->iov_len = sizeof(T);
    mem_remote->iov_base = reinterpret_cast<void *>(addr);
    mem_remote->iov_len = sizeof(T);
    syscall(SYS_process_vm_readv, target_pid, mem_local, 1, mem_remote, 1, 0);
    return temp;
}

template <typename S, typename T>
inline long memtool::base::readv(S addr, T *data)
{
    mem_local->iov_base = data;
    mem_local->iov_len = sizeof(T);
    mem_remote->iov_base = reinterpret_cast<void *>(addr);
    mem_remote->iov_len = sizeof(T);
    return syscall(SYS_process_vm_readv, target_pid, mem_local, 1, mem_remote, 1, 0);
}

template <class S>
inline long memtool::base::readv(S addr, void *data, size_t size)
{
    mem_local->iov_base = data;
    mem_local->iov_len = size;
    mem_remote->iov_base = reinterpret_cast<void *>(addr);
    mem_remote->iov_len = size;
    return syscall(SYS_process_vm_readv, target_pid, mem_local, 1, mem_remote, 1, 0);
}

template <typename S, typename T>
inline long memtool::base::writev(S addr, T data)
{
    mem_local->iov_base = &data;
    mem_local->iov_len = sizeof(T);
    mem_remote->iov_base = reinterpret_cast<void *>(addr);
    mem_remote->iov_len = sizeof(T);
    return syscall(SYS_process_vm_writev, target_pid, mem_local, 1, mem_remote, 1, 0);
}

template <class S>
inline long memtool::base::writev(S addr, void *data, size_t size)
{
    mem_local->iov_base = data;
    mem_local->iov_len = size;
    mem_remote->iov_base = reinterpret_cast<void *>(addr);
    mem_remote->iov_len = size;
    return syscall(SYS_process_vm_writev, target_pid, mem_local, 1, mem_remote, 1, 0);
}

template <typename T, typename... Args>
inline T memtool::base::read_pointer(T start, Args &&...args)
{
    T address;
    T offset[] = {(T)args...};

    address = start + offset[0];
    for (auto i = 1ul; i < sizeof...(args); ++i) {
        readv<T>(address, &address);
        address += offset[i];
    }
    return address;
}