//
// Create by 青杉白衣 on 2023
//

#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h> // for PAGE_SIZE
#include <unistd.h>

#include "memsetting.h"

namespace memtool
{

class base
{
private:
    static inline thread_local iovec mem_local[1];

    static inline thread_local iovec mem_remote[1];

    static inline thread_local size_t page_present;

    static inline int page_handle = -1;

protected:
    base();
    ~base();

    base(const memtool::base &b) = delete;
    base(memtool::base &&b) = delete;
    base &operator=(const memtool::base &b) = delete;
    base &operator=(memtool::base &&b) = delete;

public:
    static inline pid_t target_pid = -1;

    static int get_package_uid(const char *package);

    static int get_pid_by_uid(int uid);

    static int get_pid(const char *package);

    static int judge_target_bit(pid_t pid);

    static void close_target_pagemap();

    static void open_target_pagemap();

    template <typename T>
    static bool is_physical_addr(T addr);

    template <typename T>
    static size_t *check_physical_addr(T addr, size_t size);

    template <typename T>
    static long check_physical_addr(T addr, size_t size, void *data);

    template <typename T, typename S>
    static T readv(S addr);

    template <typename S, typename T>
    static long readv(S addr, T *data);

    template <typename S>
    static long readv(S addr, void *data, size_t size);

    template <typename S, typename T>
    static long writev(S addr, T data);

    template <typename S>
    static long writev(S addr, void *data, size_t size);

    template <typename T, typename... Args>
    static T read_pointer(T start, Args &&...args);
};

} // namespace memtool

#include "membase.hpp"