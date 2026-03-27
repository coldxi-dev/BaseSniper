//
// Create by 青杉白衣 on 2023
//

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "memextend.h"

#include "sutils.h"
#include "mapqueue.h"
#include "varray.h"

namespace chainer
{

template <class T>
struct pointer_data {
    T address;
    T value;

    pointer_data() : address(0), value(0) {}
    pointer_data(T addr, T val) : address(addr), value(val) {}
};

template <class T>
struct pointer_pcount {
    size_t count;
    pointer_data<T> **data;

    pointer_pcount() : count(0) {}
};

template <class T>
struct pointer_dir {
    T address;
    T value;
    uint32_t start;
    uint32_t end;

    pointer_dir() {}
    pointer_dir(T addr, T val) : address(addr), value(val) {}
    pointer_dir(T addr, T val, uint32_t s, uint32_t e) : address(addr), value(val), start(s), end(e) {}
}; // [start, end)

template <class T>
struct pointer_range {
    int level;
    memtool::vm_static_data *vma;
    // std::vector<chainer::pointer_dir<T>> results;
    utils::mapqueue<chainer::pointer_dir<T>> results;

    pointer_range() {}
    pointer_range(int lvl, memtool::vm_static_data *v, utils::mapqueue<chainer::pointer_dir<T>> &&r) : level(lvl), vma(v), results(std::move(r)) {}
};

template <class T>
struct chain_info {
    std::vector<utils::mapqueue<size_t>> counts;
    std::vector<utils::mapqueue<chainer::pointer_dir<T> *>> contents;

    chain_info() {}
    chain_info(std::vector<utils::mapqueue<size_t>> &&c, std::vector<utils::mapqueue<chainer::pointer_dir<T> *>> &&c2) : counts(std::move(c)), contents(std::move(c2)) {}
};

struct cprog_header {
    char sign[128];
    // int max_offset;
    int module_count;
    int version;
    int size;
    int level; //[0, level)
};

template <typename T>
struct cprog_sym {
    T start;

    char name[128];
    int range;
    int count;
    int pointer_count;
    int level;
};

struct cprog_llen {
    int module_count;
    unsigned int count;
    int level;
};

template <typename T>
using cprog_data = pointer_dir<T>;

template <typename T>
struct cprog_sym_integr {
    cprog_sym<T> *sym;
    // std::vector<cprog_data<T> *> data;
    utils::varray<cprog_data<T>> data;

    cprog_sym_integr() {}
    cprog_sym_integr(cprog_sym<T> *s, utils::varray<cprog_data<T>> &&dat) : sym(s), data(std::move(dat)) {}
};

template <class T>
struct cprog_chain_info {
    char *addr;
    size_t size;
    std::vector<chainer::cprog_sym_integr<T>> syms;
    std::vector<utils::varray<cprog_data<T>>> contents;

    cprog_chain_info() : addr(nullptr), size(0ul) {}
    cprog_chain_info(std::vector<chainer::cprog_sym_integr<T>> &&s, std::vector<utils::varray<cprog_data<T>>> &&c) : addr(nullptr), size(0ul), syms(std::move(s)), contents(std::move(c)) {}

    cprog_chain_info(const cprog_chain_info &other) = delete;
    cprog_chain_info(cprog_chain_info &&other) noexcept : addr(nullptr), size(0ul) { *this = std::move(other); }

    cprog_chain_info &operator=(const cprog_chain_info &other) = delete;
    cprog_chain_info &operator=(cprog_chain_info &&other) noexcept
    {
        if (this == &other)
            return *this;

        addr = other.addr, size = other.size, syms = std::move(other.syms), contents = std::move(other.contents);
        other.addr = nullptr, other.size = 0ul;
        return *this;
    }

    ~cprog_chain_info()
    {
        if (addr != nullptr || size != 0ul) munmap(addr, size);
    }
};

template <typename T>
class base
{
public:
    void parse_cprog_bin_data(cprog_chain_info<T> &b_data);

    cprog_chain_info<T> parse_cprog_bin_data(FILE *f);

    base();

    ~base();
};

} // namespace chainer

#include "cbase.hpp"
