//
// Create by 青杉白衣 on 2023
//

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <utility>

namespace utils
{

template <typename T>
struct mapqueue {
    FILE *f;

    size_t ssize;
    size_t scapacity;

    T *data;

    typedef T value_type;
    typedef value_type *iterator;
    typedef const value_type *const_iterator;

    mapqueue();

    mapqueue(const mapqueue<T> &src);
    mapqueue(mapqueue<T> &&src) noexcept;

    mapqueue<T> &operator=(const mapqueue<T> &src);
    mapqueue<T> &operator=(mapqueue<T> &&src) noexcept;

    ~mapqueue();

    void clear();
    void shrink();

    bool empty() const;
    size_t size() const;
    size_t size_in_bytes() const;
    size_t max_size() const;
    size_t capacity() const;

    T &operator[](size_t i);

    const T &operator[](size_t i) const;

    T *begin();
    const T *begin() const;
    T *end();
    const T *end() const;

    T &front();
    const T &front() const;

    T &back();
    const T &back() const;

    void map(FILE *new_f);

    void swap(mapqueue<T> &rhs);

    size_t grow_capacity(size_t sz) const;

    void resize(size_t new_size);
    void resize(size_t new_size, const T &v);

    void reserve(size_t new_capacity);

    void push_back(const T &v);

    template <typename... Args>
    void emplace_back(Args &&...args);

    void pop_back();
};

} // namespace utils

#include "mapqueue.hpp"