//
// Create by 青杉白衣 on 2023
//

#pragma once

#include <stdio.h>
#include <unistd.h>

#include <utility>

namespace utils
{

template <typename T>
struct varray {
    size_t ssize;

    T *data;

    typedef T value_type;
    typedef value_type *iterator;
    typedef const value_type *const_iterator;

    varray();

    varray(const varray<T> &src) noexcept;
    varray(varray<T> &&src) noexcept;

    varray<T> &operator=(const varray<T> &src) noexcept;
    varray<T> &operator=(varray<T> &&src) noexcept;

    ~varray();

    size_t size() const;

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

    void swap(varray<T> &rhs);

    void resize(size_t s_size);

    void set_data(T *begin);
    void set_data(T *begin, T *end);
    void set_data(T *begin, size_t s_size);
};

} // namespace utils

#include "varray.hpp"