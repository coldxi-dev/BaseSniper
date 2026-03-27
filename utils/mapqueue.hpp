//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "mapqueue.h"

template <class T>
inline utils::mapqueue<T>::mapqueue()
{
    ssize = scapacity = 0;
    f = nullptr;
    data = nullptr;
}

template <class T>
inline utils::mapqueue<T>::mapqueue(const utils::mapqueue<T> &src)
{
    ssize = scapacity = 0;
    f = nullptr;
    data = nullptr;
    operator=(src);
}

template <class T>
utils::mapqueue<T>::mapqueue(utils::mapqueue<T> &&src) noexcept
{
    ssize = scapacity = 0;
    f = nullptr;
    data = nullptr;
    operator=(std::move(src));
}

template <class T>
inline utils::mapqueue<T> &utils::mapqueue<T>::operator=(const utils::mapqueue<T> &src)
{
    shrink();
    resize(src.ssize);
    if (src.data)
        memcpy(data, src.data, ssize * sizeof(T));

    return *this;
}

template <class T>
utils::mapqueue<T> &utils::mapqueue<T>::operator=(utils::mapqueue<T> &&src) noexcept
{
    if (this == &src)
        return *this;

    if (data) {
        munmap(data, scapacity * sizeof(T));
        fclose(f);
    }

    data = src.data;
    ssize = src.ssize;
    scapacity = src.scapacity;
    f = src.f;

    src.data = nullptr;
    src.f = nullptr;
    src.ssize = src.scapacity = 0;

    return *this;
}

template <class T>
inline utils::mapqueue<T>::~mapqueue()
{
    if (data) {
        fclose(f);
        munmap(data, scapacity * sizeof(T));
    }
}

template <class T>
void utils::mapqueue<T>::clear()
{
    ssize = 0;
}

template <class T>
inline void utils::mapqueue<T>::shrink()
{
    if (data) {
        fclose(f);
        munmap(data, scapacity * sizeof(T));
        ssize = scapacity = 0;
        data = nullptr;
    }
}

template <class T>
inline bool utils::mapqueue<T>::empty() const
{
    return ssize == 0;
}

template <class T>
inline size_t utils::mapqueue<T>::size() const
{
    return ssize;
}

template <class T>
inline size_t utils::mapqueue<T>::size_in_bytes() const
{
    return ssize * sizeof(T);
}

template <class T>
inline size_t utils::mapqueue<T>::max_size() const
{
    return 0x7FFFFFFF / sizeof(T);
}

template <class T>
inline size_t utils::mapqueue<T>::capacity() const
{
    return scapacity;
}

template <class T>
inline T &utils::mapqueue<T>::operator[](size_t i)
{
    return data[i];
}

template <class T>
inline const T &utils::mapqueue<T>::operator[](size_t i) const
{
    return data[i];
}

template <class T>
inline T *utils::mapqueue<T>::begin()
{
    return data;
}

template <class T>
inline const T *utils::mapqueue<T>::begin() const
{
    return data;
}

template <class T>
inline T *utils::mapqueue<T>::end()
{
    return data + ssize;
}

template <class T>
inline const T *utils::mapqueue<T>::end() const
{
    return data + ssize;
}

template <class T>
inline T &utils::mapqueue<T>::front()
{
    return data[0];
}

template <class T>
inline const T &utils::mapqueue<T>::front() const
{
    return data[0];
}

template <class T>
inline T &utils::mapqueue<T>::back()
{
    return data[ssize - 1];
}

template <class T>
inline const T &utils::mapqueue<T>::back() const
{
    return data[ssize - 1];
}

template <class T>
inline void utils::mapqueue<T>::map(FILE *new_f)
{
    int fd;
    struct stat st;

    shrink();
    f = new_f;
    fd = fileno(f);
    fstat(fd, &st);
    data = (T *)mmap(nullptr, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    data = (data == MAP_FAILED) ? nullptr : data;

    ssize = scapacity = (st.st_size / sizeof(T));
}

template <class T>
inline void utils::mapqueue<T>::swap(utils::mapqueue<T> &rhs)
{
    size_t rhs_size = rhs.ssize;
    rhs.ssize = ssize;
    ssize = rhs_size;
    size_t rhs_cap = rhs.scapacity;
    rhs.scapacity = scapacity;
    scapacity = rhs_cap;
    T *rhs_data = rhs.data;
    rhs.data = data;
    data = rhs_data;
    FILE *rhs_f = rhs.f;
    rhs.f = f;
    f = rhs_f;
}

template <class T>
inline size_t utils::mapqueue<T>::grow_capacity(size_t sz) const
{
    size_t new_capacity = scapacity ? (scapacity + scapacity / 2) : 8;
    return new_capacity > sz ? new_capacity : sz;
}

template <class T>
inline void utils::mapqueue<T>::resize(size_t new_size)
{
    if (new_size > scapacity)
        reserve(grow_capacity(new_size));

    ssize = new_size;
}

template <class T>
inline void utils::mapqueue<T>::resize(size_t new_size, const T &v)
{
    if (new_size > scapacity)
        reserve(grow_capacity(new_size));

    if (new_size > ssize)
        for (auto n = ssize; n < new_size; n++)
            memcpy(&data[n], &v, sizeof(v));

    ssize = new_size;
}

template <class T>
inline void utils::mapqueue<T>::reserve(size_t new_capacity)
{
    if (new_capacity <= scapacity)
        return;

    FILE *new_f = tmpfile();
    (void)!ftruncate(fileno(new_f), new_capacity * sizeof(T));
    T *new_data = (T *)mmap(nullptr, new_capacity * sizeof(T), PROT_READ | PROT_WRITE, MAP_SHARED, fileno(new_f), 0);
    new_data = (new_data == MAP_FAILED) ? nullptr : new_data;
    if (data) {
        memcpy(new_data, data, ssize * sizeof(T));
        munmap(data, scapacity * sizeof(T));
        fclose(f);
    }
    f = new_f;
    data = new_data;
    scapacity = new_capacity;
}

template <class T>
inline void utils::mapqueue<T>::push_back(const T &v)
{
    if (ssize == scapacity)
        reserve(grow_capacity(ssize + 1));

    memcpy(&data[ssize], &v, sizeof(v));
    ssize++;
}

template <class T>
template <typename... Args>
inline void utils::mapqueue<T>::emplace_back(Args &&...args)
{
    if (ssize == scapacity)
        reserve(grow_capacity(ssize + 1));

    //data[ssize] = T(std::forward<Args>(args)...);
    new (&data[ssize]) T(std::forward<Args>(args)...);
    ssize++;
}

template <class T>
inline void utils::mapqueue<T>::pop_back()
{
    ssize--;
}
