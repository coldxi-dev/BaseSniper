//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "memextend.h"

template <typename F>
int memtool::extend::parse_process_maps(char *path, F &&call)
{
    FILE *f;
    vm_area_data vma;
    char *line;
    size_t len;

    f = fopen(path, "r");
    if (f == nullptr)
        return -1;

    line = nullptr;
    len = 0;
    while (getline(&line, &len, f) > 0) {
        *vma.name = 0;
        sscanf(line, "%lx-%lx %4s %lx %31s %lu %127s\n", &vma.start, &vma.end, vma.perms, &vma.offset, vma.dev, &vma.inode, vma.name);
        // if (strstr(vma.perms, "r") == nullptr)
        //    continue;

        vma.range = det_mem_range(vma.name, vma.perms);
        vma.prot = get_perms_prot(vma.perms);

        call(vma);
    }

    free(line);
    return 0;
}

template <class F, class... Args>
void memtool::extend::employ_memory_block(size_t start, size_t size, char **buffer, int &index, memtool::vm_area_data *vma, F &&call, Args &&...args)
{
    char *buf;

    std::unique_lock<std::mutex> lock(mem_mutex);
    if (index < 0)
        mem_condition.wait(lock, [&index] { return index >= 0; });

    buf = buffer[index];
    --index;
    lock.unlock();

    // readv(start, buf, size);
    call(buf, start, size, vma, std::forward<Args>(args)...);

    lock.lock();
    ++index;
    buffer[index] = buf;
    lock.unlock();

    mem_condition.notify_one();
}

template <class C, class F>
void memtool::extend::divide_memory_to_block(size_t start, size_t end, memtool::vm_area_data *vma, char **buffer, int &index, int size, C &cache, F &&call)
{
    auto employ_memory = [buffer, &call, &index, vma](auto s, auto e, auto &dat) { employ_memory_block(s, e, buffer, index, vma, call, dat); };

    auto push_pool = [&start, &employ_memory, &cache](auto t) {
        auto &dat = cache.emplace_back(typename C::value_type{});

        utils::thread_pool->pushpool(employ_memory, start, t, std::ref(dat));

        start += t;
    };

    utils::split_num_to_avg(end - start, size, push_pool);
}

template <class F>
void memtool::extend::divide_memory_to_block(size_t start, size_t end, memtool::vm_area_data *vma, char **buffer, int &index, int size, F &&call)
{
    auto employ_memory = [buffer, &call, &index, vma](auto s, auto e) { employ_memory_block(s, e, buffer, index, vma, call); };

    auto push_pool = [&start, &employ_memory](auto t) {
        utils::thread_pool->pushpool(employ_memory, start, t);

        start += t;
    };

    utils::split_num_to_avg(end - start, size, push_pool);
}

template <class F>
void memtool::extend::for_each_memory_call(size_t start, size_t end, bool rest, int count, int size, F &&call)
{
    int index;
    char **buffer = new char*[count];

    index = count - 1;
    for (auto i = 0; i <= index; ++i)
        buffer[i] = new char[size];

    if (rest)
        goto limit;

    for (auto vma : vm_area_vec)
        call(vma->start, vma->end, vma, buffer, index);

    goto wait_for_finish;

limit:
    for (auto vma : vm_area_vec) {
        size_t max, min;

        max = std::max(vma->start, start);
        min = std::min(vma->end, end);
        if (max <= min) call(vma->start, vma->end, vma, buffer, index);
    }

wait_for_finish:
    utils::thread_pool->wait();

    for (auto i = 0; i < count; ++i) delete[] buffer[i];
    delete[] buffer;
}

template <class C, class F>
auto memtool::extend::for_each_memory_impl<C, F>::for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call)
{
    size_t t;
    std::vector<C> cache;

    auto for_each = [size, &call, &cache](auto start, auto end, auto vma, auto buffer, int &index) {
        if (vma->prot & PROT_READ) divide_memory_to_block(start, end, vma, buffer, index, size, cache, call);
    };

    t = 0;
    for (auto &vma : vm_area_vec) {
        if (vma->prot & PROT_READ) t += DIV_ROUND_UP(vma->end - vma->start, size);
    }
    cache.reserve(t);

    for_each_memory_call(start, end, rest, count, size, for_each);
    return cache;
}

template <class F>
void memtool::extend::for_each_memory_impl<void, F>::for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call)
{
    auto for_each = [size, &call](auto start, auto end, auto vma, auto buffer, auto &index) {
        if (vma->prot & PROT_READ) divide_memory_to_block(start, end, vma, buffer, index, size, call);
    };

    for_each_memory_call(start, end, rest, count, size, for_each);
}

template <class C, class F>
auto memtool::extend::for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call)
{
    return for_each_memory_impl<C, F>::for_each_memory_area(start, end, rest, count, size, std::forward<F>(call));
}

template <class F>
void memtool::extend::for_each_page_size(size_t start, size_t len, F &&call)
{
    size_t offset;

    while (len) {
        offset = std::min(PAGE_SIZE - (start & (PAGE_SIZE - 1)), len);

        call(start, offset);

        len -= offset;
        start += offset;
    }
}

template <class F>
void memtool::extend::check_page_fault(size_t start, size_t len, F &&call)
{
    size_t size;

    size = 0;
    auto do_in_page = [&size, &call](auto s, auto z) {
        if (is_physical_addr(s)) {
            size += z;
            return;
        }

        if (size == 0)
            return;

        call(s - size, size), size = 0;
    };

    for_each_page_size(start, len, do_in_page);
    if (size != 0) call(start + len - size, size);
}

template <class F>
void memtool::extend::check_page_fault(size_t start, size_t len, void *data, F &&call)
{
    size_t index, size, *dat;

    dat = (size_t *)data;
    index = size = 0;
    auto do_in_page = [&size, &call, &index, dat](auto s, auto z) {
        if (dat[index++] & (1UL << 63)) {
            size += z;
            return;
        }

        if (size == 0)
            return;

        call(s - size, size), size = 0;
    };

    for_each_page_size(start, len, do_in_page);
    if (size != 0) call(start + len - size, size);
}
