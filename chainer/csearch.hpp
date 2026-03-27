//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "csearch.h"

static auto search_pointer_by_bin_gt = [](auto &&n, auto &&target) { return utils::address_of(n)->address < target; };

static auto get_pointer_by_bin_gt = [](auto &&vma, auto &&target) { return vma->end < target; };

template <class T>
void chainer::search<T>::output_pointer_to_file(FILE *f, T *buffer, T start, size_t maxn, T min, T sub)
{
    T value;
    size_t size;
    int lower, upper;
    pointer_data<T> data;

    auto &avec = memtool::extend::vm_area_vec;
    size = avec.size();

    for (auto i = 0ul; i < maxn; ++i) {
        value = (*(buffer + i)) & 0xffffffffffff; // u can & 0xffffffffffff ......

        if ((value - min) > sub )
            continue;

        utils::binary_search(avec, get_pointer_by_bin_gt, value, size, lower, upper);

        if ((size_t)lower == size || value < avec[lower]->start)
            continue;

        data.address = start + i * sizeof(T);
        data.value = value;
        fwrite(&data, sizeof(data), 1, f);
    }
}

template <class T>
void chainer::search<T>::filter_pointer_to_fmmap(char *buffer, T start, size_t len, memtool::vm_area_data *vma, FILE *&f)
{
    T min, max, sub;

    f = tmpfile(); // wb+;
    if (f == nullptr)
        return;

    min = memtool::extend::vm_area_vec.front()->start,
    max = memtool::extend::vm_area_vec.back()->end;
    sub = max - min;

    if (memtool::extend::readv(start, buffer, len) == -1) {
        fclose(f), f = nullptr;
        return;
    }

    output_pointer_to_file(f, (T *)buffer, start, len / sizeof(T), min, sub);

    fflush(f);
}

template <class T>
void chainer::search<T>::filter_pointer_to_fmmap_by_page(char *buffer, T start, size_t len, memtool::vm_area_data *vma, FILE *&f)
{
    size_t *dat;
    T min, max, sub;

    f = tmpfile(); // wb+;
    if (f == nullptr)
        return;

    min = memtool::extend::vm_area_vec.front()->start,
    max = memtool::extend::vm_area_vec.back()->end;
    sub = max - min;

    auto out_pointers = [this, &f, buffer, min, sub](auto s, auto z) {
        if (memtool::extend::readv(s, buffer, z) == -1)
            return;

        output_pointer_to_file(f, (T *)buffer, s, z / sizeof(T), min, sub);
    };

    dat = memtool::base::check_physical_addr(start, len);
    memtool::extend::check_page_fault(start, len, dat, out_pointers);

    delete[] dat;
    fflush(f);
}

template <class T>
template <typename P>
void chainer::search<T>::filter_pointer_from_fmmap(P &&input, chainer::pointer_data<T> *start, size_t count, size_t offset, std::atomic<size_t> &total, utils::list_head<pointer_pcount<T>> *block)
{
    int lower, upper;
    size_t size, pcount;
    T min, max, sub, value;
    pointer_data<T> *data, **save;

    min = memtool::extend::vm_area_vec.front()->start;
    max = memtool::extend::vm_area_vec.back()->end;
    sub = max - min;
    size = input.size();

    pcount = 0;
    save = block->data.data;
    for (auto i = 0ul; i < count; ++i) {
        data = start + i;

        value = data->value;
        if ((value - min) > sub)
            continue;

        utils::binary_search(input, search_pointer_by_bin_gt, value, size, lower, upper);

        if ((size_t)lower == size || utils::address_of(input[lower])->address - value > offset)
            continue;

        save[pcount++] = data;
    }

    total += pcount;
    block->data.count = pcount;
}

template <class T>
template <typename P>
void chainer::search<T>::filter_pointer_to_block(P &&input, size_t offset, utils::list_head<pointer_pcount<T>> *node, size_t avg, std::atomic<size_t> &total)
{
    pointer_data<T> *start, **save;

    auto &trf = reinterpret_cast<utils::mapqueue<pointer_data<T> *> &>(cache);

    auto find_pointer = [this, &input, &total, offset](auto start, auto count, auto block) { filter_pointer_from_fmmap(input, start, count, offset, total, block); };

    auto push_pool = [&find_pointer, &start, &save, &node](auto t) {
        node->next = new utils::list_head<pointer_pcount<T>>;
        node = node->next;
        node->data.data = save;

        utils::thread_pool->pushpool(find_pointer, start, t, node);

        start += t, save += t;
    };

    start = &pcoll.front();
    save = &trf.front();
    utils::split_num_to_avg(pcoll.size(), avg, push_pool);
}

/* this function compatible with bypassing page fault
 * bypass page_fault by note off "open_target_pagemap" "close_target_pagemap" and change "filter_pointer_to_fmmap" to "filter_pointer_to_fmmap_by_page"(in for_each_memory_area<FILE *>.....)
 * and if u want to bypass pagemap inotify, change "/proc/sys/fs/inotify/max_user_watches" content to 0 (before call inotify_init())
 */
template <class T>
size_t chainer::search<T>::get_pointers(T start, T end, bool rest, int count, int size)
{
    FILE *f;
    uint32_t len;
    char *buffer;

    cache.shrink();
    pcoll.shrink();
    f = tmpfile();
    if (f == nullptr)
        return 0;

    auto cat_file_list = [this, &f, &len, &buffer](auto &in) {
        if (in == nullptr)
            return;

        rewind(in);
        utils::cat_file_to_another(buffer, len, in, f);
        fclose(in);
    }; // faster than sort i thought

    memtool::base::open_target_pagemap();
    auto ins = memtool::extend::for_each_memory_area<FILE *>(start, end, rest, count, size, [this](auto buffer, auto start, auto len, auto vma, auto &dat) { filter_pointer_to_fmmap_by_page(buffer, start, len, vma, dat); });
    memtool::base::close_target_pagemap();

    len = 1 << 20; // 1m
    buffer = new char[len];
    for (auto &in : ins)
        cat_file_list(in);

    delete[] buffer;

    pcoll.map(f);
    cache.reserve(pcoll.size());
    return pcoll.size();
}

template <class T>
template <typename P, typename U>
void chainer::search<T>::search_pointer(P &&input, U &out, size_t offset, bool rest, size_t limit)
{
    if (input.empty() || pcoll.begin() == nullptr || pcoll.size() == 0)
        return;

    size_t count;
    std::atomic<size_t> total(0);
    utils::list_head<pointer_pcount<T>> *head;

    auto emplace_pointer = [this, &count, &out, &limit](auto n) {
        if (n->data.count == 0 || count >= limit)
            return;

        size_t cnt;
        pointer_data<T> **data;

        cnt = n->data.count;
        data = n->data.data;
        for (auto i = 0u; i < cnt; ++i)
            out.emplace_back(data[i]);

        count += cnt;
    };

    count = 0;
    head = new utils::list_head<pointer_pcount<T>>;
    filter_pointer_to_block(input, offset, head, 10000, total); // 10000 is the avg to split ptr for multi threads, actually it can custom made by uself

    utils::thread_pool->wait();

    limit = rest ? limit : total.load();
    limit = std::min(limit, total.load());
    out.reserve(limit);

    utils::free_list_for_each(head, emplace_pointer);
}

template <class T>
chainer::search<T>::search()
{
}

template <class T>
chainer::search<T>::~search()
{
}
