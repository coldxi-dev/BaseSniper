//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "cscan.h"

namespace chainer
{

template <class T>
struct cscan : public ::chainer::scan<T>
{
    size_t get_pointers(T start, T end, bool rest, int count, int size);

    size_t scan_pointer_chain(std::vector<T> &addr, int depth, size_t offset, bool limit, size_t plim, FILE *outstream);

    cscan();

    ~cscan();
};

extern template class chainer::cscan<uint32_t>;
extern template class chainer::cscan<size_t>;

} // namespace chainer