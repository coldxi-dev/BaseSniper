//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "cformat.h"

namespace chainer
{

template <class T>
struct cformat : public ::chainer::format<T>
{
    size_t format_bin_chain_data(FILE *instream, const char *name, bool folder);

    cformat();

    ~cformat();
};

extern template class chainer::cformat<uint32_t>;
extern template class chainer::cformat<size_t>;

} // namespace chainer