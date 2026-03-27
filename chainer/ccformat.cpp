//
// Create by 青杉白衣 on 2023
//

#ifndef CHAINER_CCFORMAT_CPP
#define CHAINER_CCFORMAT_CPP

#include "ccformat.h"

template <class T>
size_t chainer::cformat<T>::format_bin_chain_data(FILE *instream, const char *name, bool folder)
{
    FILE *f;

    if (folder)
        return ::chainer::format<T>::format_bin_chain_data(instream, name);

    f = fopen(name, "w+");
    if (f == nullptr)
        return 0;

    return ::chainer::format<T>::format_bin_chain_data(instream, f);
}

template <class T>
chainer::cformat<T>::cformat()
{
}

template <class T>
chainer::cformat<T>::~cformat()
{
}

template class chainer::cformat<uint32_t>;
template class chainer::cformat<size_t>;

#endif