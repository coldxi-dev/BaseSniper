//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "cbase.h"

namespace chainer
{

template <class T>
class format : public ::chainer::base<T>
{
private:
    static inline thread_local FILE *out_f;
    static inline thread_local char *buf;
    static inline thread_local size_t t_count;

    void out_chain_string(char *pre, int level, chainer::cprog_data<T> &dat, std::vector<utils::varray<chainer::cprog_data<T>>> &contents);

public:
    size_t format_bin_chain_data(FILE *instream, FILE *outstream);

    size_t format_bin_chain_data(FILE *instream, const char *folder);
};
}; // namespace chainer

#include "cformat.hpp"