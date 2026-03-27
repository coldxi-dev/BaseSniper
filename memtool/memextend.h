//
// Create by 青杉白衣 on 2023
//

#pragma once

#include <list>
#include <unordered_set>
#include <vector>

#include "sutils.h"
#include "threadpool.h"

#include "membase.h"
#include "memsetting.h"

#include <sys/mman.h>
#include <sys/user.h>

namespace memtool
{

class extend final : public ::memtool::base
{
private:
    extend();
    ~extend();

    extend(const memtool::extend &b) = delete;
    extend(memtool::extend &&b) = delete;
    extend &operator=(const memtool::extend &b) = delete;
    extend &operator=(memtool::extend &&b) = delete;

    static inline std::mutex mem_mutex;

    static inline std::condition_variable mem_condition;

    template <typename F, typename... Args>
    static void employ_memory_block(size_t start, size_t size, char **buffer, int &index, vm_area_data *vma, F &&call, Args &&...args);

    template <typename F>
    static void divide_memory_to_block(size_t start, size_t end, vm_area_data *vma, char **buffer, int &index, int size, F &&call);

    template <typename C, typename F>
    static void divide_memory_to_block(size_t start, size_t end, vm_area_data *vma, char **buffer, int &index, int size, C &cache, F &&call);

    template <typename F>
    static void for_each_memory_call(size_t start, size_t end, bool rest, int count, int size, F &&call);

    template <typename C, typename F>
    struct for_each_memory_impl {
        static auto for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call);
    };

    template <typename F>
    struct for_each_memory_impl<void, F> {
        static void for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call);
    };

public:
    static inline std::list<vm_area_data *> vm_area_list; // global

    static inline std::vector<vm_area_data *> vm_area_vec; // set

    static inline std::list<vm_static_data *> vm_static_list;

    /*static inline auto vm_static_set = [](int n) {

        auto index = [](auto vma) { return ((std::hash<int>()(vma->range) ^ (std::hash<int>()(vma->count) << 1)) >> 1) ^ (std::hash<std::string>()(vma->name) << 1); };

        auto aol = [](auto a, auto b) { return (strcmp(a->name, b->name) == 0) && (a->range == b->range) && (a->count == b->count); };

        std::unordered_set<memtool::vm_static_data *, decltype(index), decltype(aol)> mset(n, index, aol);
        return mset;
    }(100);*/

    static int get_perms_prot(char *perms);

    static int det_mem_range(char *name, char *prems);

    template <typename F>
    static int parse_process_maps(char *path, F &&call);

    static int parse_process_maps();

    static int parse_process_module();

    static void set_mem_ranges(int ranges);

    static int get_target_mem();

    template <typename C, typename F>
    static auto for_each_memory_area(size_t start, size_t end, bool rest, int count, int size, F &&call); // std::conditional_t<std::is_same_v<C, void>, void, std::vector<C>>

    template <typename F>
    static void check_page_fault(size_t start, size_t len, F &&call);

    template <typename F>
    static void check_page_fault(size_t start, size_t len, void *data, F &&call);

    template <typename F>
    static void for_each_page_size(size_t start, size_t len, F &&call);
};

} // namespace memtool

#include "memextend.hpp"

