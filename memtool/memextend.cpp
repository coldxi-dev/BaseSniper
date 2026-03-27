//
// Create by 青杉白衣 on 2023
//

#ifndef MEMTOOL_MEM_EXTENDS
#define MEMTOOL_MEM_EXTENDS

#include <unordered_map>

#include "memextend.h"

#define PERMS_PROT_ASSIGN(perms, index, perm, prot, val) \
    if (perms[index] == perm)                            \
    val |= prot

auto create_module_map(int n)
{
    auto index = [](auto vma) { return std::hash<std::string>()(vma->name) ^ std::hash<int>()(vma->range); };

    auto aol = [](auto a, auto b) { return (strcmp(a->name, b->name) == 0) && (a->range == b->range); };

    std::unordered_map<memtool::vm_static_data *, int, decltype(index), decltype(aol)> module_map(n, index, aol);
    return module_map;
}

int memtool::extend::get_perms_prot(char *perms)
{
    int prot;

    prot = PROT_NONE;
    PERMS_PROT_ASSIGN(perms, 0, 'r', PROT_READ, prot);
    PERMS_PROT_ASSIGN(perms, 1, 'w', PROT_WRITE, prot);
    PERMS_PROT_ASSIGN(perms, 2, 'x', PROT_EXEC, prot);
    return prot;
}

int memtool::extend::det_mem_range(char *name, char *prems)
{
    if (strlen(name) == 0)
        return memsetting::Anonymous;

    if (strcmp(name, "[heap]") == 0)
        return memsetting::C_heap;

    if (strcmp(name, "[stack]") == 0)
        return memsetting::Stack;

    if (strcmp(name, "/dev/kgsl-3d0") == 0)
        return memsetting::Video;

    if (strcmp(name, "[anon:libc_malloc]") == 0)
        return memsetting::C_alloc;

    if (strstr(name, "/dev/ashmem/") != nullptr)
        return memsetting::Ashmem;

    if (strstr(name, "/system/fonts/") != nullptr)
        return memsetting::Bad;

    if (strstr(name, "[anon:dalvik-/") != nullptr)
        return memsetting::Java;

    if (strstr(name, "[anon:dalvik-main") != nullptr)
        return memsetting::Java_heap;

    if ((strstr(name, "/data/app/") != nullptr) && strstr(prems, "xp") != nullptr)
        return memsetting::Code_app;

    if (strstr(name, "/system/framework/") != nullptr)
        return memsetting::Code_system;

    if (strstr(name, "[anon:.bss]") != nullptr)
        return memsetting::C_bss;

    if (strstr(name, "/data/app/") != nullptr)
        return memsetting::C_data;

    return memsetting::Other;
}

void memtool::extend::set_mem_ranges(int ranges)
{
    vm_area_vec.clear();

    for (auto vma : vm_area_list) {
        if (ranges & vma->range) {
            vm_area_vec.emplace_back(vma);
        }
    }
}

int memtool::extend::parse_process_module()
{
    if (vm_area_list.empty())
        return -1;

    auto static_cd_xa = memsetting::C_data | memsetting::Code_app;

    auto mod_map = create_module_map(100);
    auto count_mod = [&mod_map](auto curr, auto prev) {
        auto mod = new vm_static_data(curr->start, curr->end, curr->range);

        strcpy(mod->name, utils::strtok_final_name(prev->name, "/"));

        mod_map.find(mod) == mod_map.end() ? mod_map[mod] = 1 : ++mod_map[mod];
        mod->count = mod_map[mod];
        vm_static_list.emplace_back(mod);

        return mod;
    };

    utils::free_container_data(vm_static_list);
    vm_static_list.clear();

    auto prev = vm_area_list.front();
    for (auto curr : vm_area_list) {
        if (curr->range & static_cd_xa) count_mod(curr, curr);
        else if (curr->range & memsetting::C_bss && prev->range & static_cd_xa) { auto *mod = count_mod(curr, prev); if (strlen(mod->name) + 4 < sizeof(mod->name)) strcat(mod->name, ":bss"); }

        prev = curr;
    }
    return 0;
}

int memtool::extend::parse_process_maps()
{
    char fname[64];
    auto add_vma_list = [](auto &vma) {
        vm_area_data *v;

        v = new vm_area_data();
        memcpy(v, &vma, sizeof(vma));
        vm_area_list.emplace_back(v);
    };

    utils::free_container_data(vm_area_list);
    vm_area_list.clear();

    snprintf(fname, sizeof(fname), "/proc/%d/maps", target_pid);
    return parse_process_maps(fname, add_vma_list);
}

int memtool::extend::get_target_mem()
{
    return parse_process_maps() || parse_process_module();
}

memtool::extend::extend()
{
}

memtool::extend::~extend()
{
    utils::free_container_data(vm_area_list);
    vm_area_list.clear();
    utils::free_container_data(vm_static_list);
    vm_static_list.clear();
} // actually useless

#endif
