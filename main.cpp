
#include "ccformat.h"
#include "ccscan.h"

#include <getopt.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>

// ==================== Scan parameters ====================

static const char *DEFAULT_CONFIG_DIR  = "/sdcard/BaseSniper";
static const char *DEFAULT_CONFIG_PATH = "/sdcard/BaseSniper/BaseSniper.conf";
static const char *DEFAULT_OUTPUT_PATH = "/sdcard/BaseSniper/BaseSniper_result.bin";
static const char *DEFAULT_FORMAT_PATH = "/sdcard/BaseSniper/BaseSniper_result.txt";
static const char *DEFAULT_FILTER_PATH = "/sdcard/BaseSniper/BaseSniper_result_filtered.txt";

struct scan_params {
    std::string package;
    int         pid         = -1;
    uint64_t    address     = 0;
    bool        has_address = false;
    int         depth       = 8;
    size_t      offset      = 2048;
    int         threads     = 10;
    int         block_size  = 1 << 20; // 1MB
    int         mem_types   = memtool::Anonymous | memtool::C_bss | memtool::C_data;
    std::string output      = DEFAULT_OUTPUT_PATH;
    std::string format_path;
};

// ==================== Helpers ====================

static void print_usage(const char *prog)
{
    printf(
        "\n"
        "  BaseSniper - Pointer Chain Scanner\n"
        "\n"
        "  Usage: %s [options]\n"
        "\n"
        "  Target:\n"
        "    -p, --package <name>    Target package name (e.g. com.example.app)\n"
        "    -P, --pid <pid>         Target PID (use instead of --package)\n"
        "\n"
        "  Scan:\n"
        "    -a, --address <addr>    Target address to scan (hex, e.g. 0x784701F1C0)\n"
        "    -d, --depth <n>         Pointer chain depth (default: 8)\n"
        "    -r, --range <n>         Max offset range per level (default: 2048)\n"
        "    -t, --threads <n>       Thread count (default: 10)\n"
        "    -s, --block-size <n>    Memory block size (default: 1048576 = 1MB)\n"
        "\n"
        "  Memory type (can combine multiple):\n"
        "    -m, --mem <types>       Memory types, comma separated:\n"
        "                              A  = Anonymous\n"
        "                              Ca = C_alloc\n"
        "                              Ch = C_heap\n"
        "                              Cd = C_data\n"
        "                              Cb = C_bss\n"
        "                              Jh = Java_heap\n"
        "                              J  = Java\n"
        "                              S  = Stack\n"
        "                              Xa = Code_app\n"
        "                              Xs = Code_system\n"
        "                              As = Ashmem\n"
        "                              all = All\n"
        "                            (default: A,Cb,Cd)\n"
        "\n"
        "  Output:\n"
        "    -o, --output <path>     Output file name/path (saved under /sdcard/BaseSniper)\n"
        "    -f, --format <path>     Format file name/path (saved under /sdcard/BaseSniper)\n"
        "\n"
        "    -h, --help              Show this help\n"
        "\n"
        "  Examples:\n"
        "    %s -p com.example.app -a 0x784701F1C0 -d 8 -r 2048\n"
        "    %s -P 12345 -a 0x784701F1C0 -d 10 -r 4096 -m A,Ca,Cb,Cd -o result.bin\n"
        "    %s -P 12345 -a 0x784701F1C0 -m all\n"
        "\n",
        prog, prog, prog, prog);
}

static int parse_mem_types(const char *input)
{
    int result = 0;
    char buf[512];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;

    char *token = strtok(buf, ",");
    while (token != nullptr) {
        // trim spaces
        while (*token == ' ') ++token;

        if (strcmp(token, "all") == 0)       return memtool::All;
        else if (strcmp(token, "A") == 0)    result |= memtool::Anonymous;
        else if (strcmp(token, "Ca") == 0)   result |= memtool::C_alloc;
        else if (strcmp(token, "Ch") == 0)   result |= memtool::C_heap;
        else if (strcmp(token, "Cd") == 0)   result |= memtool::C_data;
        else if (strcmp(token, "Cb") == 0)   result |= memtool::C_bss;
        else if (strcmp(token, "Jh") == 0)   result |= memtool::Java_heap;
        else if (strcmp(token, "J") == 0)    result |= memtool::Java;
        else if (strcmp(token, "S") == 0)    result |= memtool::Stack;
        else if (strcmp(token, "Xa") == 0)   result |= memtool::Code_app;
        else if (strcmp(token, "Xs") == 0)   result |= memtool::Code_system;
        else if (strcmp(token, "As") == 0)   result |= memtool::Ashmem;
        else {
            fprintf(stderr, "[!] Unknown memory type: %s\n", token);
            return -1;
        }

        token = strtok(nullptr, ",");
    }

    return result;
}

static std::string read_line(const char *prompt)
{
    printf("%s", prompt);
    fflush(stdout);
    char buf[1024];
    if (fgets(buf, sizeof(buf), stdin) == nullptr)
        return "";
    // strip trailing newline
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return std::string(buf);
}

static std::string read_line(const std::string &prompt)
{
    return read_line(prompt.c_str());
}

static const char *path_filename(const char *path)
{
    if (path == nullptr || *path == '\0')
        return "";

    const char *slash = strrchr(path, '/');
    return slash == nullptr ? path : slash + 1;
}

static std::string normalize_path_in_base_dir(const std::string &path, const char *default_name)
{
    const char *filename = default_name;

    if (!path.empty()) {
        const char *name = path_filename(path.c_str());
        if (*name != '\0')
            filename = name;
    }

    return std::string(DEFAULT_CONFIG_DIR) + "/" + filename;
}

static void normalize_params_paths(scan_params &p)
{
    p.output = normalize_path_in_base_dir(p.output, "BaseSniper_result.bin");

    if (!p.format_path.empty())
        p.format_path = normalize_path_in_base_dir(p.format_path, "BaseSniper_result.txt");
}

static const char *mem_types_to_string(int types)
{
    static char buf[256];
    buf[0] = '\0';

    if (types == memtool::All) { strcpy(buf, "all"); return buf; }

    auto append = [&](int flag, const char *name) {
        if (types & flag) {
            if (buf[0] != '\0') strcat(buf, ",");
            strcat(buf, name);
        }
    };

    append(memtool::Anonymous,   "A");
    append(memtool::C_alloc,     "Ca");
    append(memtool::C_heap,      "Ch");
    append(memtool::C_data,      "Cd");
    append(memtool::C_bss,       "Cb");
    append(memtool::Java_heap,   "Jh");
    append(memtool::Java,        "J");
    append(memtool::Stack,       "S");
    append(memtool::Code_app,    "Xa");
    append(memtool::Code_system, "Xs");
    append(memtool::Ashmem,      "As");

    return buf;
}

// ==================== 配置文件 ====================

static bool file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static bool ensure_dir(const char *dir)
{
    struct stat st {};
    if (stat(dir, &st) == 0)
        return S_ISDIR(st.st_mode);

    return mkdir(dir, 0777) == 0;
}

static bool ensure_dir_recursive(const char *dir)
{
    char buf[1024];
    size_t len = strlen(dir);

    if (len == 0 || len >= sizeof(buf))
        return false;

    strncpy(buf, dir, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    if (len > 1 && buf[len - 1] == '/')
        buf[len - 1] = '\0';

    for (char *cursor = buf + 1; *cursor != '\0'; ++cursor) {
        if (*cursor != '/')
            continue;

        *cursor = '\0';
        if (!ensure_dir(buf))
            return false;
        *cursor = '/';
    }

    return ensure_dir(buf);
}

static bool ensure_parent_dir(const char *path)
{
    char buf[1024];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(buf))
        return false;

    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strrchr(buf, '/');
    if (slash == nullptr || slash == buf)
        return true;

    *slash = '\0';
    return ensure_dir_recursive(buf);
}

static bool save_config(const scan_params &p, const char *path)
{
    if (!ensure_parent_dir(path)) {
        fprintf(stderr, "[!] 无法创建配置目录: %s\n", path);
        return false;
    }

    FILE *f = fopen(path, "w");
    if (f == nullptr) {
        fprintf(stderr, "[!] 无法写入配置文件: %s\n", path);
        return false;
    }

    fprintf(f, "# BaseSniper 配置文件\n");
    if (!p.package.empty())
        fprintf(f, "package=%s\n", p.package.c_str());
    if (p.pid != -1)
        fprintf(f, "pid=%d\n", p.pid);
    if (p.has_address)
        fprintf(f, "address=%" PRIx64 "\n", p.address);
    fprintf(f, "depth=%d\n", p.depth);
    fprintf(f, "offset=%zu\n", p.offset);
    fprintf(f, "threads=%d\n", p.threads);
    fprintf(f, "block_size=%d\n", p.block_size);
    fprintf(f, "mem_types=%s\n", mem_types_to_string(p.mem_types));
    fprintf(f, "output=%s\n", p.output.c_str());
    if (!p.format_path.empty())
        fprintf(f, "format=%s\n", p.format_path.c_str());

    fclose(f);
    return true;
}

static bool load_config(scan_params &p, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == nullptr) {
        fprintf(stderr, "[!] 无法读取配置文件: %s\n", path);
        return false;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f) != nullptr) {
        // 去除换行
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        // 跳过注释和空行
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *eq = strchr(line, '=');
        if (eq == nullptr) continue;

        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "package") == 0)         { p.package = val; p.pid = -1; }
        else if (strcmp(key, "pid") == 0)         { p.pid = atoi(val); p.package.clear(); }
        else if (strcmp(key, "address") == 0)     { p.address = strtoull(val, nullptr, 16); p.has_address = true; }
        else if (strcmp(key, "depth") == 0)        p.depth = atoi(val);
        else if (strcmp(key, "offset") == 0)       p.offset = strtoull(val, nullptr, 10);
        else if (strcmp(key, "threads") == 0)      p.threads = atoi(val);
        else if (strcmp(key, "block_size") == 0)   p.block_size = atoi(val);
        else if (strcmp(key, "mem_types") == 0)   {
            int mt = parse_mem_types(val);
            if (mt != -1) p.mem_types = mt;
        }
        else if (strcmp(key, "output") == 0)       p.output = val;
        else if (strcmp(key, "format") == 0)       p.format_path = val;
    }

    fclose(f);
    normalize_params_paths(p);
    return true;
}

// ==================== Core operations ====================

static int do_scan(scan_params &p)
{
    normalize_params_paths(p);

    // ---------- resolve PID ----------
    if (p.pid != -1) {
        memtool::base::target_pid = p.pid;
    } else {
        memtool::base::target_pid = memtool::base::get_pid(p.package.c_str());
        if (memtool::base::target_pid == -1) {
            fprintf(stderr, "[!] Failed to get PID for package: %s\n", p.package.c_str());
            return 1;
        }
    }

    printf("[*] BaseSniper - Pointer Chain Scanner\n");
    printf("[*] PID:        %d\n", memtool::base::target_pid);
    printf("[*] Address:    0x%" PRIx64 "\n", p.address);
    printf("[*] Depth:      %d\n", p.depth);
    printf("[*] Range:      %zu\n", p.offset);
    printf("[*] Threads:    %d\n", p.threads);
    printf("[*] Block size: %d\n", p.block_size);
    printf("[*] Output:     %s\n", p.output.c_str());
    printf("\n");

    // ---------- init memory ----------
    chainer::cscan<uint64_t> scanner;

    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(p.mem_types);

    // ---------- scan pointers ----------
    printf("[*] Scanning pointers...\n");
    size_t ptr_count = scanner.get_pointers(0, 0, false, p.threads, p.block_size);
    printf("[*] Found %zu pointers\n\n", ptr_count);

    if (ptr_count == 0) {
        fprintf(stderr, "[!] No pointers found, exiting\n");
        return 1;
    }

    // ---------- scan pointer chains ----------
    std::vector<uint64_t> addr;
    addr.emplace_back(p.address);

    if (!ensure_parent_dir(p.output.c_str())) {
        fprintf(stderr, "[!] Failed to create output directory: %s\n", p.output.c_str());
        return 1;
    }

    FILE *fout = fopen(p.output.c_str(), "wb+");
    if (fout == nullptr) {
        fprintf(stderr, "[!] Failed to open output file: %s\n", p.output.c_str());
        return 1;
    }

    printf("[*] Scanning pointer chains (depth=%d, range=%zu)...\n", p.depth, p.offset);
    size_t chain_count = scanner.scan_pointer_chain(addr, p.depth, p.offset, false, 0, fout);
    fclose(fout);

    printf("[*] Found %zu chains\n", chain_count);
    printf("[*] Results saved to: %s\n", p.output.c_str());

    // ---------- format (optional) ----------
    if (!p.format_path.empty() && chain_count > 0) {
        printf("\n[*] Formatting results to: %s\n", p.format_path.c_str());

        if (!ensure_parent_dir(p.format_path.c_str())) {
            fprintf(stderr, "[!] Failed to create format output directory: %s\n", p.format_path.c_str());
            return 1;
        }

        chainer::cformat<uint64_t> formatter;
        FILE *fin = fopen(p.output.c_str(), "rb+");
        if (fin == nullptr) {
            fprintf(stderr, "[!] Failed to reopen output file for formatting\n");
            return 1;
        }

        size_t fmt_count = formatter.format_bin_chain_data(fin, p.format_path.c_str(), 0);
        fclose(fin);
        printf("[*] Formatted %zu chains\n", fmt_count);
    }

    printf("\n[*] Done\n");
    return 0;
}

static int do_format(scan_params &p)
{
    normalize_params_paths(p);

    std::string bin_path = normalize_path_in_base_dir(p.output, "BaseSniper_result.bin");
    std::string input = read_line("[?] 输入 .bin 文件名 (固定目录: /sdcard/BaseSniper) [" +
                                  std::string(path_filename(bin_path.c_str())) + "]: ");
    if (!input.empty())
        bin_path = normalize_path_in_base_dir(input, "BaseSniper_result.bin");

    std::string default_txt = p.format_path.empty()
                              ? std::string(DEFAULT_FORMAT_PATH)
                              : normalize_path_in_base_dir(p.format_path, "BaseSniper_result.txt");

    input = read_line("[?] 输出文本文件名 (固定目录: /sdcard/BaseSniper) [" +
                      std::string(path_filename(default_txt.c_str())) + "]: ");
    std::string txt_path = input.empty()
                           ? default_txt
                           : normalize_path_in_base_dir(input, path_filename(default_txt.c_str()));

    if (!ensure_parent_dir(txt_path.c_str())) {
        fprintf(stderr, "[!] 无法创建输出目录: %s\n", txt_path.c_str());
        return 1;
    }

    FILE *fin = fopen(bin_path.c_str(), "rb+");
    if (fin == nullptr) {
        fprintf(stderr, "[!] 无法打开文件: %s\n", bin_path.c_str());
        return 1;
    }

    printf("[*] 格式化 %s -> %s\n", bin_path.c_str(), txt_path.c_str());

    chainer::cformat<uint64_t> formatter;
    size_t fmt_count = formatter.format_bin_chain_data(fin, txt_path.c_str(), 0);
    fclose(fin);

    printf("[*] 已格式化 %zu 条链\n", fmt_count);
    printf("[*] 完成\n");
    return 0;
}

// ==================== 二次过滤 ====================

// 递归遍历指针链树，对每条完整链从 static base 开始逐级 readv，
// 验证最终地址是否等于 target_addr。有效链写入 out_f。
static void verify_chain_recursive(
    char *pre, int level,
    chainer::cprog_data<uint64_t> &dat,
    std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    uint64_t target_addr,
    FILE *out_f, char *buf, size_t &valid_count, size_t &total_count)
{
    if (level == 0) {
        // 叶子节点: dat.address 是最终地址，验证是否等于目标
        ++total_count;
        if (dat.address == target_addr) {
            *pre = 0;
            auto n = sprintf(pre, " = %lx\n", (size_t)dat.address);
            fwrite(buf, pre + n - buf, 1, out_f);
            ++valid_count;
        }
    } else {
        for (auto i = dat.start; i < dat.end; ++i) {
            *pre = 0;
            auto n = sprintf(pre, " -> + 0x%lX", (size_t)(contents[level - 1][i].address - dat.value));
            verify_chain_recursive(pre + n, level - 1, contents[level - 1][i], contents,
                                   target_addr, out_f, buf, valid_count, total_count);
        }
    }
}

// 运行时验证: 从 static base 开始，沿着偏移链逐级 readv 目标进程内存，
// 检查最终读到的地址是否等于 target_addr
// root_addr: 链顶层的静态指针地址
// offsets: 每一级的偏移量，从外到内
// target_addr: 期望最终指向的地址
static bool verify_chain_runtime(
    uint64_t root_addr, const std::vector<size_t> &offsets, uint64_t target_addr)
{
    uint64_t cur = root_addr;
    for (size_t i = 0; i < offsets.size(); ++i) {
        uint64_t val = 0;
        long ret = memtool::base::readv(cur, &val, sizeof(val));
        if (ret <= 0) return false;
        cur = val + offsets[i];
    }
    return cur == target_addr;
}

// 递归收集偏移并验证
// root_addr: 链顶层的静态指针地址 (不变，一直传递下去)
static void verify_chain_runtime_recursive(
    int level,
    chainer::cprog_data<uint64_t> &dat,
    std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    uint64_t root_addr,
    uint64_t sym_start, const char *sym_name, int sym_count,
    uint64_t target_addr,
    std::vector<size_t> &offset_stack,
    FILE *out_f, size_t &valid_count, size_t &total_count)
{
    if (level == 0) {
        ++total_count;
        // root_addr 是链顶层的静态地址, offset_stack 是从外到内的偏移
        if (verify_chain_runtime(root_addr, offset_stack, target_addr)) {
            char buf[500];
            int pos = sprintf(buf, "%s[%d] + 0x%lX",
                              sym_name, sym_count, (size_t)(root_addr - sym_start));
            for (auto &off : offset_stack) {
                pos += sprintf(buf + pos, " -> + 0x%lX", off);
            }
            pos += sprintf(buf + pos, " = %lx\n", (size_t)target_addr);
            fwrite(buf, pos, 1, out_f);
            ++valid_count;
        }
    } else {
        for (auto i = dat.start; i < dat.end; ++i) {
            size_t off = (size_t)(contents[level - 1][i].address - dat.value);
            offset_stack.push_back(off);
            verify_chain_runtime_recursive(level - 1, contents[level - 1][i], contents,
                                           root_addr,
                                           sym_start, sym_name, sym_count,
                                           target_addr, offset_stack,
                                           out_f, valid_count, total_count);
            offset_stack.pop_back();
        }
    }
}

static int do_filter(scan_params &p)
{
    normalize_params_paths(p);

    // 输入 bin 文件
    std::string bin_path = normalize_path_in_base_dir(p.output, "BaseSniper_result.bin");
    std::string input = read_line("[?] 输入 .bin 文件名 (固定目录: /sdcard/BaseSniper) [" +
                                  std::string(path_filename(bin_path.c_str())) + "]: ");
    if (!input.empty())
        bin_path = normalize_path_in_base_dir(input, "BaseSniper_result.bin");

    // 输入新的目标地址
    input = read_line("[?] 输入新的目标地址 (十六进制): ");
    if (input.empty()) {
        fprintf(stderr, "[!] 必须输入目标地址\n");
        return 1;
    }
    uint64_t target_addr = strtoull(input.c_str(), nullptr, 16);

    // 选择验证模式
    printf("\n  验证模式:\n");
    printf("  [1] 静态验证 - 仅比对 .bin 中记录的最终地址 (离线，不需要目标进程)\n");
    printf("  [2] 运行时验证 - 实时读取目标进程内存逐级验证 (需要目标进程运行中)\n");
    input = read_line("\n  请选择 [1]: ");
    bool runtime_mode = (input == "2");

    // 如果运行时验证，需要确保 PID 已设置
    if (runtime_mode) {
        if (p.pid != -1) {
            memtool::base::target_pid = p.pid;
        } else if (!p.package.empty()) {
            memtool::base::target_pid = memtool::base::get_pid(p.package.c_str());
            if (memtool::base::target_pid == -1) {
                fprintf(stderr, "[!] 无法获取 PID: %s\n", p.package.c_str());
                return 1;
            }
        } else {
            input = read_line("[?] 输入目标进程 PID: ");
            if (input.empty()) {
                fprintf(stderr, "[!] 运行时验证需要 PID\n");
                return 1;
            }
            memtool::base::target_pid = atoi(input.c_str());
        }
        printf("[*] PID: %d\n", memtool::base::target_pid);
    }

    // 输出文件
    std::string default_out = DEFAULT_FILTER_PATH;

    input = read_line("[?] 输出文件名 (固定目录: /sdcard/BaseSniper) [" +
                      std::string(path_filename(default_out.c_str())) + "]: ");
    std::string out_path = input.empty()
                           ? default_out
                           : normalize_path_in_base_dir(input, "BaseSniper_result_filtered.txt");

    if (!ensure_parent_dir(out_path.c_str())) {
        fprintf(stderr, "[!] 无法创建输出目录: %s\n", out_path.c_str());
        return 1;
    }

    // 打开 bin 文件
    FILE *fin = fopen(bin_path.c_str(), "rb+");
    if (fin == nullptr) {
        fprintf(stderr, "[!] 无法打开文件: %s\n", bin_path.c_str());
        return 1;
    }

    // 解析 bin 数据
    chainer::cformat<uint64_t> formatter;
    auto chain_data = formatter.parse_cprog_bin_data(fin);
    fclose(fin);

    auto &syms = chain_data.syms;
    auto &contents = chain_data.contents;

    FILE *fout = fopen(out_path.c_str(), "w+");
    if (fout == nullptr) {
        fprintf(stderr, "[!] 无法创建输出文件: %s\n", out_path.c_str());
        return 1;
    }

    printf("[*] 过滤中... 目标地址: 0x%" PRIx64 " 模式: %s\n",
           target_addr, runtime_mode ? "运行时验证" : "静态验证");

    size_t valid_count = 0;
    size_t total_count = 0;

    if (runtime_mode) {
        // 运行时验证: 逐级 readv 目标进程
        for (auto &sym : syms) {
            for (auto &dat : sym.data) {
                std::vector<size_t> offset_stack;
                verify_chain_runtime_recursive(
                    sym.sym->level, dat, contents,
                    dat.address,  // root_addr: 链顶层的静态指针地址
                    sym.sym->start, sym.sym->name, sym.sym->count,
                    target_addr, offset_stack,
                    fout, valid_count, total_count);
            }
        }
    } else {
        // 静态验证: 比对 bin 中记录的最终地址
        for (auto &sym : syms) {
            char s_buf[500];
            for (auto &dat : sym.data) {
                *s_buf = 0;
                auto n = sprintf(s_buf, "%s[%d] + 0x%lX", sym.sym->name, sym.sym->count,
                                 (size_t)(dat.address - sym.sym->start));
                verify_chain_recursive(s_buf + n, sym.sym->level, dat, contents,
                                       target_addr, fout, s_buf, valid_count, total_count);
            }
        }
    }

    fclose(fout);

    printf("[*] 总链数: %zu, 有效链数: %zu\n", total_count, valid_count);
    if (valid_count > 0)
        printf("[*] 结果已保存到: %s\n", out_path.c_str());
    else
        printf("[*] 未找到有效链\n");

    printf("[*] 完成\n");
    return 0;
}

// ==================== 交互式菜单 ====================

static void print_banner()
{
    printf(
        "\n"
        "  ╔══════════════════════════════════════════╗\n"
        "  ║     BaseSniper - 指针链扫描器            ║\n"
        "  ╚══════════════════════════════════════════╝\n"
        "\n");
}

static void print_params(const scan_params &p)
{
    char addr_buf[32];
    snprintf(addr_buf, sizeof(addr_buf), "0x%" PRIx64, p.address);

    printf("\n  ┌─ 当前参数 ─────────────────────────────┐\n");
    printf("  │  1. 包名:      %-24s │\n", p.package.empty() ? "(未设置)" : p.package.c_str());
    printf("  │  2. PID:       %-24d │\n", p.pid);
    printf("  │  3. 目标地址:  %-24s │\n", p.has_address ? addr_buf : "(未设置)");
    printf("  │  4. 层级:      %-24d │\n", p.depth);
    printf("  │  5. 偏移:      %-24zu │\n", p.offset);
    printf("  │  6. 线程数:    %-24d │\n", p.threads);
    printf("  │  7. 块大小:    %-24d │\n", p.block_size);
    printf("  │  8. 内存类型:  %-24s │\n", mem_types_to_string(p.mem_types));
    printf("  │  9. 输出文件:  %-24s │\n", p.output.c_str());
    printf("  │ 10. 格式化:    %-24s │\n", p.format_path.empty() ? "(未启用)" : p.format_path.c_str());
    printf("  └──────────────────────────────────────────┘\n\n");
}

static void interactive_set_params(scan_params &p)
{
    while (true) {
        print_params(p);

        printf(
            "  [1]  设置包名          [6]  设置线程数\n"
            "  [2]  设置PID           [7]  设置块大小\n"
            "  [3]  设置目标地址      [8]  设置内存类型\n"
            "  [4]  设置层级          [9]  设置输出文件\n"
            "  [5]  设置偏移          [10] 设置格式化文件\n"
            "  [s]  保存配置          [l]  加载配置\n"
            "  [0]  返回上级菜单\n"
            "\n");

        std::string choice = read_line("  请选择> ");

        if (choice == "0" || choice.empty()) return;

        std::string input;

        if (choice == "1") {
            input = read_line("  包名 [" + (p.package.empty() ? std::string("未设置") : p.package) + "]: ");
            if (!input.empty()) { p.package = input; p.pid = -1; }
        } else if (choice == "2") {
            input = read_line("  PID [" + std::to_string(p.pid) + "]: ");
            if (!input.empty()) { p.pid = atoi(input.c_str()); p.package.clear(); }
        } else if (choice == "3") {
            char buf[32];
            snprintf(buf, sizeof(buf), "%" PRIx64, p.address);
            input = read_line(std::string("  目标地址 (十六进制) [0x") + buf + "]: ");
            if (!input.empty()) { p.address = strtoull(input.c_str(), nullptr, 16); p.has_address = true; }
        } else if (choice == "4") {
            input = read_line("  层级 [" + std::to_string(p.depth) + "]: ");
            if (!input.empty()) p.depth = atoi(input.c_str());
        } else if (choice == "5") {
            input = read_line("  偏移 [" + std::to_string(p.offset) + "]: ");
            if (!input.empty()) p.offset = strtoull(input.c_str(), nullptr, 10);
        } else if (choice == "6") {
            input = read_line("  线程数 [" + std::to_string(p.threads) + "]: ");
            if (!input.empty()) p.threads = atoi(input.c_str());
        } else if (choice == "7") {
            input = read_line("  块大小 [" + std::to_string(p.block_size) + "]: ");
            if (!input.empty()) p.block_size = atoi(input.c_str());
        } else if (choice == "8") {
            printf("  可选: A,Ca,Ch,Cd,Cb,Jh,J,S,Xa,Xs,As,all\n");
            input = read_line(std::string("  内存类型 [") + mem_types_to_string(p.mem_types) + "]: ");
            if (!input.empty()) {
                int mt = parse_mem_types(input.c_str());
                if (mt != -1) p.mem_types = mt;
                else fprintf(stderr, "  [!] 无效的内存类型，保持原值\n");
            }
        } else if (choice == "9") {
            input = read_line("  输出文件名 (固定保存到 /sdcard/BaseSniper) [" +
                              std::string(path_filename(p.output.c_str())) + "]: ");
            if (!input.empty())
                p.output = normalize_path_in_base_dir(input, "BaseSniper_result.bin");
        } else if (choice == "10") {
            input = read_line("  格式化文件名 (固定保存到 /sdcard/BaseSniper) [" +
                              (p.format_path.empty() ? std::string("未启用") : std::string(path_filename(p.format_path.c_str()))) + "]: ");
            if (!input.empty())
                p.format_path = normalize_path_in_base_dir(input, "BaseSniper_result.txt");
        } else if (choice == "s" || choice == "S") {
            normalize_params_paths(p);
            if (save_config(p, DEFAULT_CONFIG_PATH))
                printf("  [*] 配置已保存到: %s\n", DEFAULT_CONFIG_PATH);
        } else if (choice == "l" || choice == "L") {
            if (load_config(p, DEFAULT_CONFIG_PATH))
                printf("  [*] 配置已加载: %s\n", DEFAULT_CONFIG_PATH);
        } else {
            fprintf(stderr, "  [!] 无效选项\n");
        }
    }
}

static int interactive_menu()
{
    scan_params params;

    // 自动加载默认配置 (如果存在)
    if (file_exists(DEFAULT_CONFIG_PATH)) {
        if (load_config(params, DEFAULT_CONFIG_PATH))
            printf("  [*] 已自动加载配置: %s\n", DEFAULT_CONFIG_PATH);
    }

    print_banner();

    while (true) {
        printf(
            "  [1] 设置参数\n"
            "  [2] 扫描基址\n"
            "  [3] 格式化结果\n"
            "  [4] 二次过滤\n"
            "  [0] 退出\n"
            "\n");

        std::string choice = read_line("  请选择> ");

        if (choice == "0" || choice == "q") {
            printf("  再见.\n");
            return 0;
        }

        if (choice == "1") {
            interactive_set_params(params);
            continue;
        }

        if (choice == "2") {
            if (params.package.empty() && params.pid == -1) {
                fprintf(stderr, "\n  [!] 未设置包名或PID，请先设置参数 (选项1)\n\n");
                continue;
            }
            if (!params.has_address) {
                fprintf(stderr, "\n  [!] 未设置目标地址，请先设置参数 (选项1)\n\n");
                continue;
            }
            printf("\n");
            int ret = do_scan(params);
            if (ret != 0)
                fprintf(stderr, "\n  [!] 扫描失败 (code %d)\n\n", ret);
            else
                printf("\n");
            continue;
        }

        if (choice == "3") {
            printf("\n");
            int ret = do_format(params);
            if (ret != 0)
                fprintf(stderr, "\n  [!] 格式化失败 (code %d)\n\n", ret);
            else
                printf("\n");
            continue;
        }

        if (choice == "4") {
            printf("\n");
            int ret = do_filter(params);
            if (ret != 0)
                fprintf(stderr, "\n  [!] 过滤失败 (code %d)\n\n", ret);
            else
                printf("\n");
            continue;
        }

        fprintf(stderr, "  [!] 无效选项，请重新选择\n\n");
    }
}

// ==================== Main ====================

int main(int argc, char *argv[])
{
    // ---------- no arguments: interactive mode ----------
    if (argc == 1) {
        return interactive_menu();
    }

    // ---------- CLI mode (original behavior) ----------
    scan_params p;
    if (file_exists(DEFAULT_CONFIG_PATH)) {
        load_config(p, DEFAULT_CONFIG_PATH);
    }

    static struct option long_options[] = {
        {"package",    required_argument, 0, 'p'},
        {"pid",        required_argument, 0, 'P'},
        {"address",    required_argument, 0, 'a'},
        {"depth",      required_argument, 0, 'd'},
        {"range",      required_argument, 0, 'r'},
        {"threads",    required_argument, 0, 't'},
        {"block-size", required_argument, 0, 's'},
        {"mem",        required_argument, 0, 'm'},
        {"output",     required_argument, 0, 'o'},
        {"format",     required_argument, 0, 'f'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:P:a:d:r:t:s:m:o:f:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p': p.package     = optarg; break;
            case 'P': p.pid         = atoi(optarg); break;
            case 'a': p.address     = strtoull(optarg, nullptr, 16); p.has_address = true; break;
            case 'd': p.depth       = atoi(optarg); break;
            case 'r': p.offset      = strtoull(optarg, nullptr, 10); break;
            case 't': p.threads     = atoi(optarg); break;
            case 's': p.block_size  = atoi(optarg); break;
            case 'm': p.mem_types   = parse_mem_types(optarg); break;
            case 'o': p.output      = optarg; break;
            case 'f': p.format_path = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    normalize_params_paths(p);

    if (p.mem_types == -1)
        return 1;

    // ---------- validate ----------
    if (p.package.empty() && p.pid == -1) {
        fprintf(stderr, "[!] Must specify --package (-p) or --pid (-P)\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!p.has_address) {
        fprintf(stderr, "[!] Must specify --address (-a)\n");
        print_usage(argv[0]);
        return 1;
    }

    return do_scan(p);
}
