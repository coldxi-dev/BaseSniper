
#include "ccformat.h"
#include "ccscan.h"

#include <getopt.h>
#include <inttypes.h>
#include <atomic>
#include <chrono>
#include <cctype>
#include <mutex>
#include <thread>
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
static const char *DEFAULT_FILTER_BIN_PATH = "/sdcard/BaseSniper/BaseSniper_result_filtered.bin";

struct scan_params {
    std::string package;
    int         pid         = -1;
    uint64_t    address     = 0;
    bool        has_address = false;
    uint64_t    link_start  = 0;
    uint64_t    link_end    = 0;
    bool        has_link_range = false;
    int         depth       = 8;
    int         min_level   = 0;
    size_t      offset      = 2048;
    int         threads     = 10;
    int         block_size  = 1 << 20; // 1MB
    int         mem_types   = memtool::Anonymous | memtool::C_bss | memtool::C_data;
    bool        use_kernel_rw = false;
    int         kernel_rw_mode = 1;
    std::string base_module;
    std::string output      = DEFAULT_OUTPUT_PATH;
    std::string format_path;
};

// ==================== Helpers ====================

static std::string trim_string(const std::string &input);

static const char *kernel_rw_mode_to_string(bool enabled, int mode)
{
    if (!enabled)
        return "off";
    return mode == 2 ? "hook" : "dev";
}

static bool parse_kernel_rw_mode(const std::string &input, int &mode)
{
    std::string text = trim_string(input);
    if (text.empty())
        return false;

    if (text == "1" || text == "dev" || text == "rtdev") {
        mode = 1;
        return true;
    }

    if (text == "2" || text == "hook" || text == "rthook") {
        mode = 2;
        return true;
    }

    return false;
}

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
        "    -R, --link-range <a-b|addr> Search chains between two addresses: use this as root range\n"
        "    -d, --depth <n>         Pointer chain depth (default: 8)\n"
        "    -L, --min-level <n>     Do not save chains below this level (default: 0)\n"
        "    -r, --range <n>         Max offset range per level (default: 2048)\n"
        "    -t, --threads <n>       Thread count (default: 10)\n"
        "    -s, --block-size <n>    Memory block size (default: 1048576 = 1MB)\n"
        "    -M, --module <names>    Base module filter, comma separated (e.g. libUE4.so,libanogs.so)\n"
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
        "  Read/Write backend:\n"
        "    -k, --kernel-rw <mode> Enable kernel R/W: dev or hook\n"
        "    -K, --no-kernel-rw     Disable kernel R/W and use process_vm\n"
        "\n"
        "  Output:\n"
        "    -o, --output <path>     Output file name/path (saved under /sdcard/BaseSniper)\n"
        "    -f, --format <path>     Format file name/path (saved under /sdcard/BaseSniper)\n"
        "\n"
        "    -h, --help              Show this help\n"
        "\n"
        "  Examples:\n"
        "    %s -p com.example.app -a 0x784701F1C0 -d 8 -r 2048\n"
        "    %s -P 12345 -a 0x784701F1C0 -R 0x7000000000-0x7000001000 -d 10 -r 4096\n"
        "    %s -P 12345 -a 0x784701F1C0 -m all\n"
        "    %s -P 12345 -a 0x784701F1C0 -k dev\n"
        "\n",
        prog, prog, prog, prog, prog);
}

static bool parse_address_range_text(const std::string &input, uint64_t &start, uint64_t &end)
{
    std::string text = trim_string(input);
    if (text.empty())
        return false;

    size_t pos = text.find('-');
    if (pos == std::string::npos)
        pos = text.find(',');
    if (pos == std::string::npos)
        pos = text.find(':');
    if (pos == std::string::npos)
        pos = text.find(' ');
    if (pos == std::string::npos)
    {
        char *single_end = nullptr;
        start = strtoull(text.c_str(), &single_end, 16);
        if (single_end == nullptr || *single_end != '\0')
            return false;

        end = start + 1;
        return true;
    }

    std::string left = trim_string(text.substr(0, pos));
    std::string right = trim_string(text.substr(pos + 1));
    if (left.empty() || right.empty())
        return false;

    char *left_end = nullptr;
    char *right_end = nullptr;
    start = strtoull(left.c_str(), &left_end, 16);
    end = strtoull(right.c_str(), &right_end, 16);
    return left_end != nullptr && *left_end == '\0' && right_end != nullptr && *right_end == '\0';
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

static std::string trim_string(const std::string &input)
{
    const char *spaces = " \t\r\n";
    size_t start = input.find_first_not_of(spaces);
    if (start == std::string::npos)
        return "";

    size_t end = input.find_last_not_of(spaces);
    return input.substr(start, end - start + 1);
}

static std::string normalize_module_name(const std::string &input)
{
    std::string trimmed = trim_string(input);
    if (trimmed.empty())
        return "";

    const char *name = path_filename(trimmed.c_str());
    return *name == '\0' ? trimmed : std::string(name);
}

static std::vector<std::string> split_module_filters(const std::string &input)
{
    std::vector<std::string> filters;
    size_t start = 0;

    while (start <= input.size()) {
        size_t end = input.find(',', start);
        std::string part = input.substr(start, end == std::string::npos ? std::string::npos : end - start);
        std::string name = normalize_module_name(part);
        if (!name.empty())
            filters.emplace_back(std::move(name));

        if (end == std::string::npos)
            break;
        start = end + 1;
    }

    return filters;
}

static std::string join_module_filters(const std::vector<std::string> &filters)
{
    std::string result;

    for (const auto &filter : filters) {
        if (!result.empty())
            result += ",";
        result += filter;
    }

    return result;
}

static std::string normalize_module_filter_list(const std::string &input)
{
    std::string trimmed = trim_string(input);
    if (trimmed.empty() || trimmed == "all" || trimmed == "ALL" || trimmed == "*" || trimmed == "全部")
        return "";

    return join_module_filters(split_module_filters(trimmed));
}

static void normalize_scan_params(scan_params &p)
{
    normalize_params_paths(p);
    if (p.min_level < 0)
        p.min_level = 0;
    if (p.has_link_range && p.link_start > p.link_end)
        std::swap(p.link_start, p.link_end);
    if (p.kernel_rw_mode < 1 || p.kernel_rw_mode > 2)
        p.kernel_rw_mode = 1;
    p.base_module = normalize_module_filter_list(p.base_module);
}

static bool is_pid_input(const std::string &input)
{
    if (input.empty())
        return false;

    for (char ch : input) {
        if (!std::isdigit(static_cast<unsigned char>(ch)))
            return false;
    }

    return true;
}

static void set_target(scan_params &p, const std::string &input)
{
    if (is_pid_input(input)) {
        p.pid = atoi(input.c_str());
        p.package.clear();
        return;
    }

    p.package = input;
    p.pid = -1;
}

static std::string current_target_label(const scan_params &p)
{
    if (p.pid != -1)
        return std::string("PID:") + std::to_string(p.pid);
    if (!p.package.empty())
        return std::string("包名:") + p.package;
    return "(未设置)";
}

static void set_base_module_filter(scan_params &p, const std::string &input)
{
    p.base_module = normalize_module_filter_list(input);
}

static int apply_base_module_filter(const std::string &module_names)
{
    std::vector<std::string> filters = split_module_filters(module_names);
    int matched = 0;

    for (auto module : memtool::extend::vm_static_list) {
        bool enabled = filters.empty();
        for (const auto &filter : filters) {
            if (strstr(module->name, filter.c_str()) != nullptr) {
                enabled = true;
                break;
            }
        }

        module->filter = !enabled;
        if (enabled)
            ++matched;
    }

    return matched;
}

static void apply_link_range_filter(const scan_params &p)
{
    for (auto *module : memtool::extend::vm_static_list)
        module->filter = true;

    auto *custom = new memtool::vm_static_data((size_t)p.link_start, (size_t)p.link_end);
    strcpy(custom->name, "dizhi1");
    custom->filter = false;
    memtool::extend::vm_static_list.emplace_back(custom);
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
    if (p.has_link_range)
        fprintf(f, "link_range=%" PRIx64 "-%" PRIx64 "\n", p.link_start, p.link_end);
    fprintf(f, "kernel_rw=%s\n", kernel_rw_mode_to_string(p.use_kernel_rw, p.kernel_rw_mode));
    fprintf(f, "depth=%d\n", p.depth);
    fprintf(f, "min_level=%d\n", p.min_level);
    fprintf(f, "offset=%zu\n", p.offset);
    fprintf(f, "threads=%d\n", p.threads);
    fprintf(f, "block_size=%d\n", p.block_size);
    fprintf(f, "mem_types=%s\n", mem_types_to_string(p.mem_types));
    if (!p.base_module.empty())
        fprintf(f, "base_module=%s\n", p.base_module.c_str());
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
        else if (strcmp(key, "link_range") == 0)  p.has_link_range = parse_address_range_text(val, p.link_start, p.link_end);
        else if (strcmp(key, "kernel_rw") == 0)   {
            std::string rw = trim_string(val);
            if (rw == "off" || rw == "0" || rw == "false")
                p.use_kernel_rw = false;
            else if (parse_kernel_rw_mode(rw, p.kernel_rw_mode))
                p.use_kernel_rw = true;
        }
        else if (strcmp(key, "depth") == 0)        p.depth = atoi(val);
        else if (strcmp(key, "min_level") == 0)    p.min_level = atoi(val);
        else if (strcmp(key, "offset") == 0)       p.offset = strtoull(val, nullptr, 10);
        else if (strcmp(key, "threads") == 0)      p.threads = atoi(val);
        else if (strcmp(key, "block_size") == 0)   p.block_size = atoi(val);
        else if (strcmp(key, "mem_types") == 0)   {
            int mt = parse_mem_types(val);
            if (mt != -1) p.mem_types = mt;
        }
        else if (strcmp(key, "base_module") == 0)  p.base_module = val;
        else if (strcmp(key, "output") == 0)       p.output = val;
        else if (strcmp(key, "format") == 0)       p.format_path = val;
    }

    fclose(f);
    normalize_scan_params(p);
    return true;
}

// ==================== Core operations ====================

static int do_scan(scan_params &p)
{
    normalize_scan_params(p);

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

    memtool::base::configure_rw_backend(p.use_kernel_rw, p.kernel_rw_mode);

    printf("[*] BaseSniper - Pointer Chain Scanner\n");
    printf("[*] PID:        %d\n", memtool::base::target_pid);
    printf("[*] Address:    0x%" PRIx64 "\n", p.address);
    if (p.has_link_range)
        printf("[*] Link range: 0x%" PRIx64 "-0x%" PRIx64 "\n", p.link_start, p.link_end);
    printf("[*] R/W:        %s\n", kernel_rw_mode_to_string(p.use_kernel_rw, p.kernel_rw_mode));
    printf("[*] Depth:      %d\n", p.depth);
    printf("[*] Min level:  %d\n", p.min_level);
    printf("[*] Range:      %zu\n", p.offset);
    printf("[*] Threads:    %d\n", p.threads);
    printf("[*] Block size: %d\n", p.block_size);
    printf("[*] Base mod:   %s\n", p.base_module.empty() ? "all" : p.base_module.c_str());
    printf("[*] Output:     %s\n", p.output.c_str());
    printf("\n");

    // ---------- init memory ----------
    chainer::cscan<uint64_t> scanner;

    memtool::extend::get_target_mem();
    int matched_modules = 0;
    if (p.has_link_range)
        apply_link_range_filter(p);
    else
        matched_modules = apply_base_module_filter(p.base_module);
    memtool::extend::set_mem_ranges(p.mem_types);

    if (p.has_link_range) {
        printf("[*] Root range filter enabled: 0x%" PRIx64 "-0x%" PRIx64 "\n", p.link_start, p.link_end);
    } else if (!p.base_module.empty()) {
        if (matched_modules == 0) {
            fprintf(stderr, "[!] No base module matched: %s\n", p.base_module.c_str());
            return 1;
        }

        printf("[*] Matched base modules: %d\n", matched_modules);
    }

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
    size_t chain_count = scanner.scan_pointer_chain(addr, p.depth, p.min_level, p.offset, false, 0, fout);
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
    normalize_scan_params(p);

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

enum filter_output_mode {
    FILTER_OUTPUT_BIN,
    FILTER_OUTPUT_TXT,
};

struct filtered_runtime_node {
    uint64_t address = 0;
    uint64_t value = 0;
    std::vector<filtered_runtime_node> children;
};

struct filtered_bin_root {
    chainer::cprog_data<uint64_t> data {};
};

struct filtered_runtime_sym {
    uint64_t start = 0;
    int range = 0;
    int count = 0;
    int level = 0;
    std::string name;
    std::vector<filtered_bin_root> roots;
};

struct txt_chain_entry {
    std::string sym_name;
    int sym_count = 0;
    uint64_t root_offset = 0;
    std::vector<size_t> offsets;
};

static bool has_file_ext(const std::string &path, const char *ext)
{
    size_t path_len = path.size();
    size_t ext_len = strlen(ext);
    if (path_len < ext_len)
        return false;

    return path.compare(path_len - ext_len, ext_len, ext) == 0;
}

static bool parse_hex_uint64(const std::string &text, uint64_t &value)
{
    if (text.empty())
        return false;

    char *end = nullptr;
    value = strtoull(text.c_str(), &end, 16);
    return end != nullptr && *end == '\0';
}

static bool parse_txt_chain_line(const std::string &line, txt_chain_entry &entry)
{
    std::string text = trim_string(line);
    if (text.empty())
        return false;

    size_t left = text.find('[');
    size_t right = left == std::string::npos ? std::string::npos : text.find(']', left + 1);
    size_t plus = right == std::string::npos ? std::string::npos : text.find(" + 0x", right + 1);
    if (left == std::string::npos || right == std::string::npos || plus == std::string::npos)
        return false;

    entry = {};
    entry.sym_name = text.substr(0, left);
    entry.sym_count = atoi(text.substr(left + 1, right - left - 1).c_str());

    size_t root_start = plus + 5;
    size_t arrow = text.find(" -> + 0x", root_start);
    std::string root_text = text.substr(root_start, arrow == std::string::npos ? std::string::npos : arrow - root_start);
    if (!parse_hex_uint64(root_text, entry.root_offset))
        return false;

    size_t pos = arrow;
    while (pos != std::string::npos) {
        size_t off_start = pos + 8;
        size_t next = text.find(" -> + 0x", off_start);
        std::string off_text = text.substr(off_start, next == std::string::npos ? std::string::npos : next - off_start);

        uint64_t off = 0;
        if (!parse_hex_uint64(off_text, off))
            return false;

        entry.offsets.emplace_back((size_t)off);
        pos = next;
    }

    return true;
}

static std::vector<txt_chain_entry> load_txt_chain_entries(const std::string &path)
{
    std::vector<txt_chain_entry> entries;
    FILE *f = fopen(path.c_str(), "r");
    if (f == nullptr)
        return entries;

    char *line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, f) > 0) {
        txt_chain_entry entry;
        if (parse_txt_chain_line(line, entry))
            entries.emplace_back(std::move(entry));
    }

    free(line);
    fclose(f);
    return entries;
}

static memtool::vm_static_data *find_static_module_by_name_count(const txt_chain_entry &entry)
{
    for (auto *module : memtool::extend::vm_static_list) {
        if (strcmp(module->name, entry.sym_name.c_str()) == 0 && module->count == entry.sym_count)
            return module;
    }
    return nullptr;
}

static bool verify_txt_chain_runtime(const txt_chain_entry &entry, uint64_t target_addr, uint64_t &root_addr)
{
    auto *module = find_static_module_by_name_count(entry);
    if (module == nullptr)
        return false;

    root_addr = module->start + entry.root_offset;
    uint64_t current_addr = root_addr;
    for (size_t off : entry.offsets) {
        uint64_t value = 0;
        long ret = memtool::base::readv(current_addr, &value, sizeof(value));
        if (ret <= 0)
            return false;

        current_addr = value + off;
    }

    return current_addr == target_addr;
}

static void write_filter_txt_line(
    const char *sym_name,
    int sym_count,
    uint64_t root_addr,
    uint64_t sym_start,
    const std::vector<size_t> &offset_stack,
    FILE *out_f)
{
    char buf[500];
    int pos = sprintf(buf, "%s[%d] + 0x%lX",
                      sym_name, sym_count, (size_t)(root_addr - sym_start));
    for (auto &off : offset_stack)
        pos += sprintf(buf + pos, " -> + 0x%lX", off);
    pos += sprintf(buf + pos, "\n");
    fwrite(buf, pos, 1, out_f);
}

static uint32_t append_filtered_bin_node(
    int level,
    const chainer::cprog_data<uint64_t> &dat,
    const std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    uint64_t target_addr,
    std::vector<std::vector<chainer::cprog_data<uint64_t>>> &filtered_contents,
    bool &matched)
{
    chainer::cprog_data<uint64_t> out = dat;

    if (level == 0) {
        matched = dat.address == target_addr;
        if (!matched)
            return 0;

        out.start = 0;
        out.end = 0;
        filtered_contents[0].push_back(out);
        return (uint32_t)(filtered_contents[0].size() - 1);
    }

    std::vector<uint32_t> child_indexes;
    child_indexes.reserve(dat.end - dat.start);
    for (uint32_t i = dat.start; i < dat.end; ++i) {
        bool child_matched = false;
        uint32_t child_index = append_filtered_bin_node(level - 1, contents[level - 1][i], contents,
                                                        target_addr, filtered_contents, child_matched);
        if (child_matched)
            child_indexes.push_back(child_index);
    }

    matched = !child_indexes.empty();
    if (!matched)
        return 0;

    out.start = child_indexes.front();
    out.end = child_indexes.back() + 1;
    filtered_contents[level].push_back(out);
    return (uint32_t)(filtered_contents[level].size() - 1);
}

static bool append_filtered_runtime_node(
    int level,
    const chainer::cprog_data<uint64_t> &dat,
    const std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    uint64_t current_addr,
    uint64_t target_addr,
    filtered_runtime_node &out)
{
    out.address = dat.address;
    out.value = dat.value;

    if (level == 0)
        return current_addr == target_addr;

    uint64_t value = 0;
    long ret = memtool::base::readv(current_addr, &value, sizeof(value));
    if (ret <= 0)
        return false;

    out.children.clear();
    out.children.reserve(dat.end - dat.start);
    for (uint32_t i = dat.start; i < dat.end; ++i) {
        const auto &next = contents[level - 1][i];
        size_t off = (size_t)(next.address - dat.value);
        filtered_runtime_node child;
        if (append_filtered_runtime_node(level - 1, next, contents, value + off, target_addr, child))
            out.children.emplace_back(std::move(child));
    }

    return !out.children.empty();
}

static void flatten_filtered_runtime_node(
    const filtered_runtime_node &node,
    int level,
    std::vector<std::vector<chainer::cprog_data<uint64_t>>> &filtered_contents,
    uint32_t &out_index)
{
    chainer::cprog_data<uint64_t> out;
    out.address = node.address;
    out.value = node.value;

    if (level == 0) {
        out.start = 0;
        out.end = 0;
        filtered_contents[0].push_back(out);
        out_index = (uint32_t)(filtered_contents[0].size() - 1);
        return;
    }

    uint32_t start = 0;
    uint32_t end = 0;
    bool has_child = false;
    for (const auto &child : node.children) {
        uint32_t child_index = 0;
        flatten_filtered_runtime_node(child, level - 1, filtered_contents, child_index);
        if (!has_child) {
            start = child_index;
            has_child = true;
        }
        end = child_index + 1;
    }

    out.start = start;
    out.end = end;
    filtered_contents[level].push_back(out);
    out_index = (uint32_t)(filtered_contents[level].size() - 1);
}

static size_t write_filtered_bin_file(
    const std::vector<filtered_runtime_sym> &syms,
    const std::vector<std::vector<chainer::cprog_data<uint64_t>>> &filtered_contents,
    FILE *fout)
{
    chainer::cprog_header header;
    header.size = sizeof(uint64_t);
    header.version = 101;
    header.module_count = (int)syms.size();
    header.level = (int)filtered_contents.size() - 1;
    header.sign[0] = 0;
    strcpy(header.sign, "BaseSniper pointer chain data\n");
    fwrite(&header, sizeof(header), 1, fout);

    size_t total_count = 0;
    for (const auto &sym_info : syms) {
        chainer::cprog_sym<uint64_t> sym {};
        sym.start = sym_info.start;
        sym.range = sym_info.range;
        sym.count = sym_info.count;
        sym.level = sym_info.level;
        sym.pointer_count = (int)sym_info.roots.size();
        strncpy(sym.name, sym_info.name.c_str(), sizeof(sym.name) - 1);
        sym.name[sizeof(sym.name) - 1] = 0;
        fwrite(&sym, sizeof(sym), 1, fout);

        for (const auto &root : sym_info.roots) {
            fwrite(&root.data, sizeof(root.data), 1, fout);
            ++total_count;
        }
    }

    for (size_t level = 0; level + 1 < filtered_contents.size(); ++level) {
        chainer::cprog_llen llen {};
        llen.level = (int)level;
        llen.count = (unsigned int)filtered_contents[level].size();
        fwrite(&llen, sizeof(llen), 1, fout);

        if (!filtered_contents[level].empty())
            fwrite(filtered_contents[level].data(), sizeof(chainer::cprog_data<uint64_t>),
                   filtered_contents[level].size(), fout);
    }

    fflush(fout);
    return total_count;
}

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
            auto n = sprintf(pre, "\n");
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
struct runtime_filter_progress {
    size_t total = 0;
    size_t last_basis_points = 0;
    size_t last_count = 0;
    std::chrono::steady_clock::time_point last_report_at {};
    bool printed = false;
};

struct runtime_filter_task {
    int level = 0;
    const chainer::cprog_data<uint64_t> *dat = nullptr;
    uint64_t root_addr = 0;
    uint64_t sym_start = 0;
    const char *sym_name = nullptr;
    int sym_count = 0;
    size_t subtree_total = 0;
};

struct runtime_filter_shared_state {
    FILE *out_f = nullptr;
    std::atomic_size_t total_count {0};
    std::atomic_size_t valid_count {0};
    runtime_filter_progress progress;
    std::mutex progress_mutex;
    std::mutex output_mutex;
};

struct runtime_filter_worker_state {
    std::vector<size_t> offset_stack;
    size_t pending_total = 0;
    size_t pending_valid = 0;
    std::chrono::steady_clock::time_point last_sync_at = std::chrono::steady_clock::now();
};

static std::vector<std::vector<size_t>> build_runtime_subtree_counts(
    const std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents)
{
    std::vector<std::vector<size_t>> subtree_counts(contents.size());
    if (contents.empty())
        return subtree_counts;

    for (size_t level = 0; level < contents.size(); ++level)
        subtree_counts[level].resize(contents[level].size(), 0);

    for (size_t i = 0; i < contents[0].size(); ++i)
        subtree_counts[0][i] = 1;

    for (size_t level = 1; level < contents.size(); ++level) {
        for (size_t i = 0; i < contents[level].size(); ++i) {
            const auto &dat = contents[level][i];
            size_t count = 0;
            for (uint32_t child = dat.start; child < dat.end; ++child) {
                count += subtree_counts[level - 1][child];
            }
            subtree_counts[level][i] = count;
        }
    }

    return subtree_counts;
}

static size_t get_runtime_chain_count_for_node(
    int level,
    const chainer::cprog_data<uint64_t> &dat,
    const std::vector<std::vector<size_t>> &subtree_counts)
{
    if (level == 0)
        return 1;

    size_t count = 0;
    for (uint32_t child = dat.start; child < dat.end; ++child) {
        count += subtree_counts[level - 1][child];
    }

    return count;
}

static void print_runtime_filter_progress(
    size_t total_count, size_t valid_count,
    runtime_filter_progress &progress)
{
    if (progress.total == 0)
        return;

    const auto now = std::chrono::steady_clock::now();
    const long double percent = (long double)total_count * 100.0L / (long double)progress.total;
    const size_t basis_points = (size_t)(percent * 100.0L);
    const bool final_update = total_count == progress.total;
    const bool percent_changed = !progress.printed || basis_points != progress.last_basis_points;
    const bool timed_update = progress.printed && total_count != progress.last_count &&
                              std::chrono::duration_cast<std::chrono::milliseconds>(now - progress.last_report_at).count() >= 500;

    if (!percent_changed && !timed_update && !final_update)
        return;

    progress.last_basis_points = basis_points;
    progress.last_count = total_count;
    progress.last_report_at = now;
    progress.printed = true;

    if (percent < 0.01L) {
        printf("\r[*] 过滤进度: %.6Lf%% (%zu/%zu), 有效: %zu",
               percent, total_count, progress.total, valid_count);
    } else if (percent < 1.0L) {
        printf("\r[*] 过滤进度: %.4Lf%% (%zu/%zu), 有效: %zu",
               percent, total_count, progress.total, valid_count);
    } else {
        printf("\r[*] 过滤进度: %.2Lf%% (%zu/%zu), 有效: %zu",
               percent, total_count, progress.total, valid_count);
    }
    fflush(stdout);

    if (final_update)
        printf("\n");
}

static void flush_runtime_filter_worker_state(
    runtime_filter_shared_state &shared,
    runtime_filter_worker_state &worker,
    bool force)
{
    const bool has_pending = worker.pending_total != 0 || worker.pending_valid != 0;
    const auto now = std::chrono::steady_clock::now();
    const bool should_flush = force || worker.pending_valid != 0 || worker.pending_total >= 1024 ||
                              std::chrono::duration_cast<std::chrono::milliseconds>(now - worker.last_sync_at).count() >= 200;

    if (!has_pending || !should_flush)
        return;

    size_t total_count = shared.total_count.fetch_add(worker.pending_total, std::memory_order_relaxed) + worker.pending_total;
    size_t valid_count = shared.valid_count.fetch_add(worker.pending_valid, std::memory_order_relaxed) + worker.pending_valid;

    worker.pending_total = 0;
    worker.pending_valid = 0;
    worker.last_sync_at = now;

    std::lock_guard<std::mutex> lock(shared.progress_mutex);
    print_runtime_filter_progress(total_count, valid_count, shared.progress);
}

static void write_runtime_filter_match(
    const runtime_filter_task &task,
    uint64_t target_addr,
    const std::vector<size_t> &offset_stack,
    runtime_filter_shared_state &shared)
{
    std::lock_guard<std::mutex> lock(shared.output_mutex);
    write_filter_txt_line(task.sym_name, task.sym_count, task.root_addr, task.sym_start,
                          offset_stack, shared.out_f);
}

// 递归收集偏移并验证
// current_addr: 当前前缀解析到的地址
static void verify_chain_runtime_recursive(
    int level,
    const chainer::cprog_data<uint64_t> &dat,
    const std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    const std::vector<std::vector<size_t>> &subtree_counts,
    const runtime_filter_task &task,
    uint64_t current_addr,
    uint64_t target_addr,
    runtime_filter_shared_state &shared,
    runtime_filter_worker_state &worker,
    size_t subtree_total)
{
    if (level == 0) {
        ++worker.pending_total;
        if (current_addr == target_addr) {
            write_runtime_filter_match(task, target_addr, worker.offset_stack, shared);
            ++worker.pending_valid;
        }

        flush_runtime_filter_worker_state(shared, worker, false);
        return;
    }

    uint64_t value = 0;
    long ret = memtool::base::readv(current_addr, &value, sizeof(value));
    if (ret <= 0) {
        worker.pending_total += subtree_total;
        flush_runtime_filter_worker_state(shared, worker, false);
        return;
    }

    for (uint32_t i = dat.start; i < dat.end; ++i) {
        const auto &next = contents[level - 1][i];
        size_t off = (size_t)(next.address - dat.value);
        worker.offset_stack.push_back(off);
        verify_chain_runtime_recursive(level - 1, next, contents, subtree_counts,
                                       task, value + off, target_addr,
                                       shared, worker, subtree_counts[level - 1][i]);
        worker.offset_stack.pop_back();
    }
}

static void process_runtime_filter_task(
    const runtime_filter_task &task,
    const std::vector<utils::varray<chainer::cprog_data<uint64_t>>> &contents,
    const std::vector<std::vector<size_t>> &subtree_counts,
    uint64_t target_addr,
    runtime_filter_shared_state &shared,
    runtime_filter_worker_state &worker)
{
    worker.offset_stack.clear();
    size_t reserve_count = task.level > 0 ? (size_t)task.level : 1;
    if (worker.offset_stack.capacity() < reserve_count)
        worker.offset_stack.reserve(reserve_count);

    verify_chain_runtime_recursive(task.level, *task.dat, contents, subtree_counts,
                                   task, task.root_addr, target_addr,
                                   shared, worker, task.subtree_total);
    flush_runtime_filter_worker_state(shared, worker, true);
}

static int do_filter(scan_params &p)
{
    normalize_scan_params(p);

    // 输入过滤源文件
    std::string source_path = normalize_path_in_base_dir(p.output, "BaseSniper_result.bin");
    std::string input = read_line("[?] 输入过滤源文件名 (.bin/.txt，固定目录: /sdcard/BaseSniper) [" +
                                  std::string(path_filename(source_path.c_str())) + "]: ");
    if (!input.empty())
        source_path = normalize_path_in_base_dir(input, "BaseSniper_result.bin");

    bool source_is_txt = has_file_ext(source_path, ".txt");
    bool source_is_bin = has_file_ext(source_path, ".bin");
    if (!source_is_txt && !source_is_bin) {
        fprintf(stderr, "[!] 仅支持 .bin 或 .txt 作为过滤源: %s\n", source_path.c_str());
        return 1;
    }

    // 输入新的目标地址
    input = read_line("[?] 输入新的目标地址 (十六进制): ");
    if (input.empty()) {
        fprintf(stderr, "[!] 必须输入目标地址\n");
        return 1;
    }
    uint64_t target_addr = strtoull(input.c_str(), nullptr, 16);

    // 选择验证模式
    bool runtime_mode = false;
    if (source_is_txt) {
        runtime_mode = true;
        printf("\n[*] 检测到 txt 过滤源，仅支持运行时验证模式\n");
    } else {
        printf("\n  验证模式:\n");
        printf("  [1] 静态验证 - 仅比对 .bin 中记录的最终地址 (离线，不需要目标进程)\n");
        printf("  [2] 运行时验证 - 实时读取目标进程内存逐级验证 (需要目标进程运行中)\n");
        input = read_line("\n  请选择 [1]: ");
        runtime_mode = (input == "2");
    }

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
        memtool::base::configure_rw_backend(p.use_kernel_rw, p.kernel_rw_mode);
        printf("[*] PID: %d\n", memtool::base::target_pid);
    }

    // 输出格式
    filter_output_mode output_mode = FILTER_OUTPUT_TXT;
    if (source_is_txt) {
        printf("\n[*] txt 过滤源当前仅支持输出 txt\n");
    } else {
        printf("\n  输出格式:\n");
        printf("  [1] 压缩格式 (.bin，可再次格式化)\n");
        printf("  [2] txt 格式 (仅保留指针偏移链)\n");
        input = read_line("\n  请选择 [2]: ");
        output_mode = (input == "1") ? FILTER_OUTPUT_BIN : FILTER_OUTPUT_TXT;
    }

    // 输出文件
    std::string default_out = output_mode == FILTER_OUTPUT_BIN ? DEFAULT_FILTER_BIN_PATH : DEFAULT_FILTER_PATH;

    input = read_line("[?] 输出文件名 (固定目录: /sdcard/BaseSniper) [" +
                      std::string(path_filename(default_out.c_str())) + "]: ");
    std::string out_path = input.empty()
                           ? default_out
                           : normalize_path_in_base_dir(input, output_mode == FILTER_OUTPUT_BIN
                                                                ? "BaseSniper_result_filtered.bin"
                                                                : "BaseSniper_result_filtered.txt");

    if (!ensure_parent_dir(out_path.c_str())) {
        fprintf(stderr, "[!] 无法创建输出目录: %s\n", out_path.c_str());
        return 1;
    }

    FILE *fout = fopen(out_path.c_str(), output_mode == FILTER_OUTPUT_BIN ? "wb+" : "w+");
    if (fout == nullptr) {
        fprintf(stderr, "[!] 无法创建输出文件: %s\n", out_path.c_str());
        return 1;
    }

    if (runtime_mode && output_mode == FILTER_OUTPUT_TXT)
        setvbuf(fout, nullptr, _IONBF, 0);

    size_t valid_count = 0;
    size_t total_count = 0;

    if (source_is_txt) {
        printf("[*] 正在解析 txt 数据...\n");
        fflush(stdout);

        memtool::extend::get_target_mem();
        auto entries = load_txt_chain_entries(source_path);
        if (entries.empty()) {
            fclose(fout);
            fprintf(stderr, "[!] txt 中没有可过滤的链: %s\n", source_path.c_str());
            return 1;
        }

        printf("[*] 过滤中... 目标地址: 0x%" PRIx64 " 模式: 运行时验证 (txt 源)\n", target_addr);
        for (const auto &entry : entries) {
            ++total_count;
            uint64_t root_addr = 0;
            if (!verify_txt_chain_runtime(entry, target_addr, root_addr))
                continue;

            write_filter_txt_line(entry.sym_name.c_str(), entry.sym_count, root_addr,
                                  root_addr - entry.root_offset, entry.offsets, fout);
            ++valid_count;
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

    FILE *fin = fopen(source_path.c_str(), "rb+");
    if (fin == nullptr) {
        fclose(fout);
        fprintf(stderr, "[!] 无法打开文件: %s\n", source_path.c_str());
        return 1;
    }

    printf("[*] 正在解析 bin 数据...\n");
    fflush(stdout);

    chainer::cformat<uint64_t> formatter;
    auto chain_data = formatter.parse_cprog_bin_data(fin);
    fclose(fin);

    auto &syms = chain_data.syms;
    auto &contents = chain_data.contents;

    printf("[*] 过滤中... 目标地址: 0x%" PRIx64 " 模式: %s\n",
           target_addr, runtime_mode ? "运行时验证" : "静态验证");

    if (runtime_mode && output_mode == FILTER_OUTPUT_TXT) {
        // 运行时验证: 逐级 readv 目标进程
        printf("[*] 正在统计链数...\n");
        fflush(stdout);

        auto subtree_counts = build_runtime_subtree_counts(contents);
        size_t task_count = 0;
        for (auto &sym : syms) {
            task_count += sym.data.size();
        }

        std::vector<runtime_filter_task> tasks;
        tasks.reserve(task_count);
        for (auto &sym : syms) {
            for (auto &dat : sym.data) {
                size_t subtree_total = get_runtime_chain_count_for_node(sym.sym->level, dat, subtree_counts);
                tasks.push_back(runtime_filter_task {
                    sym.sym->level,
                    &dat,
                    dat.address,
                    sym.sym->start,
                    sym.sym->name,
                    sym.sym->count,
                    subtree_total,
                });
                total_count += subtree_total;
            }
        }

        runtime_filter_shared_state shared;
        shared.out_f = fout;
        shared.progress.total = total_count;

        size_t filter_threads = p.threads > 0 ? (size_t)p.threads : 1;
        if (tasks.empty())
            filter_threads = 1;
        else if (filter_threads > tasks.size())
            filter_threads = tasks.size();

        printf("[*] 待验证链数: %zu\n", total_count);
        printf("[*] 过滤线程: %zu\n", filter_threads);
        print_runtime_filter_progress(0, 0, shared.progress);

        std::atomic_size_t next_task {0};
        auto worker_fn = [&]() {
            runtime_filter_worker_state worker;
            while (true) {
                size_t index = next_task.fetch_add(1, std::memory_order_relaxed);
                if (index >= tasks.size())
                    break;

                process_runtime_filter_task(tasks[index], contents, subtree_counts,
                                            target_addr, shared, worker);
            }
            flush_runtime_filter_worker_state(shared, worker, true);
        };

        std::vector<std::thread> workers;
        workers.reserve(filter_threads > 0 ? filter_threads - 1 : 0);
        for (size_t i = 1; i < filter_threads; ++i) {
            workers.emplace_back(worker_fn);
        }
        worker_fn();
        for (auto &worker : workers) {
            worker.join();
        }

        total_count = shared.total_count.load(std::memory_order_relaxed);
        valid_count = shared.valid_count.load(std::memory_order_relaxed);
    } else if (!runtime_mode && output_mode == FILTER_OUTPUT_TXT) {
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
    } else {
        std::vector<filtered_runtime_sym> filtered_syms;
        filtered_syms.reserve(syms.size());

        int max_level = 0;
        for (const auto &sym : syms) {
            if (sym.sym->level > max_level)
                max_level = sym.sym->level;
        }
        std::vector<std::vector<chainer::cprog_data<uint64_t>>> filtered_contents((size_t)max_level + 1);

        for (auto &sym : syms) {
            filtered_runtime_sym filtered_sym;
            filtered_sym.start = sym.sym->start;
            filtered_sym.range = sym.sym->range;
            filtered_sym.count = sym.sym->count;
            filtered_sym.level = sym.sym->level;
            filtered_sym.name = sym.sym->name;

            for (auto &dat : sym.data) {
                ++total_count;
                if (runtime_mode) {
                    filtered_runtime_node root;
                    if (!append_filtered_runtime_node(sym.sym->level, dat, contents, dat.address, target_addr, root))
                        continue;

                    uint32_t root_index = 0;
                    flatten_filtered_runtime_node(root, sym.sym->level, filtered_contents, root_index);
                    filtered_bin_root root_info;
                    root_info.data.address = root.address;
                    root_info.data.value = root.value;
                    root_info.data.start = root_index;
                    root_info.data.end = root_index + 1;
                    filtered_sym.roots.emplace_back(std::move(root_info));
                    ++valid_count;
                } else {
                    bool matched = false;
                    uint32_t root_index = append_filtered_bin_node(sym.sym->level, dat, contents, target_addr,
                                                                   filtered_contents, matched);
                    if (!matched)
                        continue;

                    filtered_bin_root root_info;
                    root_info.data.address = dat.address;
                    root_info.data.value = dat.value;
                    root_info.data.start = root_index;
                    root_info.data.end = root_index + 1;
                    filtered_sym.roots.emplace_back(std::move(root_info));
                    ++valid_count;
                }
            }

            if (!filtered_sym.roots.empty())
                filtered_syms.emplace_back(std::move(filtered_sym));
        }

        valid_count = write_filtered_bin_file(filtered_syms, filtered_contents, fout);
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
    char link_buf[64];
    snprintf(addr_buf, sizeof(addr_buf), "0x%" PRIx64, p.address);
    if (p.has_link_range)
        snprintf(link_buf, sizeof(link_buf), "0x%" PRIx64 "-0x%" PRIx64, p.link_start, p.link_end);
    else
        strcpy(link_buf, "(未启用)");

    printf("\n  ┌─ 当前参数 ─────────────────────────────┐\n");
    printf("  │  1. 目标:      %-24s │\n", current_target_label(p).c_str());
    printf("  │  2. 目标地址:  %-24s │\n", p.has_address ? addr_buf : "(未设置)");
    printf("  │  3. 层级:      %-24d │\n", p.depth);
    printf("  │  4. 最小层级:  %-24d │\n", p.min_level);
    printf("  │  5. 偏移:      %-24zu │\n", p.offset);
    printf("  │  6. 线程数:    %-24d │\n", p.threads);
    printf("  │  7. 块大小:    %-24d │\n", p.block_size);
    printf("  │  8. 内存类型:  %-24s │\n", mem_types_to_string(p.mem_types));
    printf("  │  9. 基址模块:  %-24s │\n", p.base_module.empty() ? "(全部)" : p.base_module.c_str());
    printf("  │ 10. 内核读写:  %-24s │\n", kernel_rw_mode_to_string(p.use_kernel_rw, p.kernel_rw_mode));
    printf("  │ 11. 链路起点:  %-24s │\n", link_buf);
    printf("  │ 12. 输出文件:  %-24s │\n", p.output.c_str());
    printf("  │ 13. 格式化:    %-24s │\n", p.format_path.empty() ? "(未启用)" : p.format_path.c_str());
    printf("  └──────────────────────────────────────────┘\n\n");
}

static void interactive_set_params(scan_params &p)
{
    while (true) {
        print_params(p);

        printf(
            "  [1]  设置目标          [7]  设置块大小\n"
            "  [2]  设置目标地址      [8]  设置内存类型\n"
            "  [3]  设置层级          [9]  设置基址模块\n"
            "  [4]  设置最小层级      [10] 设置内核读写\n"
            "  [5]  设置偏移          [11] 设置链路起点\n"
            "  [6]  设置线程数\n"
            "  [12] 设置输出文件      [13] 设置格式化文件\n"
            "  [s]  保存配置          [l]  加载配置\n"
            "  [0]  返回上级菜单\n"
            "\n");

        std::string choice = read_line("  请选择> ");

        if (choice == "0" || choice.empty()) return;

        std::string input;

        if (choice == "1") {
            input = read_line("  目标 (输入数字为PID，否则为包名) [" + current_target_label(p) + "]: ");
            if (!input.empty()) set_target(p, input);
        } else if (choice == "2") {
            char buf[32];
            snprintf(buf, sizeof(buf), "%" PRIx64, p.address);
            input = read_line(std::string("  目标地址 (十六进制) [0x") + buf + "]: ");
            if (!input.empty()) { p.address = strtoull(input.c_str(), nullptr, 16); p.has_address = true; }
        } else if (choice == "3") {
            input = read_line("  层级 [" + std::to_string(p.depth) + "]: ");
            if (!input.empty()) p.depth = atoi(input.c_str());
        } else if (choice == "4") {
            input = read_line("  最小层级 [" + std::to_string(p.min_level) + "]: ");
            if (!input.empty()) p.min_level = atoi(input.c_str());
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
            input = read_line("  基址模块 (如 libUE4.so,libanogs.so，输入 all 清除) [" +
                              (p.base_module.empty() ? std::string("全部") : p.base_module) + "]: ");
            if (!input.empty())
                set_base_module_filter(p, input);
        } else if (choice == "10") {
            input = read_line(std::string("  内核读写模式 [") + kernel_rw_mode_to_string(p.use_kernel_rw, p.kernel_rw_mode) +
                              "] (off/dev/hook): ");
            if (!input.empty()) {
                std::string rw = trim_string(input);
                if (rw == "off" || rw == "0" || rw == "false") {
                    p.use_kernel_rw = false;
                } else {
                    int mode = p.kernel_rw_mode;
                    if (!parse_kernel_rw_mode(rw, mode))
                        fprintf(stderr, "  [!] 无效模式，保持原值\n");
                    else {
                        p.use_kernel_rw = true;
                        p.kernel_rw_mode = mode;
                    }
                }
            }
        } else if (choice == "11") {
            char buf[64];
            if (p.has_link_range)
                snprintf(buf, sizeof(buf), "0x%" PRIx64 "-0x%" PRIx64, p.link_start, p.link_end);
            else
                strcpy(buf, "未启用");

            input = read_line(std::string("  链路起点范围 (十六进制, 例 0x1000-0x2000，输入 off 清除) [") + buf + "]: ");
            if (!input.empty()) {
                if (input == "off" || input == "OFF" || input == "0") {
                    p.has_link_range = false;
                } else if (!parse_address_range_text(input, p.link_start, p.link_end)) {
                    fprintf(stderr, "  [!] 范围格式错误，保持原值\n");
                } else {
                    p.has_link_range = true;
                }
            }
        } else if (choice == "12") {
            input = read_line("  输出文件名 (固定保存到 /sdcard/BaseSniper) [" +
                              std::string(path_filename(p.output.c_str())) + "]: ");
            if (!input.empty())
                p.output = normalize_path_in_base_dir(input, "BaseSniper_result.bin");
        } else if (choice == "13") {
            input = read_line("  格式化文件名 (固定保存到 /sdcard/BaseSniper) [" +
                              (p.format_path.empty() ? std::string("未启用") : std::string(path_filename(p.format_path.c_str()))) + "]: ");
            if (!input.empty())
                p.format_path = normalize_path_in_base_dir(input, "BaseSniper_result.txt");
        } else if (choice == "s" || choice == "S") {
            normalize_scan_params(p);
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
        {"link-range", required_argument, 0, 'R'},
        {"kernel-rw",  required_argument, 0, 'k'},
        {"no-kernel-rw", no_argument,     0, 'K'},
        {"depth",      required_argument, 0, 'd'},
        {"min-level",  required_argument, 0, 'L'},
        {"range",      required_argument, 0, 'r'},
        {"threads",    required_argument, 0, 't'},
        {"block-size", required_argument, 0, 's'},
        {"module",     required_argument, 0, 'M'},
        {"mem",        required_argument, 0, 'm'},
        {"output",     required_argument, 0, 'o'},
        {"format",     required_argument, 0, 'f'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:P:a:R:k:Kd:L:r:t:s:M:m:o:f:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p': p.package     = optarg; break;
            case 'P': p.pid         = atoi(optarg); break;
            case 'a': p.address     = strtoull(optarg, nullptr, 16); p.has_address = true; break;
            case 'R': p.has_link_range = parse_address_range_text(optarg, p.link_start, p.link_end); if (!p.has_link_range) { fprintf(stderr, "[!] Invalid --link-range: %s\n", optarg); return 1; } break;
            case 'k': p.use_kernel_rw = parse_kernel_rw_mode(optarg, p.kernel_rw_mode); if (!p.use_kernel_rw) { fprintf(stderr, "[!] Invalid --kernel-rw: %s\n", optarg); return 1; } break;
            case 'K': p.use_kernel_rw = false; break;
            case 'd': p.depth       = atoi(optarg); break;
            case 'L': p.min_level   = atoi(optarg); break;
            case 'r': p.offset      = strtoull(optarg, nullptr, 10); break;
            case 't': p.threads     = atoi(optarg); break;
            case 's': p.block_size  = atoi(optarg); break;
            case 'M': p.base_module = optarg; break;
            case 'm': p.mem_types   = parse_mem_types(optarg); break;
            case 'o': p.output      = optarg; break;
            case 'f': p.format_path = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    normalize_scan_params(p);

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
