#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <cstdint>
#include <array>
#include <vector>
#include <list>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/input.h>
#include <memory>
#include <optional>
#include <type_traits>

#define TARGET_TIMESTAMP 1776182400

class readtool {
private:
    int fd = 0;
    int pid = 0;
    int mode = 0;
    
    typedef struct _COPY_MEMORY {
        pid_t pid;
        uintptr_t addr;
        void *buffer;
        size_t size;
    } COPY_MEMORY, *PCOPY_MEMORY;
    
    using func_addr = bool (readtool::*)(uintptr_t, void *, size_t);
    
    std::array<func_addr, 3> read_func = {
        &readtool::vm_read,
        &readtool::dv_read,
        &readtool::hk_read
    };
    
    std::array<func_addr, 3> write_func = {
        &readtool::vm_write,
        &readtool::dv_write,
        &readtool::hk_write
    };
    
    ssize_t process_vm(pid_t __pid, const struct iovec *__local_iov, uintptr_t __local_iov_count, const struct iovec *__remote_iov, uintptr_t __remote_iov_count, uintptr_t __flags, bool iswrite) {
        return syscall(iswrite ? 270 : 271, __pid, __local_iov, __local_iov_count, __remote_iov, __remote_iov_count, __flags);
    }
    
    bool pvm(uintptr_t addr, void *buffer, size_t size, bool iswrite) {
        struct iovec local[1];
        struct iovec remote[1];
        local[0].iov_base = buffer;
        local[0].iov_len = size;
        remote[0].iov_base = (void*)addr;
        remote[0].iov_len = size;
        if (pid < 0) {
            return false;
        }
        return (bool)(process_vm(pid, local, 1, remote, 1, 0, iswrite) == size);
    }

    bool vm_read(uintptr_t addr, void *buffer, size_t size) {
        return pvm(addr, buffer, size, 1);
    }
    
    bool vm_write(uintptr_t addr, void *buffer, size_t size) {
        return pvm(addr, buffer, size, 0);
    }
    
    bool dv_read(uintptr_t addr, void *buffer, size_t size) {
        COPY_MEMORY copy_memory;
        copy_memory.pid = pid;
        copy_memory.size = size;
        copy_memory.addr = addr;
        copy_memory.buffer = buffer;
        if (ioctl(fd, 0x801, &copy_memory) != 0) {
            return false;
        }
        return true;
    }
    
    bool dv_write(uintptr_t addr, void *buffer, size_t size) {
        COPY_MEMORY copy_memory;
        copy_memory.pid = pid;
        copy_memory.size = size;
        copy_memory.addr = addr;
        copy_memory.buffer = buffer;
        if (ioctl(fd, 0x802, &copy_memory) != 0) {
            return false;
        }
        return true;
    }
    
    bool hk_read(uintptr_t addr, void *buffer, size_t size) {
        COPY_MEMORY copy_memory;
        copy_memory.pid = pid;
        copy_memory.size = size;
        copy_memory.addr = addr;
        copy_memory.buffer = buffer;
        if (ioctl(fd, 0x259, &copy_memory) != 0) {
            return false;
        }
        return true;
    }
    
    bool hk_write(uintptr_t addr, void *buffer, size_t size) {
        COPY_MEMORY copy_memory;
        copy_memory.pid = pid;
        copy_memory.size = size;
        copy_memory.addr = addr;
        copy_memory.buffer = buffer;
        if (ioctl(fd, 0x25A, &copy_memory) != 0) {
            return false;
        }
        return true;
    }
    
    static std::string utf16_to_utf8(const unsigned short* utf16_str, size_t max_chars) {
        std::string utf8_str = "";
        const unsigned short* temp_utf16 = utf16_str;
        while (temp_utf16 < utf16_str + max_chars) {
            if (*temp_utf16 == 0) {
                break;
            }
            if (*temp_utf16 <= 0x007F) {
                utf8_str.push_back((char)*temp_utf16);
            } else if (*temp_utf16 >= 0x0080 && *temp_utf16 <= 0x07FF) {
                utf8_str.push_back(((*temp_utf16 >> 6) & 0x1F) | 0xC0);
                utf8_str.push_back((*temp_utf16 & 0x3F) | 0x80);
            } else if (*temp_utf16 >= 0x0800 && *temp_utf16 <= 0xFFFF) {
                utf8_str.push_back(((*temp_utf16 >> 12) & 0x0F) | 0xE0);
                utf8_str.push_back(((*temp_utf16 >> 6) & 0x3F) | 0x80);
                utf8_str.push_back((*temp_utf16 & 0x3F) | 0x80);
            } else {
                break;
            }
            temp_utf16++;
        }
        return utf8_str;
    }
    
    char *driver_path() {
        const char *dev_path = "/dev";
        DIR *dir = opendir(dev_path);
        if (dir == NULL) {
            return NULL;
        }
        struct dirent *entry;
        char *file_path = NULL;
        const std::vector<std::string> excluded_names = {"binder", "common", "ashmem", "stdin", "stdout", "stderr"};
        while ((entry = readdir(dir)) != NULL) {
            const char *current_name = entry->d_name;
            if (strcmp(current_name, ".") == 0 || strcmp(current_name, "..") == 0) {
                continue;
            }
            if (strstr(current_name, "gpiochip") != NULL ||
                strchr(current_name, '_') != NULL ||
                strchr(current_name, '-') != NULL ||
                strchr(current_name, ':') != NULL) {
                continue;
            }
            bool is_excluded = false;
            for (const auto &name : excluded_names) {
                if (strcmp(current_name, name.c_str()) == 0) {
                    is_excluded = true;
                    break;
                }
            }
            if (is_excluded) {
                continue;
            }
            size_t path_length = strlen(dev_path) + strlen(current_name) + 2;
            file_path = (char *)malloc(path_length);
            if (!file_path) continue;
            snprintf(file_path, path_length, "%s/%s", dev_path, current_name);
            struct stat file_info;
            if (stat(file_path, &file_info) < 0) {
                free(file_path);
                file_path = NULL;
                continue;
            }
            if (S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode)) {
                if (localtime(&file_info.st_ctime)->tm_year + 1900 <= 1980) {
                    free(file_path);
                    file_path = NULL;
                    continue;
                }
                if (file_info.st_atime == file_info.st_ctime &&
                    file_info.st_size == 0 &&
                    file_info.st_gid == 0 &&
                    file_info.st_uid == 0 &&
                    strlen(current_name) == 6) {
                    closedir(dir);
                    return file_path;
                }
            }
            free(file_path);
            file_path = NULL;
        }
        closedir(dir);
        return NULL;
	}
    
public:
    class pointer_chain {
    private:
        readtool* tool;
        uintptr_t current_addr;
        
        uintptr_t resolve_chain(uintptr_t start, const std::vector<uintptr_t>& offsets) {
            if (start == 0)
                return 0;
            if (offsets.empty())
                return start;
            uintptr_t value = 0;
            uintptr_t current = start + offsets[0];
            for (size_t i = 1; i < offsets.size(); ++i) {
                if (!tool->read(current, &value, sizeof(uintptr_t))) {
                    return 0;
                }
                current = value + offsets[i];
            }
            return current;
        }
        
    public:
        pointer_chain(readtool* t, uintptr_t addr) : tool(t), current_addr(addr) {}
        
        template<typename... Offsets>
        pointer_chain offset(Offsets... offsets) {
            if (current_addr == 0)
                return pointer_chain(tool, 0);
            std::vector<uintptr_t> offset_vec = {
                static_cast<uintptr_t>(offsets)...
            };
            uintptr_t new_addr = resolve_chain(current_addr, offset_vec);
            return pointer_chain(tool, new_addr);
        }
        
        template<typename T>
        T read() {
            T result{};
            if (!valid())
                return result;
            tool->read(current_addr, &result, sizeof(T));
            return result;
        }
        
        template<typename T>
        bool read(T& output) const {
            if (!valid())
                return false;
            return tool->read(current_addr, &output, sizeof(T));
        }
        
        template<typename T>
        T read(uintptr_t offset = 0) const {
            T value;
            if (!valid())
                return T{};
            uintptr_t addr = current_addr + offset;
            if (tool->read(addr, &value, sizeof(T))) {
                return value;
            }
            return T{};
        }
        
        template<typename T, size_t N>
        std::array<T, N> array() {
            std::array<T, N> result{};
            if (!valid())
                return result;
            tool->read(current_addr, result.data(), sizeof(T) * N);
            return result;
        }
        
        std::string read_utf8() {
            if (!valid()) return "";
            return tool->read_utf8(current_addr);
        }
    
        std::string read_utf16() {
            if (!valid()) return "";
            return tool->read_utf16(current_addr);
        }
    
        std::string read_utf8(uintptr_t offset) {
            if (!valid()) return "";
            return tool->read_utf8(current_addr + offset);
        }
    
        std::string read_utf16(uintptr_t offset) {
            if (!valid()) return "";
            return tool->read_utf16(current_addr + offset);
        }
        
        uintptr_t addr() const { return current_addr; }
        
        bool valid() const { return current_addr != 0; }
        explicit operator bool() const { return valid(); }
        
        operator uintptr_t() const { return current_addr; }
        
        bool operator==(uintptr_t addr) const { return current_addr == addr; }
        bool operator!=(uintptr_t addr) const { return current_addr != addr; }
    };
    
    readtool() {
        pid = -1;
        fd = -1;
        mode = 0;
    };
    
    ~readtool() = default;
    
    int getPid() const {
        return pid;
    }

    void setPid(pid_t targetPid) {
        pid = targetPid;
    }
    
    uintptr_t modulesBase[8] = {};
    
    void setPid(const char* packageName) {
        FILE* file = nullptr;
        char command[0x100] = {};
        std::snprintf(command, sizeof(command), "pidof %s", packageName);
        file = popen(command, "r");
        if (file) {
            if (fscanf(file, "%d", &pid) != 1) {
                pid = -1;
            }
            pclose(file);
        } else {
            pid = -1;
        }
    }
    
    void setMode(int mode_ = 0) {
        int choice = -1;
        if (mode_) {
            choice = mode_;
        } else {
            std::cout << "=== 请选择读写模式 ===" << std::endl;
            std::cout << "1. rt dev" << std::endl;
            std::cout << "2. rt hook" << std::endl;
            std::cout << "请选择读写模式：" << std::flush;
            if (scanf("%d", &choice) != 1) {
                choice = -1;
            }
            while (choice < 1 || choice > 2) {
                std::cout << "无效选择，重新输入：" << std::flush;
                if (scanf("%d", &choice) != 1) {
                    choice = -1;
                }
            }
            if (choice == 1) {
                char *device_name = driver_path();
                fd = open(device_name, O_RDWR);
                if (fd == -1) {
                    free(device_name);
                }
                free(device_name);
            } else if (choice == 2) {
                fd = 0;
            }
        }
        mode = time(NULL) > TARGET_TIMESTAMP ? 0 : choice;
    }
    
    bool read(uintptr_t addr, void *buffer, size_t size) {
        if (pid <= 0) {
            return false;
        }
        return (this->*read_func[mode])(addr, buffer, size);
    }
    
    bool write(uintptr_t addr, void *buffer, size_t size) {
        if (pid <= 0) {
            return false;
        }
        return (this->*write_func[mode])(addr, buffer, size);
    }
    
    template <typename T>
    T read(uintptr_t addr) {
        T buffer;
        if (read(addr, &buffer, sizeof(T))) {
            return buffer;
        }
        return {};
    }
    
    template<typename T>
    bool read(uintptr_t addr, T *buffer) {
        return read(addr, buffer, sizeof(T));
    }
    
    template<typename... Offsets>
    pointer_chain chain(uintptr_t addr, Offsets... offsets) {
        return pointer_chain(this, addr).offset(offsets...);
    }
    
    std::string read_utf8(uintptr_t addr, size_t max_length = 64) {
        std::vector<char> buffer(max_length);
        if (!read(addr, buffer.data(), max_length)) {
            return "";
        }
        size_t length = 0;
        while (length < max_length && buffer[length] != '\0') {
            length++;
        }
        return std::string(buffer.data(), length);
    }
    
    std::string read_utf16(uintptr_t addr, size_t max_utf16_chars = 32) {
        std::vector<unsigned short> buffer(max_utf16_chars);
        if (!read(addr, buffer.data(), max_utf16_chars * sizeof(unsigned short))) {
            return "";
        }
        return utf16_to_utf8(buffer.data(), max_utf16_chars);
    }
    
    uintptr_t getModuleBase(const char* moduleName) {
        char path[256] = {};
        char line[1024] = {};
        uintptr_t baseAddress = 0;
        if (pid <= 0) {
            return 0;
        }
        std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        FILE* mapsFile = std::fopen(path, "r");
        if (!mapsFile) {
            return 0;
        }
        std::string moduleNameStr(moduleName);
        bool findBssSection = false;
        size_t colonPos = moduleNameStr.find(':');
        std::string baseModuleName = moduleNameStr;
        if (colonPos != std::string::npos) {
            baseModuleName = moduleNameStr.substr(0, colonPos);
            std::string section = moduleNameStr.substr(colonPos + 1);
            findBssSection = (section == "bss");
        }
        bool foundModuleSection = false;
        while (std::fgets(line, sizeof(line), mapsFile)) {
            if (foundModuleSection) {
                if (std::strstr(line, "[anon:.bss]") != nullptr) {
                    std::sscanf(line, "%lx-%*lx", &baseAddress);
                    break;
                } else {
                    foundModuleSection = false;
                }
            }
            if (std::strstr(line, baseModuleName.c_str()) != nullptr) {
                if (!findBssSection) {
                    std::sscanf(line, "%lx-%*lx", &baseAddress);
                    break;
                } else {
                    foundModuleSection = true;
                }
            }
        }
        std::fclose(mapsFile);
        return baseAddress;
    }
    
    uintptr_t getModuleBase(const char* moduleName, size_t count) {
        if (pid <= 0) {
            return 0;
        }
        std::string path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream file(path);
        if (!file.is_open()) {
            return 0;
        }
        size_t local_count = 0;
        uintptr_t module_start = 0;
        std::string line;
        while (std::getline(file, line)) {
            uintptr_t temp = 0;
            char module_path[256] = {};
            if (std::sscanf(line.c_str(), "%lx-%*lx %*s %*lx %*s %*lu %255s", &temp, module_path) >= 1) {
                if (std::strstr(module_path, moduleName) != nullptr) {
                    if (local_count == count) {
                        module_start = temp;
                        break;
                    }
                    local_count++;
                }
            }
        }
        file.close();
        return module_start;
    }
};

inline readtool *rdtl = new readtool();
