//
// Create by 青杉白衣 on 2023
//

#ifndef MEMTOOL_MEM_BASE
#define MEMTOOL_MEM_BASE

#include "membase.h"

int memtool::base::get_package_uid(const char *package)
{
    int uid = -1;
    char name[256];
    char *line = nullptr;
    size_t len;
    FILE *f;

    f = fopen("/data/system/packages.list", "r");
    if (f == nullptr)
        return uid;

    while (getline(&line, &len, f) > 0) {
        int tmp = sscanf(line, "%255s %d %*d %*s", name, &uid);

        if (tmp == 2 && strcmp(name, package) == 0)
            break;
    }

    free(line);
    fclose(f);
    return uid;
}

int memtool::base::get_pid_by_uid(int uid)
{
    int pid = -1;
    char name[64];
    char *content = (char *)malloc(4096);
    int ruid, euid, suid;

    DIR *dirinfo;
    struct dirent *entry;

    dirinfo = opendir("/proc");
    if (dirinfo == nullptr)
        return pid;

    while ((entry = readdir(dirinfo)) != nullptr) {
        int id;
        FILE *f;
        char *start;
        int tmp;

        id = atoi(entry->d_name);
        if (id == 0)
            continue;

        snprintf(name, sizeof(name), "/proc/%d/status", id);
        f = fopen(name, "r");
        if (f == nullptr)
            continue;

        tmp = fread(content, 1, 4095, f);
        content[tmp] = 0;
        fclose(f);

        start = strstr(content, "Uid:");
        if (start == nullptr)
            continue;

        tmp = sscanf(start, "Uid:%*[^0-9]%d%*[^0-9]%d%*[^0-9]%d%*[^0-9]%d\n", &ruid, &euid, &euid, &suid);
        if (tmp == 4 && ruid == uid) {
            pid = id;
            break;
        }
    }

    closedir(dirinfo);
    free(content);
    return pid;
}

int memtool::base::get_pid(const char *package)
{
    // int uid = get_package_uid(package);
    // if (uid == -1)
    //     return -1;
    //
    // return get_pid_by_uid(uid);
    pid_t pid;
    FILE* fp;
    char cmd[0x100] = "pidof ";
    strcat(cmd, package);
    fp = popen(cmd,"r");
    fscanf(fp,"%d", &pid);
    pclose(fp);
    return pid;
}

int memtool::base::judge_target_bit(pid_t pid)
{
    char path[128];
    struct stat i64, ti;

    sprintf(path, "/proc/%d/exe", pid);
    if ((stat("/system/bin/app_process64", &i64) == -1) || (stat(path, &ti)) == -1)
        return -1; // perror has been set

    return (ti.st_ino != i64.st_ino);
}

 void memtool::base::close_target_pagemap()
{
    if (page_handle == -1)
        return;

    close(page_handle), page_handle = -1;
}

void memtool::base::open_target_pagemap()
{
    char fname[64];

    snprintf(fname, sizeof(fname), "/proc/%d/pagemap", target_pid);
    close_target_pagemap();
    page_handle = open(fname, O_RDONLY);
}

memtool::base::base()
{

}

memtool::base::~base()
{
}

#endif
