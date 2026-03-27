#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>

namespace utils
{

class threadpool
{
private:
    void work_thread();
    void kill_thread();

    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    int thread_count;
    std::mutex mutex;
    std::condition_variable condition;
    bool stop;

public:
    threadpool(size_t);

    template <class F, class... Args>
    auto pushpool(F &&f, Args &&...args) -> std::future<decltype(f(args...))>;

    void change_thread(size_t count);

    void wait();

    ~threadpool();
};

} // namespace utils

#include "threadpool.hpp"