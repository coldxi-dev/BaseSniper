#pragma once

#include "threadpool.h"

template <class F, class... Args>
auto utils::threadpool::pushpool(F &&f, Args &&...args) -> std::future<decltype(f(args...))>
{
    auto task = std::make_shared<std::packaged_task<decltype(f(args...))()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
    {
        std::unique_lock<std::mutex> lock(mutex);

        tasks.emplace([task]() { (*task)(); });
    }
    condition.notify_one();
    return task->get_future();
}