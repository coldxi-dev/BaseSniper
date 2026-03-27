#ifndef UTILS_THREAD_POOL_DEFINE
#define UTILS_THREAD_POOL_DEFINE

#include "threadpool.h"

void utils::threadpool::work_thread()
{
    for (;;) {
        std::function<void()> task;

        std::unique_lock<std::mutex> lock(this->mutex);

        this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });

        if (this->stop && this->tasks.empty())
            return;

        task = std::move(this->tasks.front());
        this->tasks.pop();

        lock.unlock();

        task();
    }
}

void utils::threadpool::change_thread(size_t count)
{
    kill_thread();
    workers.clear();
    thread_count = count;

    for (size_t i = 0; i < count; ++i)
        workers.emplace_back([this] { work_thread(); });
}

void utils::threadpool::kill_thread()
{
    if (workers.empty())
        return;

    std::unique_lock<std::mutex> lock(mutex);
    stop = true;
    lock.unlock();

    condition.notify_all();

    for (auto &worker : workers) {
        if (worker.joinable())
            worker.join();
    }

    lock.lock();
    stop = false;
    lock.unlock();
}

void utils::threadpool::wait()
{
    kill_thread();
    change_thread(this->thread_count);
}

utils::threadpool::threadpool(size_t count) : thread_count(count), stop(false)
{
    change_thread(this->thread_count);
}

utils::threadpool::~threadpool()
{
    kill_thread();
}

#endif