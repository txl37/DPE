#pragma once
#include "Global.h"

namespace app::fiber_manager
{
    inline std::recursive_mutex g_fibers_mutex;
    inline std::vector<std::shared_ptr<Fiber>> g_fibers;

    void add_fiber(const std::string& name, std::function<void()> function);
    void add_fiber(std::shared_ptr<Fiber> fiber);

    bool remove_fiber(const std::string& name);
    bool remove_fiber(std::uint32_t hash);
    void remove_all_fibers();
    void tick();
} 
