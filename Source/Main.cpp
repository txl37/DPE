#include "Global.h"
#include "PageProtection.h"

using namespace app;

inline volatile int g_test_var_1 = 0;
inline volatile int g_test_var_2 = 0;
inline volatile int g_test_var_3 = 0;

#pragma code_seg(".test_1")
__declspec(noinline) void test_function_1()
{
    DBG("test_function_1 executing - string token: [test_fn_one]");
    g_test_var_1 = 12345;
}

#pragma code_seg(".test_2")
__declspec(noinline) void test_function_2()
{
    DBG("test_function_2 executing - string token: [test_fn_two]");
    g_test_var_2 = 67890;
}

#pragma code_seg(".test_3")
__declspec(noinline) void test_function_3()
{
    DBG("test_function_3 executing - string token: [test_fn_three]");
    g_test_var_3 = 54321;
}

#pragma code_seg()

void fiber_loop()
{
    while (true)
    {
        util::do_timed("evict_and_check", 2000, []{
            test_function_1();
            test_function_2();
            test_function_3();

            std::array<std::uint8_t, 16> current_bytes = {};
            PageProtection::get().read_encrypted_bytes(reinterpret_cast<uintptr_t>(&test_function_1), current_bytes);
            
            std::string current_hex;
            for (std::uint8_t b : current_bytes)
            {
                current_hex += std::format("{:02X} ", b);
            }
            
            DBG("Encrypted memory of test_function_1 in dump: {}", current_hex);
        });

        util::do_timed("protection_stats", 1000, []{
            PageProtection& protection = PageProtection::get();
            DBG("Fault count: {} | Active page 1: 0x{:X} | Active page 2: 0x{:X}", 
                protection.get_fault_count(), 
                protection.get_active_page_1(),
                protection.get_active_page_2());
        });

        Fiber::get()->yield();
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR pCmdLine, int nCmdShow)
{
    Fiber::ensure_thread_is_a_fiber();

    cmd::create(APP);

    CMD("Info", "{} {}",
        cmd::detail::colorize("App:", Color(0xffffff)),
        cmd::detail::colorize("DPE POC", Color(0x6c98ff))
    );

    CMD("Info", "{} {}",
        cmd::detail::colorize("Unload Key:", Color(0xffffff)),
        cmd::detail::colorize("F12", Color(0x6c98ff))
    );

    cmd::raw_send("________________________________________________\n");

    uintptr_t addr1 = reinterpret_cast<uintptr_t>(&test_function_1);
    uintptr_t addr2 = reinterpret_cast<uintptr_t>(&test_function_2);
    uintptr_t addr3 = reinterpret_cast<uintptr_t>(&test_function_3);

    CMD("Info", "test_function_1 page: 0x{:X}", addr1 - (addr1 % 4096));
    CMD("Info", "test_function_2 page: 0x{:X}", addr2 - (addr2 % 4096));
    CMD("Info", "test_function_3 page: 0x{:X}", addr3 - (addr3 % 4096));

    std::array<std::uint8_t, 16> original_bytes = {};
    std::copy_n(reinterpret_cast<const std::uint8_t*>(&test_function_1), original_bytes.size(), original_bytes.begin());
    
    std::string original_hex;
    for (std::uint8_t b : original_bytes)
    {
        original_hex += std::format("{:02X} ", b);
    }
    CMD("Info", "Original unencrypted memory of test_function_1: {}", original_hex);

    PageProtection::get().initialize();

    fiber_manager::add_fiber("fiber_test", &fiber_loop);

    while (true)
    {
        fiber_manager::tick();

        if (input::is_key_pressed(VK_F12))
        {
            break;
        }

        std::this_thread::sleep_for(1ms);
    }

    PageProtection::get().shutdown();

    MessageBoxA(NULL, "Press OK to exit.", "Close Application", MB_OK);

    cmd::destroy();

    return 0;
}
