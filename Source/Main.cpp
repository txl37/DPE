#include "Global.h"
#include "PageProtection.h"

using namespace app;

inline volatile int g_test_var_1 = 0;
inline volatile int g_test_var_2 = 0;
inline volatile int g_test_var_3 = 0;
inline bool g_self_test = false;

#pragma code_seg(".test_1")
__declspec(noinline) void test_function_1()
{
    if (!g_self_test) DBG("test_function_1 executing - string token: [test_fn_one]");
    g_test_var_1 = 12345;
}

#pragma code_seg(".test_2")
__declspec(noinline) void test_function_2()
{
    if (!g_self_test) DBG("test_function_2 executing - string token: [test_fn_two]");
    g_test_var_2 = 67890;
}

#pragma code_seg(".test_3")
__declspec(noinline) void test_function_3()
{
    if (!g_self_test) DBG("test_function_3 executing - string token: [test_fn_three]");
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
            if (!PageProtection::get().read_encrypted_bytes(reinterpret_cast<uintptr_t>(&test_function_1), current_bytes))
            {
                CMD("Error", "Could not read the protected function bytes");
                return;
            }
            
            std::string current_hex;
            for (std::uint8_t b : current_bytes)
            {
                current_hex += std::format("{:02X} ", b);
            }
            
            DBG("Encrypted byte preview of test_function_1: {}", current_hex);
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

#pragma code_seg(".prot")
__declspec(noinline) int run_self_test()
{
    g_self_test = true;
    auto& protection = PageProtection::get();
    const auto address = reinterpret_cast<uintptr_t>(&test_function_1);
    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);
    const auto module = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module + dos->e_lfanew);
    const auto sections = IMAGE_FIRST_SECTION(nt);
    uintptr_t boundary = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (sections[i].Name[0] == '.' && sections[i].Name[1] == 't' &&
            sections[i].Name[2] == 'e' && sections[i].Name[3] == 'x' &&
            sections[i].Name[4] == 't' && sections[i].Name[5] == 0 &&
            sections[i].Misc.VirtualSize >= 2 * system_info.dwPageSize)
        {
            boundary = module + sections[i].VirtualAddress + system_info.dwPageSize - 8;
        }
    }
    if (boundary == 0) return 12;
    std::uint8_t original[16];
    for (size_t i = 0; i < 16; ++i)
    {
        original[i] = reinterpret_cast<const std::uint8_t*>(address)[i];
    }
    protection.shutdown();
    for (int cycle = 0; cycle < 2; ++cycle)
    {
        if (!protection.initialize() || !protection.initialize()) return 1;
        std::array<std::uint8_t, 16> encrypted = {};
        std::array<std::uint8_t, 16> active = {};
        if (!protection.read_encrypted_bytes(address, encrypted)) return 2;
        if (protection.read_encrypted_bytes(0, active)) return 3;
        std::array<std::uint8_t, 16> crossing = {};
        if (!protection.read_encrypted_bytes(boundary, crossing)) return 13;
        if (!protection.read_encrypted_bytes(boundary, active)) return 14;
        for (size_t i = 0; i < 16; ++i)
        {
            if (crossing[i] != active[i]) return 15;
        }
        test_function_1();
        MEMORY_BASIC_INFORMATION memory = {};
        if (VirtualQuery(reinterpret_cast<void*>(address), &memory, sizeof(memory)) == 0 ||
            memory.Protect != PAGE_NOACCESS) return 16;
        if (VirtualQueryEx(GetCurrentProcess(), reinterpret_cast<void*>(address), &memory, sizeof(memory)) == 0 ||
            memory.Protect != PAGE_NOACCESS) return 17;
        EXCEPTION_RECORD record = {};
        record.ExceptionCode = STATUS_ACCESS_VIOLATION;
        record.NumberParameters = 2;
        record.ExceptionInformation[0] = 1;
        record.ExceptionInformation[1] = address;
        EXCEPTION_POINTERS exception = { &record, nullptr };
        if (PageProtection::vectored_exception_handler(&exception) != EXCEPTION_CONTINUE_SEARCH) return 18;
        if (!protection.read_encrypted_bytes(address, active)) return 4;
        bool differs = false;
        for (size_t i = 0; i < 16; ++i)
        {
            if (encrypted[i] != active[i]) return 5;
            if (encrypted[i] != original[i]) differs = true;
        }
        if (!differs) return 6;
        test_function_1();
        test_function_2();
        test_function_3();
        if (g_test_var_1 != 12345 || g_test_var_2 != 67890 || g_test_var_3 != 54321) return 7;
        if (protection.get_fault_count() < 3) return 8;
        if (!protection.read_encrypted_bytes(address, active)) return 9;
        for (size_t i = 0; i < 16; ++i)
        {
            if (encrypted[i] != active[i]) return 10;
        }
        protection.shutdown();
        protection.shutdown();
        if (VirtualQuery(reinterpret_cast<void*>(address), &memory, sizeof(memory)) == 0 ||
            memory.Protect != PAGE_EXECUTE_READ) return 19;
        for (size_t i = 0; i < 16; ++i)
        {
            if (reinterpret_cast<const std::uint8_t*>(address)[i] != original[i]) return 11;
        }
    }
    return 0;
}
#pragma code_seg()

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR command_line, int)
{
    if (std::string_view(command_line) == "--self-test")
    {
        return run_self_test();
    }
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

    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);
    CMD("Info", "test_function_1 page: 0x{:X}", addr1 - (addr1 % system_info.dwPageSize));
    CMD("Info", "test_function_2 page: 0x{:X}", addr2 - (addr2 % system_info.dwPageSize));
    CMD("Info", "test_function_3 page: 0x{:X}", addr3 - (addr3 % system_info.dwPageSize));

    std::array<std::uint8_t, 16> original_bytes = {};
    std::copy_n(reinterpret_cast<const std::uint8_t*>(&test_function_1), original_bytes.size(), original_bytes.begin());
    
    std::string original_hex;
    for (std::uint8_t b : original_bytes)
    {
        original_hex += std::format("{:02X} ", b);
    }
    CMD("Info", "Original unencrypted memory of test_function_1: {}", original_hex);

    if (!PageProtection::get().initialize())
    {
        CMD("Error", "Page protection initialization failed");
        cmd::destroy();
        return 1;
    }

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
    fiber_manager::remove_all_fibers();

    MessageBoxA(NULL, "Press OK to exit.", "Close Application", MB_OK);

    cmd::destroy();

    return 0;
}
