#pragma once
#include "Global.h"

#pragma code_seg(".prot")

namespace app
{
    class __declspec(code_seg(".prot")) SpinLock
    {
    private:
        volatile long m_lock_val = 0;
    public:
        __declspec(safebuffers) void lock()
        {
            while (InterlockedCompareExchange(&m_lock_val, 1, 0) != 0)
            {
                YieldProcessor();
            }
        }

        __declspec(safebuffers) void unlock()
        {
            InterlockedExchange(&m_lock_val, 0);
        }
    };

    using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using VirtualQueryFn = SIZE_T(WINAPI*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    using VirtualQueryExFn = SIZE_T(WINAPI*)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

    struct ProtectedSection
    {
        uintptr_t base_addr = 0;
        size_t size = 0;
    };

    class PageProtection;
    inline PageProtection* g_instance = nullptr;
    inline VirtualQueryFn g_original_virtual_query = nullptr;
    inline VirtualQueryExFn g_original_virtual_query_ex = nullptr;

    __declspec(safebuffers) SIZE_T WINAPI hooked_virtual_query(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
    __declspec(safebuffers) SIZE_T WINAPI hooked_virtual_query_ex(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);

    class __declspec(code_seg(".prot")) PageProtection
    {
    private:
        ProtectedSection m_protected_sections[8] = {};
        size_t m_protected_section_count = 0;
        size_t m_page_size = 4096;
        uintptr_t m_active_page_1 = 0;
        uintptr_t m_active_page_2 = 0;
        std::uint8_t m_xor_key[256] = {};
        bool m_initialized = false;
        void* m_veh_handle = nullptr;
        SpinLock m_lock;
        size_t m_fault_count = 0;
        VirtualProtectFn m_virtual_protect = nullptr;

        __declspec(safebuffers) void xor_page(uintptr_t page_addr)
        {
            std::uint8_t* ptr = reinterpret_cast<std::uint8_t*>(page_addr);
            for (size_t i = 0; i < m_page_size; ++i)
            {
                ptr[i] ^= m_xor_key[i % 256];
            }
        }

        __declspec(safebuffers) void protect_page(uintptr_t page, DWORD protection)
        {
            DWORD previous = 0;
            if (!m_virtual_protect(reinterpret_cast<void*>(page), m_page_size, protection, &previous))
            {
                __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }
        }

        __declspec(safebuffers) void flush_page(uintptr_t page)
        {
            if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(page), m_page_size))
            {
                __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }
        }

        __declspec(safebuffers) void perform_iat_hook(const char* module_name, const char* function_name, void* hook_fn, void** original_fn)
        {
            uintptr_t module_base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
            IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);
            IMAGE_IMPORT_DESCRIPTOR* import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(module_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

            if (import_desc == nullptr || nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
            {
                return;
            }

            while (import_desc->Name != 0)
            {
                const char* cur_mod_name = reinterpret_cast<const char*>(module_base + import_desc->Name);
                std::string_view cur_mod_view(cur_mod_name);
                
                auto check_name = [](std::string_view s1, std::string_view s2) -> bool
                {
                    if (s1.size() != s2.size()) return false;
                    for (size_t idx = 0; idx < s1.size(); ++idx)
                    {
                        char c1 = s1[idx];
                        char c2 = s2[idx];
                        if (c1 >= 'A' && c1 <= 'Z') c1 = c1 - 'A' + 'a';
                        if (c2 >= 'A' && c2 <= 'Z') c2 = c2 - 'A' + 'a';
                        if (c1 != c2) return false;
                    }
                    return true;
                };

                if (check_name(cur_mod_view, module_name) || (cur_mod_view.ends_with(".dll") && check_name(cur_mod_view.substr(0, cur_mod_view.size() - 4), module_name)))
                {
                    if (import_desc->OriginalFirstThunk == 0)
                    {
                        return;
                    }
                    IMAGE_THUNK_DATA* original_first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(module_base + import_desc->OriginalFirstThunk);
                    IMAGE_THUNK_DATA* first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(module_base + import_desc->FirstThunk);

                    while (first_thunk->u1.Function != 0)
                    {
                        bool match = false;
                        if (original_first_thunk != nullptr && (original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0 && original_first_thunk->u1.AddressOfData != 0)
                        {
                            IMAGE_IMPORT_BY_NAME* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(module_base + original_first_thunk->u1.AddressOfData);
                            std::string_view cur_func_view(reinterpret_cast<const char*>(import_by_name->Name));
                            if (cur_func_view == function_name)
                            {
                                match = true;
                            }
                        }

                        if (match)
                        {
                            if (first_thunk->u1.Function == reinterpret_cast<uintptr_t>(hook_fn))
                            {
                                return;
                            }
                            DWORD old_protect = 0;
                            if (!m_virtual_protect(&first_thunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &old_protect))
                            {
                                return;
                            }
                            *original_fn = reinterpret_cast<void*>(first_thunk->u1.Function);
                            first_thunk->u1.Function = reinterpret_cast<uintptr_t>(hook_fn);
                            if (!m_virtual_protect(&first_thunk->u1.Function, sizeof(uintptr_t), old_protect, &old_protect))
                            {
                                __fastfail(FAST_FAIL_FATAL_APP_EXIT);
                            }
                            return;
                        }

                        if (original_first_thunk != nullptr) original_first_thunk++;
                        first_thunk++;
                    }
                }
                import_desc++;
            }
        }

    public:
        __declspec(safebuffers) PageProtection()
        {
            g_instance = this;
        }

        ~PageProtection() = default;
        PageProtection(const PageProtection&) = delete;
        PageProtection& operator=(const PageProtection&) = delete;

        __declspec(safebuffers) static PageProtection& get()
        {
            static PageProtection instance;
            return instance;
        }

        __declspec(safebuffers) bool is_in_protected_section(uintptr_t addr) const
        {
            if (!m_initialized)
            {
                return false;
            }
            for (size_t i = 0; i < m_protected_section_count; ++i)
            {
                const auto& sec = m_protected_sections[i];
                if (addr >= sec.base_addr && addr < (sec.base_addr + sec.size))
                {
                    return true;
                }
            }
            return false;
        }

        __declspec(safebuffers) size_t get_fault_count() const
        {
            return m_fault_count;
        }

        __declspec(safebuffers) uintptr_t get_active_page_1() const
        {
            return m_active_page_1;
        }

        __declspec(safebuffers) uintptr_t get_active_page_2() const
        {
            return m_active_page_2;
        }

        __declspec(safebuffers) void handle_page_fault(uintptr_t fault_addr)
        {
            m_lock.lock();
            uintptr_t fault_page = fault_addr - (fault_addr % m_page_size);

            if (m_active_page_1 == fault_page || m_active_page_2 == fault_page)
            {
                m_lock.unlock();
                return;
            }

            if (m_active_page_1 != 0 && m_active_page_2 != 0)
            {
                protect_page(m_active_page_1, PAGE_READWRITE);
                xor_page(m_active_page_1);
                protect_page(m_active_page_1, PAGE_NOACCESS);

                m_active_page_1 = m_active_page_2;
                m_active_page_2 = 0;
            }

            protect_page(fault_page, PAGE_READWRITE);
            xor_page(fault_page);
            protect_page(fault_page, PAGE_EXECUTE_READ);
            flush_page(fault_page);

            if (m_active_page_1 == 0)
            {
                m_active_page_1 = fault_page;
            }
            else
            {
                m_active_page_2 = fault_page;
            }

            m_fault_count++;
            m_lock.unlock();
        }

        __declspec(safebuffers) static LONG WINAPI vectored_exception_handler(EXCEPTION_POINTERS* exception_info)
        {
            DWORD exception_code = exception_info->ExceptionRecord->ExceptionCode;
            if (exception_code == STATUS_ACCESS_VIOLATION &&
                exception_info->ExceptionRecord->NumberParameters >= 2 &&
                exception_info->ExceptionRecord->ExceptionInformation[0] != 1)
            {
                uintptr_t fault_addr = exception_info->ExceptionRecord->ExceptionInformation[1];
                if (g_instance != nullptr && g_instance->is_in_protected_section(fault_addr))
                {
                    g_instance->handle_page_fault(fault_addr);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        __declspec(safebuffers) bool read_encrypted_bytes(uintptr_t func_addr, std::array<std::uint8_t, 16>& out_bytes)
        {
            if (!is_in_protected_section(func_addr) || func_addr > UINTPTR_MAX - 15 ||
                !is_in_protected_section(func_addr + 15))
            {
                return false;
            }
            auto* output = out_bytes.data();
            m_lock.lock();
            for (size_t i = 0; i < 16;)
            {
                uintptr_t address = func_addr + i;
                uintptr_t page = address - (address % m_page_size);
                bool active = page == m_active_page_1 || page == m_active_page_2;
                if (!active)
                {
                    protect_page(page, PAGE_READONLY);
                }
                do
                {
                    auto byte = *reinterpret_cast<const std::uint8_t*>(func_addr + i);
                    output[i] = active ? byte ^ m_xor_key[(func_addr + i - page) % 256] : byte;
                    ++i;
                } while (i < 16 && func_addr + i - page < m_page_size);
                if (!active)
                {
                    protect_page(page, PAGE_NOACCESS);
                }
            }
            m_lock.unlock();
            return true;
        }

        __declspec(safebuffers) bool initialize()
        {
            if (m_initialized)
            {
                return true;
            }
            m_protected_section_count = 0;
            m_fault_count = 0;
            m_virtual_protect = reinterpret_cast<VirtualProtectFn>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect"));
            if (m_virtual_protect == nullptr)
            {
                return false;
            }

            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            m_page_size = sys_info.dwPageSize;

            uintptr_t module_base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
            IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);
            IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);

            for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
            {
                std::array<char, 9> sec_name = {};
                std::copy_n(reinterpret_cast<const char*>(section_header[i].Name), 8, sec_name.begin());
                std::string_view name_view(sec_name.data());
                if (name_view == ".text" || name_view.starts_with(".test_"))
                {
                    if (section_header[i].Misc.VirtualSize == 0)
                    {
                        continue;
                    }
                    if (m_protected_section_count < 8)
                    {
                        if (section_header[i].VirtualAddress % m_page_size != 0 ||
                            nt_headers->OptionalHeader.SectionAlignment < m_page_size)
                        {
                            return false;
                        }
                        m_protected_sections[m_protected_section_count].base_addr = module_base + section_header[i].VirtualAddress;
                        m_protected_sections[m_protected_section_count].size =
                            (static_cast<size_t>(section_header[i].Misc.VirtualSize) + m_page_size - 1) / m_page_size * m_page_size;
                        m_protected_section_count++;
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            for (size_t i = 0; i < 256; ++i)
            {
                m_xor_key[i] = static_cast<uint8_t>((__rdtsc() ^ i) & 0xFF);
            }

            g_original_virtual_query = reinterpret_cast<VirtualQueryFn>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualQuery"));
            g_original_virtual_query_ex = reinterpret_cast<VirtualQueryExFn>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualQueryEx"));

            m_veh_handle = AddVectoredExceptionHandler(1, vectored_exception_handler);
            if (m_veh_handle == nullptr)
            {
                return false;
            }
            perform_iat_hook("kernel32", "VirtualQuery", reinterpret_cast<void*>(&hooked_virtual_query), reinterpret_cast<void**>(&g_original_virtual_query));
            perform_iat_hook("kernel32", "VirtualQueryEx", reinterpret_cast<void*>(&hooked_virtual_query_ex), reinterpret_cast<void**>(&g_original_virtual_query_ex));
            m_initialized = true;

            for (size_t i = 0; i < m_protected_section_count; ++i)
            {
                const auto& sec = m_protected_sections[i];
                uintptr_t start_page = sec.base_addr - (sec.base_addr % m_page_size);
                uintptr_t end_page = (sec.base_addr + sec.size + m_page_size - 1);
                end_page = end_page - (end_page % m_page_size);

                for (uintptr_t page = start_page; page < end_page; page += m_page_size)
                {
                    protect_page(page, PAGE_READWRITE);
                    xor_page(page);
                    protect_page(page, PAGE_NOACCESS);
                }
            }
            return true;
        }

        __declspec(safebuffers) void shutdown()
        {
            if (!m_initialized)
            {
                return;
            }

            for (size_t i = 0; i < m_protected_section_count; ++i)
            {
                const auto& sec = m_protected_sections[i];
                uintptr_t start_page = sec.base_addr - (sec.base_addr % m_page_size);
                uintptr_t end_page = (sec.base_addr + sec.size + m_page_size - 1);
                end_page = end_page - (end_page % m_page_size);

                for (uintptr_t page = start_page; page < end_page; page += m_page_size)
                {
                    protect_page(page, PAGE_READWRITE);
                    if (page == m_active_page_1 || page == m_active_page_2)
                    {
                        if (page == m_active_page_1) m_active_page_1 = 0;
                        if (page == m_active_page_2) m_active_page_2 = 0;
                    }
                    else
                    {
                        xor_page(page);
                    }
                    protect_page(page, PAGE_EXECUTE_READ);
                    flush_page(page);
                }
            }
            m_initialized = false;
            m_protected_section_count = 0;
            void* previous = nullptr;
            perform_iat_hook("kernel32", "VirtualQuery", reinterpret_cast<void*>(g_original_virtual_query), &previous);
            perform_iat_hook("kernel32", "VirtualQueryEx", reinterpret_cast<void*>(g_original_virtual_query_ex), &previous);
            if (m_veh_handle != nullptr)
            {
                RemoveVectoredExceptionHandler(m_veh_handle);
                m_veh_handle = nullptr;
            }
        }
    };

    __declspec(safebuffers) inline SIZE_T WINAPI hooked_virtual_query(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length)
    {
        SIZE_T res = g_original_virtual_query(address, buffer, length);
        if (res != 0 && buffer != nullptr && g_instance != nullptr)
        {
            uintptr_t addr = reinterpret_cast<uintptr_t>(address);
            if (g_instance->is_in_protected_section(addr))
            {
                buffer->Protect = PAGE_NOACCESS;
                buffer->AllocationProtect = PAGE_NOACCESS;
                buffer->State = MEM_COMMIT;
            }
        }
        return res;
    }

    __declspec(safebuffers) inline SIZE_T WINAPI hooked_virtual_query_ex(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length)
    {
        SIZE_T res = g_original_virtual_query_ex(process, address, buffer, length);
        if (res != 0 && buffer != nullptr && g_instance != nullptr &&
            GetProcessId(process) == GetCurrentProcessId())
        {
            uintptr_t addr = reinterpret_cast<uintptr_t>(address);
            if (g_instance->is_in_protected_section(addr))
            {
                buffer->Protect = PAGE_NOACCESS;
                buffer->AllocationProtect = PAGE_NOACCESS;
                buffer->State = MEM_COMMIT;
            }
        }
        return res;
    }
}

#pragma code_seg()
