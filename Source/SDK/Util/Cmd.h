#pragma once
#include "Global.h"

namespace app
{
    struct Color;
}

namespace app
{
    class Cmd
    {
    public:
        std::ofstream m_console_out{};
        std::ofstream m_file_out{};

        std::filesystem::path m_log_path{};

        HANDLE m_console_handle{};
        DWORD  m_original_console_mode{};
        HWND m_hwnd{};
    public:
        static Cmd& get() 
        {
            static Cmd instance;
            return instance;
        }
    };
}

namespace app::cmd
{
    namespace detail
    {
        std::string colorize(const std::string& text, const Color& color);
        std::string colorize(const char c, const Color& col);
    }

    void create(const std::string& name);
    void destroy();

    void setup_folder();
    void sub_header(std::string text);
    void setup_console(const std::string& name);

    void send(const std::string& title, const std::string& message);

    void raw_send(const std::string& text);
}

#define CMD(TYPE, FMT, ...) \
    app::cmd::send(TYPE, util::format_message(FMT, __VA_ARGS__))

#define DBG(FMT, ...) \
    app::cmd::send("DBG", util::format_message(FMT, __VA_ARGS__))