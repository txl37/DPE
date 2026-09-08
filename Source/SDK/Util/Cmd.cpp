#include "Global.h"
#undef min

namespace app
{
	std::string get_current_time()
	{
		std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
		std::time_t now_c = std::chrono::system_clock::to_time_t(now);

		tm now_tm{};
		if (localtime_s(&now_tm, &now_c) == 0) {
			return std::format("{:02}:{:02}:{:02}", now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec);
		}

		return "Error retrieving time";
	}

	std::string get_time()
	{
		auto const current_time = std::chrono::system_clock::now();
		auto const time = std::chrono::system_clock::to_time_t(current_time);

		tm local_time{};

		if (localtime_s(&local_time, &time) == 0) {
			return std::format("{:0>2}-{:0>2}-{}-{:0>2}-{:0>2}-{:0>2}",
				local_time.tm_mon + 1, local_time.tm_mday, local_time.tm_year + 1900,
				local_time.tm_hour, local_time.tm_min, local_time.tm_sec
			);
		}

		return "Error retrieving time";
	}

	namespace cmd
	{
		namespace detail
		{
			std::string colorize(const std::string& text, const Color& col)
			{
				return std::format("\033[38;2;{};{};{}m{}\033[0m", col.r, col.g, col.b, text);
			}

			std::string colorize(const char c, const Color& col)
			{
				return std::format("\033[38;2;{};{};{}m{}\033[0m", col.r, col.g, col.b, c);
			}
		}

		void setup_folder()
		{
			static auto& Cmd{ Cmd::get() };

			if (!std::filesystem::exists(Cmd.m_log_path))
			{
				std::filesystem::create_directories(Cmd.m_log_path);
			}

			Cmd.m_log_path /= std::filesystem::path(std::format("{}.txt", get_time()));
		}

		void sub_header(std::string text) 
		{
			Cmd::get().m_console_out << std::format("{}+{} {}", detail::colorize("[", 0x6c98ff), detail::colorize("]", 0x6c98ff), text) << std::endl;
		}

		void setup_console(const std::string& name)
		{
			static auto& Cmd{ Cmd::get() };

			if (AllocConsole())
			{
				if (Cmd.m_console_handle = GetStdHandle(STD_OUTPUT_HANDLE); Cmd.m_console_handle != nullptr)
				{
					SetConsoleTitleA(name.data());
					SetConsoleOutputCP(CP_UTF8);

					DWORD console_mode{};
					if (GetConsoleMode(Cmd.m_console_handle, &console_mode))
					{
						Cmd.m_original_console_mode = console_mode;

						console_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN | ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
						console_mode &= ~(ENABLE_QUICK_EDIT_MODE);

						if (!SetConsoleMode(Cmd.m_console_handle, console_mode))
						{
							util::error("Failed to set console mode\n {}", GetLastError());
						}
					}
				}
			}
			else
				util::error("Failed to allocate console \n {}", GetLastError());
		}

		void create(const std::string& name)
		{
			static auto& Cmd{ Cmd::get() };

			Cmd.m_log_path = util::get_path().append("Logs");
			Cmd.m_console_handle = nullptr;
			Cmd.m_original_console_mode = 0;

			setup_folder();
			setup_console(name);
			Cmd.m_console_out.open("CONOUT$", std::ios_base::out | std::ios_base::app);

			if (!Cmd.m_console_out.is_open())
				util::error("Failed to open console output stream");

			Cmd.m_file_out.open(Cmd.m_log_path, std::ios_base::out | std::ios_base::app);

			if (!Cmd.m_file_out.is_open())
				util::error("Failed to open log file output stream");

			Sleep(100);
		}

		void destroy()
		{
			static auto& Cmd{ Cmd::get() };

			if (Cmd.m_file_out.is_open())
				Cmd.m_file_out.close();

			if (Cmd.m_console_out.is_open())
				Cmd.m_console_out.close();

			if (Cmd.m_console_handle)
			{
				SetConsoleMode(Cmd.m_console_handle, Cmd.m_original_console_mode);
				FreeConsole();
			}
		}

		void send(const std::string& title, const std::string& message)
		{
			static auto& Cmd{ Cmd::get() };

			Color theme(0xffffff, 1.f);

			if (util::equal(title, "Error"))
				theme = Color(0xff0000, 1.f);
			if (util::equal(title, "Warning"))
				theme = Color(0xffA500, 1.f);
			if (util::equal(title, "Registers"))
				theme = Color(0xff0000, 1.f);

			static const Color& purple = Color(0x6065eb);
			static const Color& blue = Color(0x6c98ff);
			static const Color& white = Color(0xffffff);

			Cmd.m_file_out << "[" << get_current_time() << "] | [" << util::convert(title) << "] > " << message << std::endl;

			Cmd.m_console_out <<
				detail::colorize("[", purple) <<
				detail::colorize(get_current_time(), white) <<
				detail::colorize("] ", purple) <<
				detail::colorize("| ", blue) <<
				detail::colorize("[", purple) <<
				detail::colorize(util::convert(title, eTextCase::Caps), theme) <<
				detail::colorize("]", purple) <<
				detail::colorize(" > ", blue) <<
				detail::colorize(message, theme) <<
				std::endl;
		}

		void raw_send(const std::string& text)
		{
			Cmd::get().m_console_out << text << std::endl;
			Cmd::get().m_file_out << text << std::endl;
		}
	}
}