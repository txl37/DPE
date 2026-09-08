#pragma once
#include "Global.h"

namespace app
{
	enum class eTextCase : uint8_t;
	enum class eTextDirection : uint8_t;
}

namespace app::util
{
	std::filesystem::path get_path();

	uint8_t char_to_byte(char c);
	std::optional<std::uint8_t> char_to_hex(const char c);

	void error_box(std::string error, std::string title = APP);

	std::string convert(const std::string& text, const eTextCase& text_case = static_cast<eTextCase>(0));

	uint32_t joaat(const std::string& str);


	template<typename T>
	concept Streamable = requires(std::ostringstream & os, T v) {
		{ os << v } -> std::convertible_to<std::ostream&>;
	};

	template<typename ReturnType = std::string, Streamable... Args>
	ReturnType combine_strings(Args&&... args) {
		std::ostringstream oss;
		(oss << ... << std::forward<Args>(args));

		if constexpr (std::is_same_v<ReturnType, std::string>) {
			return oss.str();
		}
		else if constexpr (std::is_same_v<ReturnType, const char*>) {
			static thread_local std::string result;
			result = oss.str();
			return result.c_str();
		}
	}
	
	template <typename... Args>
	std::string reverse_strings(Args&&... args) {
		std::string combined = combine_strings(std::forward<Args>(args)...);

		std::reverse(combined.begin(), combined.end());

		return combined;
	}

	std::string get_string_until(const std::string& string, const std::string& until,const eTextDirection& direction = static_cast<eTextDirection>(0));

	template <typename T>
	concept Callable = std::is_invocable_v<T>;

	template <typename callable>
	void do_timed(const std::string& id, DWORD delay, callable&& action)
	{
		static std::unordered_map<std::string, DWORD> m_next_execution_times;
		DWORD current_time = GetTickCount();

		if (m_next_execution_times.find(id) == m_next_execution_times.end() ||
			current_time >= m_next_execution_times[id]) {
			action();
			m_next_execution_times[id] = current_time + delay;
		}
	}

	template<typename... Args>
	inline std::string format_message(const std::string& message, const Args&... args)
	{
		return std::vformat(message, std::make_format_args(args...));
	} 

	inline void error(const std::string& message, const auto&... args)
	{
		std::string logMessage = format_message(message, args...);
		error_box(logMessage);
	}

	template <typename T>
	inline void* get_virtual_function(T ptr, uint64_t index)
	{
		void** virtual_functions{ *reinterpret_cast<void***>(ptr) };
		return virtual_functions[index];
	}

	template <typename T, typename... Rest>
	bool equal(const T& first, const Rest&... rest)
	{
		const std::string base = util::convert(std::string(first), eTextCase::Small);

		return ((base == util::convert(std::string(rest), eTextCase::Small)) && ...);
	}

	template <typename T, typename... Rest>
	bool equal_case(const T& first, const Rest&... rest)
	{
		std::string base{ first };
		return ((base == std::string{ rest }) && ...);
	} 

	// ughh should work with diff types aslong they are can be converted to strings  
}

#define CONCAT_IMPL(a, b) a##b
#define CONCAT(a, b) CONCAT_IMPL(a, b)

#define call_once(block)                                \
    do {                                                 \
        static std::once_flag CONCAT(_once_flag_, __LINE__); \
        std::call_once(CONCAT(_once_flag_, __LINE__), block); \
    } while (0)

