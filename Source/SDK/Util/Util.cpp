#include "Global.h"
#include "Util.h"

namespace app::util
{
	std::filesystem::path get_path() 
    {
        std::array<char, MAX_PATH> path{};
        if (SHGetFolderPathA(nullptr, CSIDL_PERSONAL, nullptr, 0, path.data()) == S_OK) 
        {
            return std::filesystem::path(path.data()).append(APP);
        }
        else 
        {
            error_box("Failed to get documents path");
            return std::filesystem::path("");
        }
	}

    uint8_t char_to_byte(char c)
    {
        constexpr uint8_t offset_0 = '0';
        constexpr uint8_t offset_a = 'a' - 10;
        constexpr uint8_t offset_A = 'A' - 10;

        c |= 0x20; 

        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - offset_0);
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - offset_a);
        return 0;
    }

    std::optional<std::uint8_t> char_to_hex(const char c)
    {
        if (c >= 'a' && c <= 'f')
            return static_cast<std::uint8_t>(static_cast<std::uint32_t>(c) - 87);
        if (c >= 'A' && c <= 'F')
            return static_cast<std::uint8_t>(static_cast<std::uint32_t>(c) - 55);
        if (c >= '0' && c <= '9')
            return static_cast<std::uint8_t>(static_cast<std::uint32_t>(c) - 48);
        return {};
    }

    uint32_t joaat(const std::string& text)
    {
        uint32_t hash = 0;
        for (const char c : text)
        {
            hash += c;
            hash += (hash << 10);
            hash ^= (hash >> 6);
        }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);
        return hash;
    }

    void error_box(std::string error, std::string title)
    {
        MessageBoxA(nullptr, error.c_str(), title.c_str(), MB_OK);
    }

    std::string convert_to_title_case(const std::string& text) 
    {
        std::string result = text;
        bool capitalize_next = true;
        for (char& c : result)
        {
            if (std::isalpha(c)) 
            {
                c = capitalize_next ? std::toupper(c) : std::tolower(c);
                capitalize_next = false;
            }
            else
            {
                capitalize_next = true;
            }
        }
        return result;
    }

    std::string convert_to_small_case(const std::string& text)
    {
        std::string result = text;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return result;
    }

    std::string convert_to_caps(const std::string& text) 
    {
        std::string result = text;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return std::toupper(c); });
        return result;
    }

    std::string convert(const std::string& text,const eTextCase& text_case)
    {
        switch (text_case) {
        case eTextCase::Title:
            return convert_to_title_case(text);
        case eTextCase::Small:
            return convert_to_small_case(text);
        case eTextCase::Caps:
            return convert_to_caps(text);
        default:
            return text;
        }
    }

    std::string get_string_until(const std::string& str, const std::string& until, const eTextDirection& dir)
    {
        bool const is_fwd = (dir == eTextDirection::Forward);
        auto const pos = is_fwd ? str.find(until) : str.rfind(until);

        if (pos == std::string::npos) return std::string(str);

        return std::string(is_fwd ? str.substr(0, pos) : str.substr(pos + until.length()));
    }
}