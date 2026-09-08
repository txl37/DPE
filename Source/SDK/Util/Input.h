#pragma once
#include "Global.h" 

#undef min

enum eInputEnums
{
    VK_KEY_0 = 0x30,
    VK_KEY_1 = 0x31,
    VK_KEY_2 = 0x32,
    VK_KEY_3 = 0x33,
    VK_KEY_4 = 0x34,
    VK_KEY_5 = 0x35,
    VK_KEY_6 = 0x36,
    VK_KEY_7 = 0x37,
    VK_KEY_8 = 0x38,
    VK_KEY_9 = 0x39,

    VK_KEY_A = 0x41,
    VK_KEY_B = 0x42,
    VK_KEY_C = 0x43,
    VK_KEY_D = 0x44,
    VK_KEY_E = 0x45,
    VK_KEY_F = 0x46,
    VK_KEY_G = 0x47,
    VK_KEY_H = 0x48,
    VK_KEY_I = 0x49,
    VK_KEY_J = 0x4A,
    VK_KEY_K = 0x4B,
    VK_KEY_L = 0x4C,
    VK_KEY_M = 0x4D,
    VK_KEY_N = 0x4E,
    VK_KEY_O = 0x4F,
    VK_KEY_P = 0x50,
    VK_KEY_Q = 0x51,
    VK_KEY_R = 0x52,
    VK_KEY_S = 0x53,
    VK_KEY_T = 0x54,
    VK_KEY_U = 0x55,
    VK_KEY_V = 0x56,
    VK_KEY_W = 0x57,
    VK_KEY_X = 0x58,
    VK_KEY_Y = 0x59,
    VK_KEY_Z = 0x5A,
};

class Input;

namespace input
{
    bool is_key_pressed(const std::string& key_name, int initial_delay_ms = 200, float max_acceleration = 5.0f);

    bool is_key_pressed(int key_code, int initial_delay_ms = 200, float max_acceleration = 5.0f);

    int get_key_code_by_name(const std::string& name);

    std::string get_key_name_by_code(int key_code);
}

class Input
{
public:
    static Input& get()
    {
        static Input instance;
        return instance;
    }

    bool is_key_pressed_impl(int key_code, int initial_delay_ms, float max_acceleration);
    int get_key_code_by_name_impl(const std::string& name) const;
    std::string get_key_name_by_code_impl(int key_code) const;
private:
    struct KeyState
    {
        bool m_was_pressed = false;
        uint64_t m_first_press_time = 0;
        uint64_t m_next_allowed_press_time = 0;
        float m_acceleration = 1.0f;

        void reset()
        {
            m_was_pressed = false;
            m_first_press_time = 0;
            m_next_allowed_press_time = 0;
            m_acceleration = 1.0f;
        }
    };

    std::unordered_map<int, KeyState> m_key_states;
    std::mutex m_mutex;

    static const std::unordered_map<std::string, int> m_key_map;
    static const std::unordered_map<int, std::string> m_reverse_key_map;
};