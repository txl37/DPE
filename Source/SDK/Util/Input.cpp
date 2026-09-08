#include "Global.h"
#include "Input.h"

const std::unordered_map<std::string, int> Input::m_key_map =
{
    {"a", VK_KEY_A}, {"b", VK_KEY_B}, {"c", VK_KEY_C}, {"d", VK_KEY_D},
    {"e", VK_KEY_E}, {"f", VK_KEY_F}, {"g", VK_KEY_G}, {"h", VK_KEY_H},
    {"i", VK_KEY_I}, {"j", VK_KEY_J}, {"k", VK_KEY_K}, {"l", VK_KEY_L},
    {"m", VK_KEY_M}, {"n", VK_KEY_N}, {"o", VK_KEY_O}, {"p", VK_KEY_P},
    {"q", VK_KEY_Q}, {"r", VK_KEY_R}, {"s", VK_KEY_S}, {"t", VK_KEY_T},
    {"u", VK_KEY_U}, {"v", VK_KEY_V}, {"w", VK_KEY_W}, {"x", VK_KEY_X},
    {"y", VK_KEY_Y}, {"z", VK_KEY_Z},

    {"0", VK_KEY_0}, {"1", VK_KEY_1}, {"2", VK_KEY_2}, {"3", VK_KEY_3}, {"4", VK_KEY_4},
    {"5", VK_KEY_5}, {"6", VK_KEY_6}, {"7", VK_KEY_7}, {"8", VK_KEY_8}, {"9", VK_KEY_9},

    {"up", VK_UP}, {"down", VK_DOWN}, {"left", VK_LEFT}, {"right", VK_RIGHT},
    {"enter", VK_RETURN}, {"back", VK_BACK}, {"space", VK_SPACE}, {"tab", VK_TAB},
    {"esc", VK_ESCAPE}, {"insert", VK_INSERT}, {"delete", VK_DELETE},
    {"home", VK_HOME}, {"end", VK_END}, {"pageup", VK_PRIOR}, {"pagedown", VK_NEXT},

    {"f1", VK_F1}, {"f2", VK_F2}, {"f3", VK_F3}, {"f4", VK_F4},
    {"f5", VK_F5}, {"f6", VK_F6}, {"f7", VK_F7}, {"f8", VK_F8},
    {"f9", VK_F9}, {"f10", VK_F10}, {"f11", VK_F11}, {"f12", VK_F12},

    {"shift", VK_SHIFT}, {"ctrl", VK_CONTROL}, {"alt", VK_MENU},
    {"capslock", VK_CAPITAL}, {"numlock", VK_NUMLOCK}, {"scrolllock", VK_SCROLL},
    {"pause", VK_PAUSE},

    {"plus", VK_ADD}, {"minus", VK_SUBTRACT}, {"multiply", VK_MULTIPLY},
    {"divide", VK_DIVIDE}, {"decimal", VK_DECIMAL},

    {"mouseleft", VK_LBUTTON}, {"mouseright", VK_RBUTTON},
    {"mousebutton4", VK_XBUTTON1}, {"mousebutton5", VK_XBUTTON2}
};

const std::unordered_map<int, std::string> Input::m_reverse_key_map = []() 
{
    std::unordered_map<int, std::string> result;
    for (const auto& pair : Input::m_key_map) {
        result[pair.second] = pair.first;
    }
    return result;
}();

bool Input::is_key_pressed_impl(int key_code, int initial_delay_ms, float max_acceleration) {
    if (key_code == 0) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    KeyState& key_state = m_key_states[key_code];
    uint64_t current_time = GetTickCount64();

    bool is_physical_key_down = (GetAsyncKeyState(key_code) & 0x8000) != 0;

    if (!key_state.m_was_pressed && is_physical_key_down) 
    {
        key_state.m_was_pressed = true;
        key_state.m_first_press_time = current_time;
        key_state.m_next_allowed_press_time = current_time + initial_delay_ms;
        key_state.m_acceleration = 1.0f;
        return true;
    }

    if (!is_physical_key_down) {
        if (key_state.m_was_pressed) {
            key_state.reset();
        }
        return false;
    }

    if (current_time < key_state.m_next_allowed_press_time) {
        return false;
    }

    uint64_t hold_time = current_time - key_state.m_first_press_time;

    float accel_factor = 1.0f + (static_cast<float>(hold_time) / 500.0f);
    key_state.m_acceleration = std::min(accel_factor, max_acceleration);

    int adjusted_delay = static_cast<int>(static_cast<float>(initial_delay_ms) / key_state.m_acceleration);
    key_state.m_next_allowed_press_time = current_time + adjusted_delay;

    return true;
}

int Input::get_key_code_by_name_impl(const std::string& name) const 
{
    auto it = m_key_map.find(name);
    return (it != m_key_map.end()) ? it->second : 0;
}

std::string Input::get_key_name_by_code_impl(int key_code) const 
{
    auto it = m_reverse_key_map.find(key_code);
    return (it != m_reverse_key_map.end()) ? it->second : "";
}

namespace input
{
    bool is_key_pressed(const std::string& key_name, int initial_delay_ms, float max_acceleration)
    {
        int code = Input::get().get_key_code_by_name_impl(key_name);
        return Input::get().is_key_pressed_impl(code, initial_delay_ms, max_acceleration);
    }

    bool is_key_pressed(int key_code, int initial_delay_ms, float max_acceleration) 
    {
        return Input::get().is_key_pressed_impl(key_code, initial_delay_ms, max_acceleration);
    }

    int get_key_code_by_name(const std::string& name) 
    {
        return Input::get().get_key_code_by_name_impl(name);
    }

    std::string get_key_name_by_code(int key_code) 
    {
        return Input::get().get_key_name_by_code_impl(key_code);
    }
}