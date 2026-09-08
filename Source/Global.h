#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#include <immintrin.h>
#include <intrin.h> 
#include <Psapi.h>
#include <wtypes.h>
#include <d3d11.h>
#include <wrl/client.h>
#include <d3dcompiler.h>
#include <chrono>
#include <concepts>
#include <format>
#include <memory>
#include <optional>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <cstdint>
#include <type_traits>
#include <string>
#include <filesystem>
#include <ranges>
#include <span>
#include <functional> 
#include <stdexcept> 
#include <mutex>
#include <deque>
#include <iostream>
#include <unordered_set>
#include <fstream>
#include <map>
#include <array>
#include <vector>
#include <algorithm>
#include <typeindex>
#define APP "DPE POC"
#include "SDK/Types.h"
#include "SDK/Util/Util.h"
#include "SDK/Util/Cmd.h"
#include "SDK/Util/Input.h"
#include "SDK/Fibers/Fiber.h"
#include "SDK/Fibers/Manager.h"
#include "SDK/Fibers/Queue.h"

namespace app
{

}

using namespace std::chrono_literals;
