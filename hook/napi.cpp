#include "napi.h"
#include <tlhelp32.h>

// 全局实例定义
QQNTNAPILoader g_QQNTNAPILoader;

// 延迟加载 QQNT DLL 的辅助函数
class QQNTDLLFinder {
public:
    static HMODULE FindQQNTModule() {
        // 尝试多种可能的模块名称
        const char* moduleNames[] = {
            "qqnt.dll",
            "node.dll", 
            "libnode.dll",
            "napi.dll",
            nullptr
        };

        for (int i = 0; moduleNames[i]; i++) {
            HMODULE hMod = GetModuleHandleA(moduleNames[i]);
            if (hMod && HasNAPIExports(hMod)) {
                return hMod;
            }
        }

        // 如果找不到，尝试枚举所有加载的模块
        return FindModuleWithNAPI();
    }

private:
    static bool HasNAPIExports(HMODULE hModule) {
        // 检查是否包含关键的 NAPI 导出函数
        return GetProcAddress(hModule, "napi_get_global") != nullptr &&
               GetProcAddress(hModule, "napi_create_object") != nullptr;
    }

    static HMODULE FindModuleWithNAPI() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return nullptr;
        }

        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &me32)) {
            do {
                if (HasNAPIExports(me32.hModule)) {
                    CloseHandle(hSnapshot);
                    return me32.hModule;
                }
            } while (Module32Next(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        return nullptr;
    }
};

// 延迟初始化函数
bool InitializeQQNTNAPI() {
    static bool initialized = false;
    static bool initResult = false;

    if (!initialized) {
        initResult = g_QQNTNAPILoader.Initialize();
        initialized = true;
    }

    return initResult;
}

// 获取 QQNT 模块句柄
HMODULE GetQQNTModuleHandle() {
    if (!InitializeQQNTNAPI()) {
        return nullptr;
    }
    return g_QQNTNAPILoader.GetModuleHandle();
}

// 安全的 NAPI 函数调用包装器
namespace SafeNAPI {
    napi_status GetGlobal(napi_env env, napi_value* result) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_get_global, env, result);
    }

    napi_status CreateStringUtf8(napi_env env, const char* str, size_t length, napi_value* result) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_create_string_utf8, env, str, length, result);
    }

    napi_status CreateObject(napi_env env, napi_value* result) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_create_object, env, result);
    }

    napi_status CallFunction(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value* argv, napi_value* result) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_call_function, env, recv, func, argc, argv, result);
    }

    napi_status GetNamedProperty(napi_env env, napi_value object, const char* utf8name, napi_value* result) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_get_named_property, env, object, utf8name, result);
    }

    napi_status SetNamedProperty(napi_env env, napi_value object, const char* utf8name, napi_value value) {
        ENSURE_NAPI_LOADED();
        return SAFE_NAPI_CALL(napi_set_named_property, env, object, utf8name, value);
    }
}