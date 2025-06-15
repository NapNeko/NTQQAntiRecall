#pragma once
#include <windows.h>
#include <functional>

// NAPI 基础类型定义
typedef struct napi_env__ *napi_env;
typedef struct napi_value__ *napi_value;
typedef struct napi_ref__ *napi_ref;
typedef struct napi_handle_scope__ *napi_handle_scope;
typedef struct napi_escapable_handle_scope__ *napi_escapable_handle_scope;
typedef struct napi_callback_info__ *napi_callback_info;
typedef struct napi_deferred__ *napi_deferred;

typedef enum
{
    napi_ok,
    napi_invalid_arg,
    napi_object_expected,
    napi_string_expected,
    napi_name_expected,
    napi_function_expected,
    napi_number_expected,
    napi_boolean_expected,
    napi_array_expected,
    napi_generic_failure,
    napi_pending_exception,
    napi_cancelled,
    napi_escape_called_twice,
    napi_handle_scope_mismatch,
    napi_callback_scope_mismatch,
    napi_queue_full,
    napi_closing,
    napi_bigint_expected,
    napi_date_expected,
    napi_arraybuffer_expected,
    napi_detachable_arraybuffer_expected,
    napi_would_deadlock
} napi_status;

typedef enum
{
    napi_undefined,
    napi_null,
    napi_boolean,
    napi_number,
    napi_string,
    napi_symbol,
    napi_object,
    napi_function,
    napi_external,
    napi_bigint,
} napi_valuetype;

typedef napi_value (*napi_callback)(napi_env env, napi_callback_info info);

// NAPI 函数指针类型定义
typedef napi_status (*napi_get_cb_info_t)(napi_env env, napi_callback_info info, size_t *argc, napi_value *argv, napi_value *this_arg, void **data);
typedef napi_status (*napi_get_global_t)(napi_env env, napi_value *result);
typedef napi_status (*napi_create_string_utf8_t)(napi_env env, const char *str, size_t length, napi_value *result);
typedef napi_status (*napi_create_object_t)(napi_env env, napi_value *result);
typedef napi_status (*napi_create_function_t)(napi_env env, const char *utf8name, size_t length, napi_callback cb, void *data, napi_value *result);
typedef napi_status (*napi_set_property_t)(napi_env env, napi_value object, napi_value key, napi_value value);
typedef napi_status (*napi_get_property_t)(napi_env env, napi_value object, napi_value key, napi_value *result);
typedef napi_status (*napi_has_property_t)(napi_env env, napi_value object, napi_value key, bool *result);
typedef napi_status (*napi_delete_property_t)(napi_env env, napi_value object, napi_value key, bool *result);
typedef napi_status (*napi_get_property_names_t)(napi_env env, napi_value object, napi_value *result);
typedef napi_status (*napi_set_named_property_t)(napi_env env, napi_value object, const char *utf8name, napi_value value);
typedef napi_status (*napi_get_named_property_t)(napi_env env, napi_value object, const char *utf8name, napi_value *result);
typedef napi_status (*napi_has_named_property_t)(napi_env env, napi_value object, const char *utf8name, bool *result);
typedef napi_status (*napi_call_function_t)(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv, napi_value *result);
typedef napi_status (*napi_create_array_t)(napi_env env, napi_value *result);
typedef napi_status (*napi_create_array_with_length_t)(napi_env env, size_t length, napi_value *result);
typedef napi_status (*napi_get_array_length_t)(napi_env env, napi_value value, uint32_t *result);
typedef napi_status (*napi_get_element_t)(napi_env env, napi_value object, uint32_t index, napi_value *result);
typedef napi_status (*napi_set_element_t)(napi_env env, napi_value object, uint32_t index, napi_value value);
typedef napi_status (*napi_typeof_t)(napi_env env, napi_value value, napi_valuetype *result);
typedef napi_status (*napi_get_value_bool_t)(napi_env env, napi_value value, bool *result);
typedef napi_status (*napi_get_value_double_t)(napi_env env, napi_value value, double *result);
typedef napi_status (*napi_get_value_int32_t)(napi_env env, napi_value value, int32_t *result);
typedef napi_status (*napi_get_value_uint32_t)(napi_env env, napi_value value, uint32_t *result);
typedef napi_status (*napi_get_value_int64_t)(napi_env env, napi_value value, int64_t *result);
typedef napi_status (*napi_get_value_string_utf8_t)(napi_env env, napi_value value, char *buf, size_t bufsize, size_t *result);
typedef napi_status (*napi_create_int32_t)(napi_env env, int32_t value, napi_value *result);
typedef napi_status (*napi_create_uint32_t)(napi_env env, uint32_t value, napi_value *result);
typedef napi_status (*napi_create_int64_t)(napi_env env, int64_t value, napi_value *result);
typedef napi_status (*napi_create_double_t)(napi_env env, double value, napi_value *result);
typedef napi_status (*napi_create_boolean_t)(napi_env env, bool value, napi_value *result);
typedef napi_status (*napi_get_null_t)(napi_env env, napi_value *result);
typedef napi_status (*napi_get_undefined_t)(napi_env env, napi_value *result);

// QQNT NAPI 延迟加载器类
class QQNTNAPILoader
{
private:
    HMODULE m_hModule;
    bool m_bInitialized;

public:
    // NAPI 函数指针
    napi_get_cb_info_t napi_get_cb_info;
    napi_get_global_t napi_get_global;
    napi_create_string_utf8_t napi_create_string_utf8;
    napi_create_object_t napi_create_object;
    napi_create_function_t napi_create_function;
    napi_set_property_t napi_set_property;
    napi_get_property_t napi_get_property;
    napi_has_property_t napi_has_property;
    napi_delete_property_t napi_delete_property;
    napi_get_property_names_t napi_get_property_names;
    napi_set_named_property_t napi_set_named_property;
    napi_get_named_property_t napi_get_named_property;
    napi_has_named_property_t napi_has_named_property;
    napi_call_function_t napi_call_function;
    napi_create_array_t napi_create_array;
    napi_create_array_with_length_t napi_create_array_with_length;
    napi_get_array_length_t napi_get_array_length;
    napi_get_element_t napi_get_element;
    napi_set_element_t napi_set_element;
    napi_typeof_t napi_typeof;
    napi_get_value_bool_t napi_get_value_bool;
    napi_get_value_double_t napi_get_value_double;
    napi_get_value_int32_t napi_get_value_int32;
    napi_get_value_uint32_t napi_get_value_uint32;
    napi_get_value_int64_t napi_get_value_int64;
    napi_get_value_string_utf8_t napi_get_value_string_utf8;
    napi_create_int32_t napi_create_int32;
    napi_create_uint32_t napi_create_uint32;
    napi_create_int64_t napi_create_int64;
    napi_create_double_t napi_create_double;
    napi_create_boolean_t napi_create_boolean;
    napi_get_null_t napi_get_null;
    napi_get_undefined_t napi_get_undefined;

    QQNTNAPILoader() : m_hModule(nullptr), m_bInitialized(false)
    {
        // 初始化所有函数指针为 nullptr
        memset(&napi_get_global, 0, sizeof(QQNTNAPILoader) - offsetof(QQNTNAPILoader, napi_get_global));
    }

    ~QQNTNAPILoader()
    {
        // 不释放模块句柄，因为是延迟获取已加载的 DLL
    }

    bool Initialize()
    {
        if (m_bInitialized)
        {
            return true;
        }

        // 尝试获取已加载的 qqnt.dll
        m_hModule = ::GetModuleHandleA("qqnt.dll");
        if (!m_hModule)
        {
            // 如果没有找到，尝试其他可能的名称
            const char *possibleNames[] = {
                "node.dll",
                "libnode.dll",
                "QQ.exe",
                nullptr};

            for (int i = 0; possibleNames[i]; i++)
            {
                m_hModule = ::GetModuleHandleA(possibleNames[i]);
                if (m_hModule)
                {
                    break;
                }
            }
        }

        if (!m_hModule)
        {
            return false;
        }

        // 加载 NAPI 函数
        bool success =
            LoadFunction("napi_get_cb_info", (void **)&napi_get_cb_info) &&
            LoadFunction("napi_get_global", (void **)&napi_get_global) &&
            LoadFunction("napi_create_string_utf8", (void **)&napi_create_string_utf8) &&
            LoadFunction("napi_create_object", (void **)&napi_create_object) &&
            LoadFunction("napi_create_function", (void **)&napi_create_function) &&
            LoadFunction("napi_set_property", (void **)&napi_set_property) &&
            LoadFunction("napi_get_property", (void **)&napi_get_property) &&
            LoadFunction("napi_has_property", (void **)&napi_has_property) &&
            LoadFunction("napi_delete_property", (void **)&napi_delete_property) &&
            LoadFunction("napi_get_property_names", (void **)&napi_get_property_names) &&
            LoadFunction("napi_set_named_property", (void **)&napi_set_named_property) &&
            LoadFunction("napi_get_named_property", (void **)&napi_get_named_property) &&
            LoadFunction("napi_has_named_property", (void **)&napi_has_named_property) &&
            LoadFunction("napi_call_function", (void **)&napi_call_function) &&
            LoadFunction("napi_create_array", (void **)&napi_create_array) &&
            LoadFunction("napi_create_array_with_length", (void **)&napi_create_array_with_length) &&
            LoadFunction("napi_get_array_length", (void **)&napi_get_array_length) &&
            LoadFunction("napi_get_element", (void **)&napi_get_element) &&
            LoadFunction("napi_set_element", (void **)&napi_set_element) &&
            LoadFunction("napi_typeof", (void **)&napi_typeof) &&
            LoadFunction("napi_get_value_bool", (void **)&napi_get_value_bool) &&
            LoadFunction("napi_get_value_double", (void **)&napi_get_value_double) &&
            LoadFunction("napi_get_value_int32", (void **)&napi_get_value_int32) &&
            LoadFunction("napi_get_value_uint32", (void **)&napi_get_value_uint32) &&
            LoadFunction("napi_get_value_int64", (void **)&napi_get_value_int64) &&
            LoadFunction("napi_get_value_string_utf8", (void **)&napi_get_value_string_utf8) &&
            LoadFunction("napi_create_int32", (void **)&napi_create_int32) &&
            LoadFunction("napi_create_uint32", (void **)&napi_create_uint32) &&
            LoadFunction("napi_create_int64", (void **)&napi_create_int64) &&
            LoadFunction("napi_create_double", (void **)&napi_create_double) &&
            LoadFunction("napi_create_boolean", (void **)&napi_create_boolean) &&
            LoadFunction("napi_get_null", (void **)&napi_get_null) &&
            LoadFunction("napi_get_undefined", (void **)&napi_get_undefined);

        m_bInitialized = success;
        return success;
    }

    bool IsInitialized() const
    {
        return m_bInitialized;
    }

    HMODULE GetModuleHandle() const
    {
        return m_hModule;
    }

private:
    bool LoadFunction(const char *functionName, void **functionPtr)
    {
        if (!m_hModule)
        {
            return false;
        }

        *functionPtr = GetProcAddress(m_hModule, functionName);
        return (*functionPtr != nullptr);
    }
};

// 全局实例
extern QQNTNAPILoader g_QQNTNAPILoader;

// 便利宏定义
#define ENSURE_NAPI_LOADED()                    \
    do                                          \
    {                                           \
        if (!g_QQNTNAPILoader.IsInitialized())  \
        {                                       \
            if (!g_QQNTNAPILoader.Initialize()) \
            {                                   \
                return napi_generic_failure;    \
            }                                   \
        }                                       \
    } while (0)

// 安全调用宏
#define SAFE_NAPI_CALL(func, ...) \
    (g_QQNTNAPILoader.func ? g_QQNTNAPILoader.func(__VA_ARGS__) : napi_generic_failure)