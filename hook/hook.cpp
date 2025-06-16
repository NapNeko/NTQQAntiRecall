#include <Windows.h>
#include <vector>
#include <psapi.h>
#include <string>
#include <atlstr.h>
#include <iostream>
#include <map>
#include <memory>
#include <algorithm>
#include "funchook.h"
#include "helper.h"
#include "ServiceScan.h"
#include "HookJump.h"
#include "HookHelper.h"

// NAPI类型定义和常量
typedef void *napi_env;
typedef void *napi_value;
typedef void *napi_callback_info;
typedef void *napi_ref;
typedef void *napi_threadsafe_function;
typedef void *napi_callback;

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
    napi_tsfn_release,
    napi_tsfn_abort
} napi_threadsafe_function_release_mode;

typedef enum
{
    napi_tsfn_nonblocking,
    napi_tsfn_blocking
} napi_threadsafe_function_call_mode;

typedef void (*napi_finalize)(napi_env env, void *finalize_data, void *finalize_hint);
typedef void (*napi_threadsafe_function_call_js)(napi_env env, napi_value js_callback, void *context, void *data);
typedef __int64(__fastcall *grp_recall_listener_func)(
    _int64 a1,
    unsigned int a2,
    int a3,
    int a4,
    __int64 a5,
    char *Str,
    __int64 a7,
    __int64 a8,
    __int64 a9,
    __int64 a10,
    __int64 a11,
    __int64 a12,
    __int64 a13,
    __int64 a14,
    char a15,
    char a16);

#define NAPI_AUTO_LENGTH SIZE_MAX

// QQNT Windows 35341 关键RVA地址
DWORD add_local_gray_tip_rva = 0x0;
DWORD add_msg_listener_rva = 0x0;

// 全局变量
napi_threadsafe_function tsfn_ptr = nullptr;
napi_ref msgService_Js_This_Ref = nullptr;
HMODULE g_wrapperModule = nullptr;
HMODULE g_qqntModule = nullptr;
grp_recall_listener_func original_grp_recall_listener = nullptr;

// NAPI函数指针定义
typedef napi_status (*napi_create_threadsafe_function_func)(
    napi_env env, napi_value func, napi_value async_resource,
    napi_value async_resource_name, size_t max_queue_size,
    size_t initial_thread_count, void *thread_finalize_data,
    napi_finalize thread_finalize_cb, void *context,
    napi_threadsafe_function_call_js call_js_cb,
    napi_threadsafe_function *result);

typedef napi_status (*napi_call_threadsafe_function_func)(
    napi_threadsafe_function tsfn, void *data, napi_threadsafe_function_call_mode mode);

typedef napi_status (*napi_get_cb_info_func)(
    napi_env env, napi_callback_info info, size_t *argc,
    napi_value *argv, napi_value *thisArg, void **data);

typedef napi_status (*napi_create_object_func)(napi_env env, napi_value *result);
typedef napi_status (*napi_create_string_utf8_func)(napi_env env, const char *str, size_t length, napi_value *result);
typedef napi_status (*napi_create_int32_func)(napi_env env, int32_t value, napi_value *result);
typedef napi_status (*napi_set_named_property_func)(napi_env env, napi_value object, const char *utf8name, napi_value value);
typedef napi_status (*napi_get_boolean_func)(napi_env env, bool value, napi_value *result);
typedef napi_status (*napi_call_function_func)(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv, napi_value *result);
typedef napi_status (*napi_create_function_func)(napi_env env, const char *utf8name, size_t length, napi_callback cb, void *data, napi_value *result);
typedef napi_status (*napi_get_named_property_func)(napi_env env, napi_value object, const char *utf8name, napi_value *result);
typedef napi_status (*napi_create_reference_func)(napi_env env, napi_value value, uint32_t initial_refcount, napi_ref *result);
typedef napi_status (*napi_get_reference_value_func)(napi_env env, napi_ref ref, napi_value *result);
typedef napi_status (*napi_get_global_func)(napi_env env, napi_value *result);
typedef napi_status (*napi_get_value_string_utf8_func)(napi_env env, napi_value value, char *buf, size_t bufsize, size_t *result);

// NAPI函数指针实例
napi_create_threadsafe_function_func napi_create_threadsafe_function_ptr = nullptr;
napi_call_threadsafe_function_func napi_call_threadsafe_function_ptr = nullptr;
napi_get_cb_info_func napi_get_cb_info_ptr = nullptr;
napi_create_object_func napi_create_object_ptr = nullptr;
napi_create_string_utf8_func napi_create_string_utf8_ptr = nullptr;
napi_create_int32_func napi_create_int32_ptr = nullptr;
napi_set_named_property_func napi_set_named_property_ptr = nullptr;
napi_get_boolean_func napi_get_boolean_ptr = nullptr;
napi_call_function_func napi_call_function_ptr = nullptr;
napi_create_function_func napi_create_function_ptr = nullptr;
napi_get_named_property_func napi_get_named_property_ptr = nullptr;
napi_create_reference_func napi_create_reference_ptr = nullptr;
napi_get_reference_value_func napi_get_reference_value_ptr = nullptr;
napi_get_global_func napi_get_global_ptr = nullptr;
napi_get_value_string_utf8_func napi_get_value_string_utf8_ptr = nullptr;

// 原始函数指针
typedef void *(*add_msg_listener_func)(void *, void *, void *, void *);
add_msg_listener_func original_add_msg_listener = nullptr;

typedef void *(*recall_grp_func)(void *, void *, void *, void *, void *, void *, void *, void *);
recall_grp_func original_recall_grp = nullptr;

// 结构体定义
struct CallbackData
{
    std::string peerUid;
    std::string tipText;
};

// 获取栈指针的辅助函数 - 使用更安全的方式
void *GetCurrentStackPointer()
{
    void *stackPtr = nullptr;
#ifdef _M_X64
    // 64位版本
    stackPtr = _AddressOfReturnAddress();
#elif defined(_M_IX86)
    // 32位版本
    __asm {
        mov stackPtr, esp
    }
#endif
    return stackPtr;
}
// 初始化NAPI函数指针
bool InitializeNAPIFunctions()
{
    g_qqntModule = GetModuleHandleW(L"qqnt.dll");
    if (!g_qqntModule)
    {
        std::wcout << L"[!] qqnt.dll not found" << std::endl;
        return false;
    }

    napi_create_threadsafe_function_ptr = (napi_create_threadsafe_function_func)GetProcAddress(g_qqntModule, "napi_create_threadsafe_function");
    napi_call_threadsafe_function_ptr = (napi_call_threadsafe_function_func)GetProcAddress(g_qqntModule, "napi_call_threadsafe_function");
    napi_get_cb_info_ptr = (napi_get_cb_info_func)GetProcAddress(g_qqntModule, "napi_get_cb_info");
    napi_create_object_ptr = (napi_create_object_func)GetProcAddress(g_qqntModule, "napi_create_object");
    napi_create_string_utf8_ptr = (napi_create_string_utf8_func)GetProcAddress(g_qqntModule, "napi_create_string_utf8");
    napi_create_int32_ptr = (napi_create_int32_func)GetProcAddress(g_qqntModule, "napi_create_int32");
    napi_set_named_property_ptr = (napi_set_named_property_func)GetProcAddress(g_qqntModule, "napi_set_named_property");
    napi_get_boolean_ptr = (napi_get_boolean_func)GetProcAddress(g_qqntModule, "napi_get_boolean");
    napi_call_function_ptr = (napi_call_function_func)GetProcAddress(g_qqntModule, "napi_call_function");
    napi_create_function_ptr = (napi_create_function_func)GetProcAddress(g_qqntModule, "napi_create_function");
    napi_get_named_property_ptr = (napi_get_named_property_func)GetProcAddress(g_qqntModule, "napi_get_named_property");
    napi_create_reference_ptr = (napi_create_reference_func)GetProcAddress(g_qqntModule, "napi_create_reference");
    napi_get_reference_value_ptr = (napi_get_reference_value_func)GetProcAddress(g_qqntModule, "napi_get_reference_value");
    napi_get_global_ptr = (napi_get_global_func)GetProcAddress(g_qqntModule, "napi_get_global");
    napi_get_value_string_utf8_ptr = (napi_get_value_string_utf8_func)GetProcAddress(g_qqntModule, "napi_get_value_string_utf8");

    return napi_create_threadsafe_function_ptr && napi_call_threadsafe_function_ptr &&
           napi_get_cb_info_ptr && napi_create_object_ptr && napi_create_string_utf8_ptr;
}

// 调用添加灰色提示
void CallAddGrayTip(const std::string &peerUid, const std::string &tipText)
{
    if (!tsfn_ptr)
    {
        std::wcout << L"[!] tsfn_ptr is null" << std::endl;
        return;
    }

    // 创建回调数据
    CallbackData *data = new CallbackData();
    data->peerUid = peerUid;
    data->tipText = tipText;

    napi_status status = napi_call_threadsafe_function_ptr(tsfn_ptr, data, napi_tsfn_blocking);
    if (status != napi_ok)
    {
    }
}

// 线程安全函数JS回调
void ThreadSafeFunctionCallback(napi_env env, napi_value js_callback, void *context, void *data)
{
    std::wcout << L"[+] ThreadSafeFunctionCallback called" << std::endl;

    CallbackData *callbackData = static_cast<CallbackData *>(data);
    std::string groupId = "819085771";
    std::string tip_text = "Frida Hook QQNT By NapCat";

    if (callbackData)
    {
        groupId = callbackData->peerUid;
        tip_text = callbackData->tipText;
    }

    // 创建第一个对象参数 (peer info)
    napi_value obj1;
    napi_create_object_ptr(env, &obj1);

    // chatType: 2
    napi_value chatType;
    napi_create_int32_ptr(env, 2, &chatType);
    napi_set_named_property_ptr(env, obj1, "chatType", chatType);

    // guildId: ""
    napi_value guildId;
    napi_create_string_utf8_ptr(env, "", 0, &guildId);
    napi_set_named_property_ptr(env, obj1, "guildId", guildId);

    // peerUid: groupId
    napi_value peerUid;
    napi_create_string_utf8_ptr(env, groupId.c_str(), groupId.length(), &peerUid);
    napi_set_named_property_ptr(env, obj1, "peerUid", peerUid);

    // 创建第二个对象参数 (tip info)
    napi_value obj2;
    napi_create_object_ptr(env, &obj2);

    // busiId: 2201
    napi_value busiId;
    napi_create_int32_ptr(env, 2201, &busiId);
    napi_set_named_property_ptr(env, obj2, "busiId", busiId);

    // jsonStr
    std::string jsonStr = R"({"align":"center","items":[{"txt":")" + tip_text + R"(","type":"nor"}]})";
    napi_value jsonStrValue;
    napi_create_string_utf8_ptr(env, jsonStr.c_str(), jsonStr.length(), &jsonStrValue);
    napi_set_named_property_ptr(env, obj2, "jsonStr", jsonStrValue);

    // recentAbstract
    napi_value recentAbstract;
    napi_create_string_utf8_ptr(env, tip_text.c_str(), tip_text.length(), &recentAbstract);
    napi_set_named_property_ptr(env, obj2, "recentAbstract", recentAbstract);

    // isServer: false
    napi_value isServer;
    napi_get_boolean_ptr(env, false, &isServer);
    napi_set_named_property_ptr(env, obj2, "isServer", isServer);

    // 创建两个bool参数
    napi_value bool1, bool2;
    napi_get_boolean_ptr(env, true, &bool1);
    napi_get_boolean_ptr(env, true, &bool2);

    // 创建native函数
    napi_value native_func;
    void *native_func_addr = (void *)((UINT_PTR)g_wrapperModule + add_local_gray_tip_rva);
    napi_create_function_ptr(env, "nativeFunc", 10, (napi_callback)native_func_addr, nullptr, &native_func);

    // 获取this对象
    napi_value js_this;
    napi_get_reference_value_ptr(env, msgService_Js_This_Ref, &js_this);

    // 准备参数数组
    napi_value argv[4] = {obj1, obj2, bool1, bool2};

    // 调用函数
    napi_value result;
    napi_status call_status = napi_call_function_ptr(env, js_this, native_func, 4, argv, &result);

    std::wcout << L"[*] napi_call_function status: " << call_status << std::endl;
    delete callbackData;
}

// Hook消息监听器
void *HookedAddMsgListener(void *arg1, void *arg2, void *arg3, void *arg4)
{
    std::wcout << L"[+] HookedAddMsgListener called" << std::endl;

    napi_env env = (napi_env)arg1;
    napi_callback_info info = (napi_callback_info)arg2;

    // 获取this对象
    napi_value this_arg;
    napi_get_cb_info_ptr(env, info, nullptr, nullptr, &this_arg, nullptr);

    // 创建this对象的引用
    napi_status ref_status = napi_create_reference_ptr(env, this_arg, 1, &msgService_Js_This_Ref);
    if (ref_status == napi_ok)
    {
        std::wcout << L"[+] msgService_Js_This_Ref created successfully" << std::endl;
    }

    // 创建线程安全函数
    napi_value async_resource_name;
    napi_create_string_utf8_ptr(env, "frida_tsfn", NAPI_AUTO_LENGTH, &async_resource_name);

    napi_status status = napi_create_threadsafe_function_ptr(
        env,
        nullptr,                    // func: NULL
        nullptr,                    // async_resource
        async_resource_name,        // async_resource_name
        0,                          // max_queue_size
        1,                          // initial_thread_count
        nullptr,                    // thread_finalize_data
        nullptr,                    // thread_finalize_cb
        nullptr,                    // context
        ThreadSafeFunctionCallback, // call_js_cb
        &tsfn_ptr);

    if (status == napi_ok)
    {
        std::wcout << L"[+] Created ThreadSafeFunction successfully" << std::endl;
    }
    else
    {
        std::wcout << L"[!] napi_create_threadsafe_function failed: " << status << std::endl;
    }

    return original_add_msg_listener(arg1, arg2, arg3, arg4);
}

__int64 __fastcall HookedGrpRecallListener(
    _int64 a1,
    unsigned int a2,
    int a3,
    int a4,
    __int64 a5,
    char *Str,
    __int64 a7,
    __int64 a8,
    __int64 rd,
    __int64 seq,
    __int64 a11,
    __int64 a12,
    __int64 a13,
    __int64 a14,
    char a15,
    char a16)
{
    std::wcout << L"[+] HookedGrpRecallListener called" << std::endl;
    // 调用原始函数
    // 打印a8偏移0x1
    char *peer = (char *)((uintptr_t)a8 + 0x1);
    // a9
    std::cout << "[Debug] Str: " << peer << std::endl;
    UINT64 seq_value = (UINT64)seq;
    std::cout << "[Debug] seq: " << seq_value << std::endl;
    if (tsfn_ptr)
    {
        std::string tip_text = "Sequence: " + std::to_string(seq_value) + " has been recalled";
        CallAddGrayTip(peer, tip_text);
    }
    // return original_grp_recall_listener(a1, a2, a3, a4, a5, Str, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16);
    return 0;
}
// Hook群组撤回函数
// void RecallGroupHookCallback(uint64_t rbp)
// {
//     std::wcout << L"[+] Group Recall detected" << std::endl;

//     std::string peer = "819085771"; // 默认值
//     uint64_t seq = 12345;           // 默认值

//     try
//     {
//         // 根据JS代码：从 rbp+0x30+0x1 读取 peer
//         const uint64_t peer_str_addr = rbp + 0x30 + 0x1;
//         std::wcout << L"[Debug] Reading peer from address: 0x" << std::hex << peer_str_addr << std::endl;
//         std::string peer_result = SafeReadString(peer_str_addr);
//         if (!peer_result.empty())
//         {
//             peer = peer_result;
//             std::wcout << L"[Debug] Successfully read peer: "
//                        << std::wstring(peer.begin(), peer.end()).c_str() << std::endl;
//         }

//         // 根据JS代码：从 rbp+0x80 读取 seq
//         const uint64_t seq_addr = rbp + 0x80;
//         uint64_t seq_result = SafeReadUInt64(seq_addr);
//         if (seq_result != 0)
//         {
//             seq = seq_result;
//             std::wcout << L"[Debug] Successfully read seq: " << seq << std::endl;
//         }
//     }
//     catch (...)
//     {
//         std::wcout << L"[!] Exception in RecallGroupHookCallback" << std::endl;
//     }

//     // 发送灰色提示
//     if (tsfn_ptr)
//     {
//         std::string tip_text = "Sequence: " + std::to_string(seq) + " has been recalled";
//         CallAddGrayTip(peer, tip_text);
//     }
// }
// 设置Hook
bool SetupHooks()
{
    funchook_t *funchook = funchook_create();
    if (!funchook)
    {
        std::wcout << L"[!] Failed to create funchook" << std::endl;
        return false;
    }

    // Hook add_msg_listener
    void *add_msg_listener_addr = (void *)((UINT_PTR)g_wrapperModule + add_msg_listener_rva);
    original_add_msg_listener = (add_msg_listener_func)add_msg_listener_addr;

    int ret1 = funchook_prepare(funchook, (void **)&original_add_msg_listener, (void *)HookedAddMsgListener);
    if (ret1 != 0)
    {
        std::wcout << L"[!] Failed to prepare hook for add_msg_listener: " << ret1 << std::endl;
        funchook_destroy(funchook);
        return false;
    }

    // Hook recall_grp_func
    std::string pattern = "89 7C ?? ?? 4C 89 ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 8A 85 ?? ?? ?? ?? 88 44 ?? ?? 0F ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 4C 89 ?? ?? ?? 4C 89 ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 89 F5 44 89 F2 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ??";
    UINT64 recall_grp_absolute_addr = SearchRangeAddressInModule(g_wrapperModule, pattern);
    void *recall_grp_addr = (void *)(recall_grp_absolute_addr + 129); // E8 ?? ?? ?? ??
    void *grp_recall_listener = GetCallAddress(reinterpret_cast<uint8_t *>(recall_grp_addr));
    void *grp_recall_listener_rva = (void *)((UINT_PTR)grp_recall_listener - (UINT_PTR)g_wrapperModule);
    std::wcout << L"[+] Found recall_grp_func at address: " << std::hex << grp_recall_listener_rva << std::endl;

    original_grp_recall_listener = (grp_recall_listener_func)grp_recall_listener;
    int ret2 = funchook_prepare(funchook, (void **)&original_grp_recall_listener, (void *)HookedGrpRecallListener);
    if (ret2 != 0)
    {
        std::wcout << L"[!] Failed to prepare hook for grp_recall_listener: " << ret2 << std::endl;
        funchook_destroy(funchook);
        return false;
    }

    int install_ret = funchook_install(funchook, 0);
    if (install_ret != 0)
    {
        std::wcout << L"[!] Failed to install hooks: " << install_ret << std::endl;
        funchook_destroy(funchook);
        return false;
    }
    else
    {
        std::wcout << L"[+] Successfully hooked add_msg_listener and grp_recall_listener using funchook" << std::endl;
    }

    return true;
}
// 主初始化函数
bool InitializeAntiRecall()
{
    // 等待wrapper.node加载
    g_wrapperModule = GetModuleHandleW(L"wrapper.node");
    if (!g_wrapperModule)
    {
        std::wcout << L"[!] wrapper.node not found" << std::endl;
        return false;
    }
    std::wcout << L"[+] wrapper.node baseAddr: " << std::hex << g_wrapperModule << std::endl;

    // 获取wrapper.node的目录
    char wrapperPath[MAX_PATH];
    if (GetModuleFileNameA(g_wrapperModule, wrapperPath, MAX_PATH) == 0)
    {
        std::wcout << L"[!] Failed to get wrapper.node path" << std::endl;
        return false;
    }

    PEAnalyzer analyzer(wrapperPath);
    auto services = analyzer.scan_services();
    // 找到"NodeIKernelMsgService"服务
    auto it = std::find_if(services.begin(), services.end(),
                           [](const ServiceInfo &service)
                           { return service.service_name == "NodeIKernelMsgService"; });
    if (it == services.end())
    {
        std::wcout << L"[!] NodeIKernelMsgService not found" << std::endl;
        return false;
    }
    std::wcout << L"[+] Found NodeIKernelMsgService at vtable address: " << std::hex << it->vtable_address << std::endl;
    // 找到addKernelMsgListener方法
    auto addMsgListenerIt = std::find_if(it->methods.begin(), it->methods.end(),
                                         [](const std::pair<std::string, uint64_t> &method)
                                         {
                                             return method.first == "addKernelMsgListener";
                                         });
    if (addMsgListenerIt == it->methods.end())
    {
        std::wcout << L"[!] addKernelMsgListener not found" << std::endl;
        return false;
    }
    std::wcout << L"[+] Found addKernelMsgListener at address: " << std::hex << addMsgListenerIt->second << std::endl;
    add_msg_listener_rva = addMsgListenerIt->second - analyzer.get_image_base();

    // 找到addLocalJsonGrayTipMsg方法
    auto addLocalJsonGrayTipMsgIt = std::find_if(it->methods.begin(), it->methods.end(),
                                                 [](const std::pair<std::string, uint64_t> &method)
                                                 {
                                                     return method.first == "addLocalJsonGrayTipMsg";
                                                 });
    if (addLocalJsonGrayTipMsgIt == it->methods.end())
    {
        std::wcout << L"[!] addLocalJsonGrayTipMsg not found" << std::endl;
        return false;
    }
    std::wcout << L"[+] Found addLocalJsonGrayTipMsg at address: " << std::hex << addLocalJsonGrayTipMsgIt->second << std::endl;
    add_local_gray_tip_rva = static_cast<DWORD>(addLocalJsonGrayTipMsgIt->second) - analyzer.get_image_base();

    std::wcout << L"[+] add_local_gray_tip_rva: " << std::hex << add_local_gray_tip_rva << std::endl;
    std::wcout << L"[+] add_msg_listener_rva: " << std::hex << add_msg_listener_rva << std::endl;
    // 初始化NAPI函数
    if (!InitializeNAPIFunctions())
    {
        std::wcout << L"[!] Failed to initialize NAPI functions" << std::endl;
        return false;
    }
    std::wcout << L"[+] NAPI functions initialized successfully" << std::endl;
    // 应用内存补丁
    if (!hookGroupRecall(g_wrapperModule))
    {
        std::wcout << L"[!] Failed to patch group recall" << std::endl;
        return false;
    }

    // 设置函数hooks
    if (!SetupHooks())
    {
        std::wcout << L"[!] Failed to setup hooks" << std::endl;
        return false;
    }

    std::wcout << L"[+] Anti-recall initialization completed successfully" << std::endl;
    return true;
}

// 检查模块是否已加载
bool IsModuleLoaded(const wchar_t *moduleName)
{
    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded))
    {
        DWORD numModules = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < numModules; i++)
        {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(GetCurrentProcess(), hModules[i], szModName, sizeof(szModName) / sizeof(wchar_t)))
            {
                wchar_t *fileName = wcsrchr(szModName, L'\\');
                if (fileName != NULL)
                {
                    fileName++;
                    if (_wcsicmp(fileName, moduleName) == 0)
                    {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

INT_PTR g_timerId = 0;
HMODULE g_selfModule = NULL;

// 定时器回调函数
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    if (IsModuleLoaded(L"wrapper.node"))
    {
        // 停止定时器
        KillTimer(NULL, g_timerId);
        g_timerId = 0;

        // 执行初始化
        InitializeAntiRecall();
    }
}

// 模块检测线程
DWORD WINAPI CheckModuleThread(LPVOID lpParam)
{
    g_timerId = SetTimer(NULL, 0, 1000, TimerProc);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, CheckModuleThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
    }
    break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}