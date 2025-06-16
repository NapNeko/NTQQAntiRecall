#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <capstone/capstone.h>

// Hook 回调函数类型 - 只传递rbp
typedef void (*HookCallback)(uint64_t rbp);

// 简化的Hook类
class SimpleInlineHook
{
private:
    csh cs_handle;
    void *target_addr;
    void *trampoline;
    std::vector<uint8_t> original_bytes;
    size_t original_size;
    bool is_active;

public:
    SimpleInlineHook();
    ~SimpleInlineHook();

    // 计算需要备份的指令长度
    size_t CalculateBackupSize(void *target_addr, size_t min_size = 12);

    // 创建简化的trampoline
    void *CreateTrampoline(void *target_addr, size_t backup_size, void *hook_func);

    // 安装hook
    bool Install(void *target_addr, HookCallback callback);

    // 卸载hook
    bool Uninstall();
};

// 内部hook处理函数
extern "C" void __stdcall InternalHookHandler(uint64_t rbp_value);

class SimpleHookManager
{
public:
    static bool InstallHook(void *target_addr, HookCallback callback);
    static bool RemoveHook();
    static void Cleanup();
};