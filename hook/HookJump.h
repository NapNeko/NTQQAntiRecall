#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <capstone/capstone.h>

// 前向声明
class StackAnalyzer;

class InlineHook
{
private:
    struct HookInfo
    {
        void *target_addr;
        void *trampoline;
        std::vector<uint8_t> original_bytes;
        size_t original_size;
        void *hook_function;
        bool is_active;
    };

    std::map<void *, HookInfo> hooks;
    csh cs_handle;

public:
    InlineHook();
    ~InlineHook();

    // 计算需要备份的指令长度（至少14字节用于绝对跳转）
    size_t CalculateBackupSize(void *target_addr, size_t min_size = 14);

    // 创建 trampoline（跳板）
    void *CreateTrampoline(void *target_addr, size_t backup_size, void *hook_func);

    // 安装 hook
    bool HookFunction(void *target_addr, void *hook_func);

    // 卸载 hook
    bool UnhookFunction(void *target_addr);
};

// 栈帧分析
class StackAnalyzer
{
public:
    struct RegisterContext
    {
        uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
        uint64_t rdi, rsi, rbp, rsp_orig, rbx, rdx, rcx, rax;
        uint64_t rflags;
        uint64_t return_addr; // 实际的返回地址
    };

    // 从栈中读取局部变量
    template <typename T>
    static T ReadStackVariable(const RegisterContext *ctx, int64_t offset)
    {
        // offset 相对于 rbp 的偏移量
        uint64_t addr = ctx->rbp + offset;
        return *(T *)addr;
    }

    // 读取函数参数（Windows x64 calling convention）
    static uint64_t GetArg1(const RegisterContext *ctx);
    static uint64_t GetArg2(const RegisterContext *ctx);
    static uint64_t GetArg3(const RegisterContext *ctx);
    static uint64_t GetArg4(const RegisterContext *ctx);

    // 第5个及以后的参数在栈上
    template <int N>
    static uint64_t GetArgN(const RegisterContext *ctx)
    {
        static_assert(N >= 5, "Use GetArg1-4 for first 4 arguments");
        return *(uint64_t *)(ctx->rsp_orig + 8 * (N - 1));
    }

    // 打印寄存器状态
    static void PrintRegisters(const RegisterContext *ctx);
};

// Hook 回调函数类型
typedef void (*HookCallback)(const StackAnalyzer::RegisterContext *ctx);

// 内部 hook 处理函数
extern "C" void __stdcall InternalHookHandler(void *stack_ptr);

// 示例回调函数
void MyHookCallback(const StackAnalyzer::RegisterContext *ctx);

// 主要的 API 函数
class QQHookManager
{
public:
    static bool Initialize();
    static void Cleanup();
    static bool InstallHook(void *target_addr, HookCallback callback);
    static bool RemoveHook(void *target_addr);
};