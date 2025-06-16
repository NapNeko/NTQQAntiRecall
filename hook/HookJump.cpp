#include "HookJump.h"
#include <stdexcept>

// 全局 hook 实例
static InlineHook *g_hook = nullptr;
static HookCallback g_user_callback = nullptr;

// InlineHook 类实现
InlineHook::InlineHook()
{
    // 初始化 Capstone 反汇编引擎
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
    {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

InlineHook::~InlineHook()
{
    // 清理所有 hook
    for (auto &[addr, info] : hooks)
    {
        if (info.is_active)
        {
            UnhookFunction(addr);
        }
    }
    cs_close(&cs_handle);
}

size_t InlineHook::CalculateBackupSize(void *target_addr, size_t min_size)
{
    uint8_t *code = (uint8_t *)target_addr;
    cs_insn *insn;
    size_t count = cs_disasm(cs_handle, code, 64, (uint64_t)target_addr, 0, &insn);

    if (count == 0)
    {
        throw std::runtime_error("Failed to disassemble target code");
    }

    size_t total_size = 0;
    for (size_t i = 0; i < count; i++)
    {
        total_size += insn[i].size;
        if (total_size >= min_size)
        {
            break;
        }
    }

    cs_free(insn, count);
    return total_size;
}

void *InlineHook::CreateTrampoline(void *target_addr, size_t backup_size, void *hook_func)
{
    // 分配可执行内存
    void *trampoline = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
    {
        throw std::runtime_error("Failed to allocate trampoline memory");
    }

    uint8_t *tramp_ptr = (uint8_t *)trampoline;

    // 1. 保存寄存器上下文
    // pushfq
    *tramp_ptr++ = 0x9C;

    // push rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15
    const uint8_t push_regs[] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, // rax-rdi
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // r8-r11
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57  // r12-r15
    };
    memcpy(tramp_ptr, push_regs, sizeof(push_regs));
    tramp_ptr += sizeof(push_regs);

    // 2. 调用 hook 函数
    // mov rcx, rsp (传递栈指针作为参数)
    *tramp_ptr++ = 0x48;
    *tramp_ptr++ = 0x89;
    *tramp_ptr++ = 0xE1;

    // mov rax, hook_func_addr
    *tramp_ptr++ = 0x48;
    *tramp_ptr++ = 0xB8;
    *(uint64_t *)tramp_ptr = (uint64_t)hook_func;
    tramp_ptr += 8;

    // call rax
    *tramp_ptr++ = 0xFF;
    *tramp_ptr++ = 0xD0;

    // 3. 恢复寄存器上下文
    const uint8_t pop_regs[] = {
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, // r15-r12
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, // r11-r8
        0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58  // rdi-rax
    };
    memcpy(tramp_ptr, pop_regs, sizeof(pop_regs));
    tramp_ptr += sizeof(pop_regs);

    // popfq
    *tramp_ptr++ = 0x9D;

    // 4. 执行原始指令
    memcpy(tramp_ptr, target_addr, backup_size);
    tramp_ptr += backup_size;

    // 5. 跳转回原位置
    // mov rax, return_addr
    *tramp_ptr++ = 0x48;
    *tramp_ptr++ = 0xB8;
    *(uint64_t *)tramp_ptr = (uint64_t)target_addr + backup_size;
    tramp_ptr += 8;

    // jmp rax
    *tramp_ptr++ = 0xFF;
    *tramp_ptr++ = 0xE0;

    return trampoline;
}

bool InlineHook::HookFunction(void *target_addr, void *hook_func)
{
    try
    {
        // 计算需要备份的指令大小
        size_t backup_size = CalculateBackupSize(target_addr);

        // 备份原始字节
        std::vector<uint8_t> original_bytes(backup_size);
        memcpy(original_bytes.data(), target_addr, backup_size);

        // 创建 trampoline
        void *trampoline = CreateTrampoline(target_addr, backup_size, hook_func);

        // 修改目标地址的内存保护
        DWORD old_protect;
        if (!VirtualProtect(target_addr, backup_size, PAGE_EXECUTE_READWRITE, &old_protect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        // 写入跳转指令
        uint8_t *target_ptr = (uint8_t *)target_addr;

        // mov rax, trampoline_addr
        *target_ptr++ = 0x48;
        *target_ptr++ = 0xB8;
        *(uint64_t *)target_ptr = (uint64_t)trampoline;
        target_ptr += 8;

        // jmp rax
        *target_ptr++ = 0xFF;
        *target_ptr++ = 0xE0;

        // 用 NOP 填充剩余空间
        for (size_t i = 12; i < backup_size; i++)
        {
            *target_ptr++ = 0x90; // NOP
        }

        // 恢复内存保护
        VirtualProtect(target_addr, backup_size, old_protect, &old_protect);

        // 保存 hook 信息
        HookInfo info;
        info.target_addr = target_addr;
        info.trampoline = trampoline;
        info.original_bytes = std::move(original_bytes);
        info.original_size = backup_size;
        info.hook_function = hook_func;
        info.is_active = true;

        hooks[target_addr] = std::move(info);
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Hook failed: " << e.what() << std::endl;
        return false;
    }
}

bool InlineHook::UnhookFunction(void *target_addr)
{
    auto it = hooks.find(target_addr);
    if (it == hooks.end() || !it->second.is_active)
    {
        return false;
    }

    HookInfo &info = it->second;

    // 修改内存保护
    DWORD old_protect;
    if (!VirtualProtect(target_addr, info.original_size, PAGE_EXECUTE_READWRITE, &old_protect))
    {
        return false;
    }

    // 恢复原始字节
    memcpy(target_addr, info.original_bytes.data(), info.original_size);

    // 恢复内存保护
    VirtualProtect(target_addr, info.original_size, old_protect, &old_protect);

    // 释放 trampoline
    VirtualFree(info.trampoline, 0, MEM_RELEASE);

    info.is_active = false;
    return true;
}

// StackAnalyzer 类实现
uint64_t StackAnalyzer::GetArg1(const RegisterContext *ctx) 
{ 
    return ctx->rcx; 
}

uint64_t StackAnalyzer::GetArg2(const RegisterContext *ctx) 
{ 
    return ctx->rdx; 
}

uint64_t StackAnalyzer::GetArg3(const RegisterContext *ctx) 
{ 
    return ctx->r8; 
}

uint64_t StackAnalyzer::GetArg4(const RegisterContext *ctx) 
{ 
    return ctx->r9; 
}

void StackAnalyzer::PrintRegisters(const RegisterContext *ctx)
{
    std::cout << "=== Register Context ===" << std::endl;
    std::cout << "RAX: 0x" << std::hex << ctx->rax << std::endl;
    std::cout << "RBX: 0x" << std::hex << ctx->rbx << std::endl;
    std::cout << "RCX: 0x" << std::hex << ctx->rcx << std::endl;
    std::cout << "RDX: 0x" << std::hex << ctx->rdx << std::endl;
    std::cout << "RSI: 0x" << std::hex << ctx->rsi << std::endl;
    std::cout << "RDI: 0x" << std::hex << ctx->rdi << std::endl;
    std::cout << "RBP: 0x" << std::hex << ctx->rbp << std::endl;
    std::cout << "RSP: 0x" << std::hex << ctx->rsp_orig << std::endl;
    std::cout << "R8:  0x" << std::hex << ctx->r8 << std::endl;
    std::cout << "R9:  0x" << std::hex << ctx->r9 << std::endl;
    std::cout << "R10: 0x" << std::hex << ctx->r10 << std::endl;
    std::cout << "R11: 0x" << std::hex << ctx->r11 << std::endl;
    std::cout << "R12: 0x" << std::hex << ctx->r12 << std::endl;
    std::cout << "R13: 0x" << std::hex << ctx->r13 << std::endl;
    std::cout << "R14: 0x" << std::hex << ctx->r14 << std::endl;
    std::cout << "R15: 0x" << std::hex << ctx->r15 << std::endl;
    std::cout << "========================" << std::endl;
}

// 内部 hook 处理函数
extern "C" void __stdcall InternalHookHandler(void *stack_ptr)
{
    if (g_user_callback)
    {
        // 栈指针指向保存的寄存器上下文
        const StackAnalyzer::RegisterContext *ctx =
            (const StackAnalyzer::RegisterContext *)stack_ptr;
        g_user_callback(ctx);
    }
}

// 示例回调函数
void MyHookCallback(const StackAnalyzer::RegisterContext *ctx)
{
    std::cout << "\n=== Hook Triggered ===" << std::endl;

    // 打印寄存器状态
    StackAnalyzer::PrintRegisters(ctx);

    // 读取栈上的局部变量示例
    try
    {
        // 读取 rbp-8 位置的 64 位值
        uint64_t local_var1 = StackAnalyzer::ReadStackVariable<uint64_t>(ctx, -8);
        std::cout << "Local var at [rbp-8]: 0x" << std::hex << local_var1 << std::endl;

        // 读取 rbp-16 位置的 32 位值
        uint32_t local_var2 = StackAnalyzer::ReadStackVariable<uint32_t>(ctx, -16);
        std::cout << "Local var at [rbp-16]: 0x" << std::hex << local_var2 << std::endl;

        // 读取函数参数
        std::cout << "Arg1 (RCX): 0x" << std::hex << StackAnalyzer::GetArg1(ctx) << std::endl;
        std::cout << "Arg2 (RDX): 0x" << std::hex << StackAnalyzer::GetArg2(ctx) << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "Error reading stack: " << e.what() << std::endl;
    }

    std::cout << "=====================" << std::endl;
}

// QQHookManager 类实现
bool QQHookManager::Initialize()
{
    if (g_hook)
        return true;

    try
    {
        g_hook = new InlineHook();
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to initialize hook: " << e.what() << std::endl;
        return false;
    }
}

void QQHookManager::Cleanup()
{
    if (g_hook)
    {
        delete g_hook;
        g_hook = nullptr;
    }
    g_user_callback = nullptr;
}

bool QQHookManager::InstallHook(void *target_addr, HookCallback callback)
{
    if (!g_hook || !target_addr || !callback)
        return false;

    g_user_callback = callback;
    return g_hook->HookFunction(target_addr, (void *)InternalHookHandler);
}

bool QQHookManager::RemoveHook(void *target_addr)
{
    if (!g_hook)
        return false;
    return g_hook->UnhookFunction(target_addr);
}