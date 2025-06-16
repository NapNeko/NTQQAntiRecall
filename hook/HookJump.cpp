#include "HookJump.h"
#include <stdexcept>

// 全局变量
static SimpleInlineHook *g_hook = nullptr;
static HookCallback g_user_callback = nullptr;

// SimpleInlineHook 类实现
SimpleInlineHook::SimpleInlineHook() : target_addr(nullptr), trampoline(nullptr), is_active(false)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
    {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

SimpleInlineHook::~SimpleInlineHook()
{
    if (is_active)
    {
        Uninstall();
    }
    cs_close(&cs_handle);
}

size_t SimpleInlineHook::CalculateBackupSize(void *target_addr, size_t min_size)
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

void *SimpleInlineHook::CreateTrampoline(void *target_addr, size_t backup_size, void *hook_func)
{
    // 分配可执行内存
    void *trampoline = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
    {
        throw std::runtime_error("Failed to allocate trampoline memory");
    }

    uint8_t *tramp_ptr = (uint8_t *)trampoline;

    // 1. 传递rbp作为参数 (Windows x64调用约定：第一个参数使用rcx)
    // mov rcx, rbp
    *tramp_ptr++ = 0x48;
    *tramp_ptr++ = 0x89;
    *tramp_ptr++ = 0xE9;

    // 2. 调用hook函数
    // mov rax, hook_func_addr
    *tramp_ptr++ = 0x48;
    *tramp_ptr++ = 0xB8;
    *(uint64_t *)tramp_ptr = (uint64_t)hook_func;
    tramp_ptr += 8;

    // call rax
    *tramp_ptr++ = 0xFF;
    *tramp_ptr++ = 0xD0;

    // 3. 执行原始指令
    memcpy(tramp_ptr, target_addr, backup_size);
    tramp_ptr += backup_size;

    // 4. 跳转回原位置
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

bool SimpleInlineHook::Install(void *target_addr, HookCallback callback)
{
    if (is_active)
    {
        return false;
    }

    try
    {
        this->target_addr = target_addr;
        
        // 计算需要备份的指令大小
        size_t backup_size = CalculateBackupSize(target_addr);

        // 备份原始字节
        original_bytes.resize(backup_size);
        original_size = backup_size;
        memcpy(original_bytes.data(), target_addr, backup_size);

        // 创建trampoline
        trampoline = CreateTrampoline(target_addr, backup_size, (void *)InternalHookHandler);

        // 修改目标地址的内存保护
        DWORD old_protect;
        if (!VirtualProtect(target_addr, backup_size, PAGE_EXECUTE_READWRITE, &old_protect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        // 写入跳转指令 (只需要12字节)
        uint8_t *target_ptr = (uint8_t *)target_addr;

        // mov rax, trampoline_addr (10字节)
        *target_ptr++ = 0x48;
        *target_ptr++ = 0xB8;
        *(uint64_t *)target_ptr = (uint64_t)trampoline;
        target_ptr += 8;

        // jmp rax (2字节)
        *target_ptr++ = 0xFF;
        *target_ptr++ = 0xE0;

        // 用NOP填充剩余空间
        for (size_t i = 12; i < backup_size; i++)
        {
            *target_ptr++ = 0x90; // NOP
        }

        // 恢复内存保护
        VirtualProtect(target_addr, backup_size, old_protect, &old_protect);

        g_user_callback = callback;
        is_active = true;
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Hook failed: " << e.what() << std::endl;
        return false;
    }
}

bool SimpleInlineHook::Uninstall()
{
    if (!is_active)
    {
        return false;
    }

    // 修改内存保护
    DWORD old_protect;
    if (!VirtualProtect(target_addr, original_size, PAGE_EXECUTE_READWRITE, &old_protect))
    {
        return false;
    }

    // 恢复原始字节
    memcpy(target_addr, original_bytes.data(), original_size);

    // 恢复内存保护
    VirtualProtect(target_addr, original_size, old_protect, &old_protect);

    // 释放trampoline
    if (trampoline)
    {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        trampoline = nullptr;
    }

    is_active = false;
    g_user_callback = nullptr;
    return true;
}

// 内部hook处理函数
extern "C" void __stdcall InternalHookHandler(uint64_t rbp_value)
{
    if (g_user_callback)
    {
        g_user_callback(rbp_value);
    }
}

// SimpleHookManager 类实现
bool SimpleHookManager::InstallHook(void *target_addr, HookCallback callback)
{
    if (g_hook)
    {
        return false; // 已经安装了hook
    }

    try
    {
        g_hook = new SimpleInlineHook();
        return g_hook->Install(target_addr, callback);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to install hook: " << e.what() << std::endl;
        delete g_hook;
        g_hook = nullptr;
        return false;
    }
}

bool SimpleHookManager::RemoveHook()
{
    if (!g_hook)
    {
        return false;
    }

    bool result = g_hook->Uninstall();
    delete g_hook;
    g_hook = nullptr;
    return result;
}

void SimpleHookManager::Cleanup()
{
    if (g_hook)
    {
        delete g_hook;
        g_hook = nullptr;
    }
    g_user_callback = nullptr;
}