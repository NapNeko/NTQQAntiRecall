#include <Windows.h>
#include <vector>
#include <psapi.h>
#include <string>
#include <atlstr.h>
#include <iostream>

BYTE jzCode[] = {0x0F, 0x86};

// 辅助函数 去除字符串中的所有空格
std::string RemoveSpaces(const std::string &input)
{

    std::string result;
    for (char c : input)
    {
        if (c != ' ')
        {
            result += c;
        }
    }
    return result;
}

// 辅助函数 将十六进制字符串转换为字节模式
std::vector<uint8_t> ParseHexPattern(const std::string &hexPattern)
{
    std::string cleanedPattern = RemoveSpaces(hexPattern);
    std::vector<uint8_t> pattern;
    for (size_t i = 0; i < cleanedPattern.length(); i += 2)
    {
        std::string byteStr = cleanedPattern.substr(i, 2);
        if (byteStr == "??")
        {
            pattern.push_back(0xCC); // 使用 0xCC 作为通配符
        }
        else
        {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            pattern.push_back(byte);
        }
    }
    return pattern;
}

// 支持通配符
bool MatchPatternWithWildcard(const uint8_t *data, const std::vector<uint8_t> &pattern)
{
    for (size_t i = 0; i < pattern.size(); ++i)
    {
        if (pattern[i] != 0xCC && data[i] != pattern[i])
        {
            return false;
        }
    }
    return true;
}

uint64_t SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, uint64_t searchStartRVA = 0, uint64_t searchEndRVA = 0)
{
    HANDLE processHandle = GetCurrentProcess();
    MODULEINFO modInfo;
    if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
    {
        return 0;
    }
    // 解析十六进制字符串为字节模式
    std::vector<uint8_t> pattern = ParseHexPattern(hexPattern);

    // 在模块内存范围内搜索模式
    uint8_t *base = static_cast<uint8_t *>(modInfo.lpBaseOfDll);
    uint8_t *searchStart = base + searchStartRVA;
    if (searchEndRVA == 0)
    {
        // 如果留空表示搜索到结束
        searchEndRVA = modInfo.SizeOfImage;
    }
    uint8_t *searchEnd = base + searchEndRVA;

    // 确保搜索范围有效
    if (searchStart >= base && searchEnd <= base + modInfo.SizeOfImage)
    {
        for (uint8_t *current = searchStart; current < searchEnd; ++current)
        {
            if (MatchPatternWithWildcard(current, pattern))
            {
                return reinterpret_cast<uint64_t>(current);
            }
        }
    }

    return 0;
}

bool hookRecall(HMODULE hModule)
{
    try
    {
        // mov     rdx, [rbp+2A0h+var_158]
        // mov     r8, [rbp+2A0h+var_150]
        // mov     rax, r8
        // sub     rax, rdx
        // cmp     rax, 7
        // ja      loc_1825B3B11 -> jna loc_1825B3B11
        std::string pattern = "48 8B 95 ?? ?? ?? ?? 4C 8B 85 ?? ?? ?? ?? 4C 89 C0 48 29 D0 48 83 F8 07 0F 87 ?? ?? ?? ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        address = address + 24;
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
        memcpy((LPVOID)address, jzCode, 2);
        VirtualProtect((LPVOID)address, 2, OldProtect, &OldProtect);
        return true;
    }
    catch (const std::exception &)
    {
        MessageBoxExW(NULL, L"Hook failed", L"Error", MB_OK, 0);
        return false;
    }
}

INT_PTR g_timerId = 0;
HMODULE g_selfModule = NULL;

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
                // 获取文件名部分
                wchar_t *fileName = wcsrchr(szModName, L'\\');
                if (fileName != NULL)
                {
                    fileName++; // 跳过反斜杠
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

// 定时器回调函数
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    if (IsModuleLoaded(L"wrapper.node"))
    {
        // 停止定时器
        KillTimer(NULL, g_timerId);
        g_timerId = 0;

        // 执行 hook 操作
        hookRecall(GetModuleHandleW(L"wrapper.node"));

        // 卸载自身
        FreeLibraryAndExitThread(g_selfModule, 0);
    }
}

// 创建启动检测线程
DWORD WINAPI CheckModuleThread(LPVOID lpParam)
{
    // 创建一个定时器，每5000毫秒检查一次
    g_timerId = SetTimer(NULL, 0, 5000, TimerProc);
    // 保持消息循环运行，以便定时器能够工作
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
    HANDLE hThread = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule); // 禁用线程通知，提高效率

        hThread = CreateThread(NULL, 0, CheckModuleThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        break;

    case DLL_PROCESS_DETACH:
        // 在DLL卸载时确保定时器被清理
        if (g_timerId != 0)
        {
            KillTimer(NULL, g_timerId);
        }
        break;
    }
    return TRUE;
}