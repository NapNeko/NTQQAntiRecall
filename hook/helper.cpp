#include "helper.h"

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

uint64_t SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, uint64_t searchStartRVA, uint64_t searchEndRVA)
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

bool hookGroupRecall(HMODULE hModule)
{
    try
    {
        BYTE patchCode[] = {0x75}; // jnz
        std::string pattern = "80 BD ?? ?? ?? ?? ?? 0F ?? ?? ?? ?? 44 88 ?? ?? ?? 44 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 89 ?? ?? ?? 4C 89 ?? ?? ?? 4C 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF 8A 9D ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 48 89 F1 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 48 85 C9 4C 8D ?? ?? 74 ?? 48 8B 01 4C 89 F2 FF ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        address = address + 168;
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
        memcpy((LPVOID)address, patchCode, 1);
        VirtualProtect((LPVOID)address, 1, OldProtect, &OldProtect);
        return true;
    }
    catch (const std::exception &)
    {
        MessageBoxExW(NULL, L"Hook failed", L"Error", MB_OK, 0);
        return false;
    }
}

bool hookPrivateRecall(HMODULE hModule)
{
    try
    {
        BYTE patchCode[] = {0x75}; // jnz
        std::string pattern = "80 BD ?? ?? ?? ?? ?? 0F ?? ?? ?? ?? 44 88 ?? ?? ?? 44 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 89 ?? ?? ?? 4C 89 ?? ?? ?? 4C 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF 8A 9D ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 48 89 F1 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 48 85 C9 4C 8D ?? ?? 74 ?? 48 8B 01 4C 89 F2 FF ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        address = address + 168;
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
        memcpy((LPVOID)address, patchCode, 1);
        VirtualProtect((LPVOID)address, 1, OldProtect, &OldProtect);
        return true;
    }
    catch (const std::exception &)
    {
        MessageBoxExW(NULL, L"Hook failed", L"Error", MB_OK, 0);
        return false;
    }
}