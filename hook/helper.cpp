#include "helper.h"
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

void PrintBytesAroundAddress(uint64_t address, int bytesBefore = 16, int bytesAfter = 16)
{
    std::stringstream ss;
    ss << "Memory dump around address 0x" << std::hex << std::uppercase << address << ":\n";

    uint8_t *startAddr = reinterpret_cast<uint8_t *>(address - bytesBefore);
    uint8_t *endAddr = reinterpret_cast<uint8_t *>(address + bytesAfter);

    try
    {
        for (uint8_t *current = startAddr; current <= endAddr; current += 16)
        {
            // 打印地址
            ss << std::hex << std::uppercase << std::setfill('0') << std::setw(16)
               << reinterpret_cast<uint64_t>(current) << ": ";

            // 打印十六进制字节
            for (int i = 0; i < 16 && (current + i) <= endAddr; ++i)
            {
                if (current + i == reinterpret_cast<uint8_t *>(address))
                {
                    ss << "[" << std::setfill('0') << std::setw(2)
                       << static_cast<int>(*(current + i)) << "] ";
                }
                else
                {
                    ss << std::setfill('0') << std::setw(2)
                       << static_cast<int>(*(current + i)) << " ";
                }
            }
            ss << "\n";
        }

        // 输出到控制台和调试器
        std::cout << ss.str() << std::endl;
        OutputDebugStringA(ss.str().c_str());
    }
    catch (...)
    {
        OutputDebugStringA("Error: Cannot read memory at specified address\n");
    }
}

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
    std::wcout << L"[DEBUG] SearchRangeAddressInModule started" << std::endl;

    try
    {
        HANDLE processHandle = GetCurrentProcess();
        std::wcout << L"[DEBUG] Process handle obtained: " << processHandle << std::endl;

        MODULEINFO modInfo;
        if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
        {
            std::wcout << L"[DEBUG] Failed to get module information, error: " << GetLastError() << std::endl;
            return 0;
        }

        std::wcout << L"[DEBUG] Module base: 0x" << std::hex << reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll)
                   << L", size: 0x" << modInfo.SizeOfImage << std::dec << std::endl;

        // 解析十六进制字符串为字节模式
        std::wcout << L"[DEBUG] Parsing hex pattern..." << std::endl;
        std::vector<uint8_t> pattern;
        try
        {
            pattern = ParseHexPattern(hexPattern);
            std::wcout << L"[DEBUG] Pattern parsed successfully, size: " << pattern.size() << std::endl;
        }
        catch (const std::exception &e)
        {
            std::wcout << L"[DEBUG] Pattern parsing failed" << std::endl;
            return 0;
        }

        // 在模块内存范围内搜索模式
        uint8_t *base = static_cast<uint8_t *>(modInfo.lpBaseOfDll);
        uint8_t *searchStart = base + searchStartRVA;
        if (searchEndRVA == 0)
        {
            // 如果留空表示搜索到结束
            searchEndRVA = modInfo.SizeOfImage;
        }
        uint8_t *searchEnd = base + searchEndRVA;

        std::wcout << L"[DEBUG] Search range: 0x" << std::hex << reinterpret_cast<uint64_t>(searchStart)
                   << L" - 0x" << reinterpret_cast<uint64_t>(searchEnd) << std::dec << std::endl;

        // 确保搜索范围有效
        if (searchStart < base || searchEnd > base + modInfo.SizeOfImage || searchStart >= searchEnd)
        {
            std::wcout << L"[DEBUG] Invalid search range!" << std::endl;
            return 0;
        }

        std::wcout << L"[DEBUG] Starting memory search..." << std::endl;

        // 检查内存保护属性
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(searchStart, &mbi, sizeof(mbi)))
        {
            std::wcout << L"[DEBUG] Memory protection: 0x" << std::hex << mbi.Protect
                       << L", state: 0x" << mbi.State << std::dec << std::endl;
        }

        uint64_t searchCount = 0;
        const uint64_t maxSearchCount = (searchEnd - searchStart);

        for (uint8_t *current = searchStart; current < searchEnd; ++current)
        {
            searchCount++;
            try
            {
                // 检查是否可以安全读取足够的字节
                if (current + pattern.size() > searchEnd)
                {
                    break;
                }

                // 使用IsBadReadPtr检查内存可读性
                if (IsBadReadPtr(current, pattern.size()))
                {
                    continue;
                }

                if (MatchPatternWithWildcard(current, pattern))
                {
                    std::wcout << L"[DEBUG] Pattern found at: 0x" << std::hex
                               << reinterpret_cast<uint64_t>(current) << std::dec << std::endl;
                    return reinterpret_cast<uint64_t>(current);
                }
            }
            catch (...)
            {
                std::wcout << L"[DEBUG] Exception at address: 0x" << std::hex
                           << reinterpret_cast<uint64_t>(current) << std::dec << std::endl;
                continue;
            }
        }

        std::wcout << L"[DEBUG] Search completed, pattern not found. Total searched: "
                   << searchCount << L" bytes" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::wcout << L"[DEBUG] Exception in SearchRangeAddressInModule" << std::endl;
    }
    catch (...)
    {
        std::wcout << L"[DEBUG] Unknown exception in SearchRangeAddressInModule" << std::endl;
    }

    return 0;
}

bool hookGroupRecall(HMODULE hModule)
{
    try
    {
        BYTE patchCode[] = {0x75}; // jnz
        std::string pattern = "49 89 DF 8A 9D ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 48 8D ?? ?? 4C 8D ?? ?? ?? ?? ?? 48 89 F1 4C 89 F2 E8 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 48 89 FA FF ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        address = address + 55;
        PrintBytesAroundAddress(address, 0);
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
        memcpy((LPVOID)address, patchCode, 1);
        VirtualProtect((LPVOID)address, 1, OldProtect, &OldProtect);
        PrintBytesAroundAddress(address, 0);
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