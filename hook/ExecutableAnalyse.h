#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// #define _LINUX_PLATFORM_
#define _WIN_PLATFORM_

#define _X64_ARCH_

#if defined(_WIN_PLATFORM_)
#include <Windows.h>
#include <psapi.h>
#elif defined(_LINUX_PLATFORM_)
#include <proc_maps.h>
#endif

// std::vector<char> ReadFileToMemory(const std::string &filePath);
// size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern);
#if defined(_LINUX_PLATFORM_)
uint64_t SearchRangeAddressInModule(std::shared_ptr<hak::proc_maps> module, const std::vector<uint8_t> &pattern, uint64_t searchStartRVA = 0, uint64_t searchEndRVA = 0);
#elif defined(_WIN_PLATFORM_)
uint64_t SearchRangeAddressInModule(HMODULE module, const std::vector<uint8_t> &pattern, uint64_t searchStartRVA = 0, uint64_t searchEndRVA = 0);
#endif