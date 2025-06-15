#ifndef HELPER_H
#define HELPER_H

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <cstdint>

// 函数声明

/**
 * 移除字符串中的空格
 * @param input 输入字符串
 * @return 移除空格后的字符串
 */
std::string RemoveSpaces(const std::string &input);

/**
 * 将十六进制字符串转换为字节模式
 * @param hexPattern 十六进制模式字符串，支持 ?? 通配符
 * @return 字节模式向量
 */
std::vector<uint8_t> ParseHexPattern(const std::string &hexPattern);

/**
 * 使用通配符匹配字节模式
 * @param data 要匹配的数据
 * @param pattern 字节模式，0xCC 表示通配符
 * @return 是否匹配成功
 */
bool MatchPatternWithWildcard(const uint8_t *data, const std::vector<uint8_t> &pattern);

/**
 * 在模块内搜索指定的字节模式
 * @param module 目标模块句柄
 * @param hexPattern 十六进制模式字符串
 * @param searchStartRVA 搜索起始相对虚拟地址（默认为0）
 * @param searchEndRVA 搜索结束相对虚拟地址（默认为0，表示搜索到模块末尾）
 * @return 找到的地址，未找到返回0
 */
uint64_t SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, uint64_t searchStartRVA = 0, uint64_t searchEndRVA = 0);

/**
 * Hook 群撤回功能
 * @param hModule 目标模块句柄
 * @return Hook 是否成功
 */
bool hookGroupRecall(HMODULE hModule);

#endif