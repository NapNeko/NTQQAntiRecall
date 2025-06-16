#include "ServiceScan.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

PEAnalyzer::PEAnalyzer(const std::string &filename) : image_base(0)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK)
    {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    cs_option(capstone_handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    if (!load_file(filename))
    {
        throw std::runtime_error("Failed to load PE file");
    }
}

PEAnalyzer::~PEAnalyzer()
{
    cs_close(&capstone_handle);
}

bool PEAnalyzer::load_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cout << "[error] Failed to open file: " << filename << std::endl;
        return false;
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    pe_data.resize(size);
    if (!file.read(reinterpret_cast<char *>(pe_data.data()), size))
    {
        std::cout << "[error] Failed to read file content" << std::endl;
        return false;
    }

    // Parse PE headers
    if (pe_data.size() < sizeof(DOSHeader))
    {
        std::cout << "[error] File too small for DOS header" << std::endl;
        return false;
    }

    auto dos_header = reinterpret_cast<const DOSHeader *>(pe_data.data());
    if (dos_header->e_magic != 0x5A4D)
    { // "MZ"
        std::cout << "[error] Invalid DOS signature" << std::endl;
        return false;
    }

    // 检查NT头偏移是否有效
    if (dos_header->e_lfanew >= pe_data.size() || 
        dos_header->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader) >= pe_data.size())
    {
        std::cout << "[error] Invalid NT header offset" << std::endl;
        return false;
    }

    // 检查PE签名
    uint32_t *nt_signature = reinterpret_cast<uint32_t *>(pe_data.data() + dos_header->e_lfanew);
    if (*nt_signature != 0x00004550) // "PE\0\0"
    {
        std::cout << "[error] Invalid PE signature" << std::endl;
        return false;
    }

    auto file_header = reinterpret_cast<const FileHeader *>(
        pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t));

    // 检查可选头大小
    if (file_header->size_of_optional_header < sizeof(OptionalHeader64))
    {
        std::cout << "[error] Optional header too small" << std::endl;
        return false;
    }

    auto optional_header = reinterpret_cast<const OptionalHeader64 *>(
        pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t) + sizeof(FileHeader));

    // 检查魔数是否为PE32+
    if (optional_header->magic != 0x020b)
    {
        std::cout << "[error] Not a PE32+ file (64-bit)" << std::endl;
        return false;
    }

    image_base = optional_header->image_base;
    std::cout << "[debug] PE file loaded successfully, image_base: 0x" << std::hex << image_base << std::dec << std::endl;
    std::cout << "[debug] Number of sections: " << file_header->number_of_sections << std::endl;

    return true;
}

uint32_t PEAnalyzer::rva_to_file_offset(uint32_t rva)
{
    if (pe_data.size() < sizeof(DOSHeader))
    {
        std::cout << "[debug] Invalid PE data for RVA conversion: 0x" << std::hex << rva << std::dec << std::endl;
        return 0;
    }

    auto dos_header = reinterpret_cast<const DOSHeader *>(pe_data.data());
    auto file_header = reinterpret_cast<const FileHeader *>(
        pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t));

    auto sections_start = pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t) +
                          sizeof(FileHeader) + file_header->size_of_optional_header;

    for (uint16_t i = 0; i < file_header->number_of_sections; ++i)
    {
        auto section = reinterpret_cast<const SectionHeader *>(sections_start + i * sizeof(SectionHeader));

        if (rva >= section->virtual_address && 
            rva < section->virtual_address + section->virtual_size)
        {
            uint32_t offset_in_section = rva - section->virtual_address;
            
            // 检查原始数据大小
            if (section->size_of_raw_data == 0)
            {
                std::cout << "[debug] Section has no raw data (BSS section?)" << std::endl;
                return 0; // BSS段或未初始化段
            }
            
            // 确保偏移不超过原始数据大小
            if (offset_in_section >= section->size_of_raw_data)
            {
                std::cout << "[debug] RVA 0x" << std::hex << rva 
                          << " is beyond raw data (offset: 0x" << offset_in_section 
                          << ", raw_size: 0x" << section->size_of_raw_data << ")" << std::dec << std::endl;
                return 0;
            }
            
            uint32_t file_offset = section->pointer_to_raw_data + offset_in_section;
            return file_offset;
        }
    }

    std::cout << "[debug] RVA 0x" << std::hex << rva << " not found in any section" << std::dec << std::endl;
    return 0; // 找不到对应节区
}

std::optional<SectionRange> PEAnalyzer::get_section_range_rva(const std::string &section_name)
{
    if (pe_data.size() < sizeof(DOSHeader))
    {
        std::cout << "[error] Invalid PE data size" << std::endl;
        return std::nullopt;
    }

    auto dos_header = reinterpret_cast<const DOSHeader *>(pe_data.data());
    auto file_header = reinterpret_cast<const FileHeader *>(
        pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t));

    auto sections_start = pe_data.data() + dos_header->e_lfanew + sizeof(uint32_t) +
                          sizeof(FileHeader) + file_header->size_of_optional_header;

    std::cout << "[debug] Looking for section: " << section_name << std::endl;

    for (uint16_t i = 0; i < file_header->number_of_sections; ++i)
    {
        auto section = reinterpret_cast<const SectionHeader *>(sections_start + i * sizeof(SectionHeader));

        // 安全地获取节区名称
        std::string name;
        for (int j = 0; j < 8 && section->name[j] != '\0'; ++j)
        {
            name += section->name[j];
        }

        std::cout << "[debug] Found section: " << name 
                  << " RVA: 0x" << std::hex << section->virtual_address
                  << " Size: 0x" << section->virtual_size 
                  << " RawSize: 0x" << section->size_of_raw_data << std::dec << std::endl;

        if (name == section_name)
        {
            // 只返回有原始数据的范围
            uint32_t end_rva = section->virtual_address;
            if (section->size_of_raw_data > 0)
            {
                end_rva += std::min(section->virtual_size, section->size_of_raw_data);
            }
            else
            {
                end_rva += section->virtual_size;
            }
            
            return SectionRange{section->virtual_address, end_rva};
        }
    }

    std::cout << "[error] Section " << section_name << " not found" << std::endl;
    return std::nullopt;
}

std::optional<uint32_t> PEAnalyzer::search_bytes(uint32_t start, uint32_t end,
                                                 const std::vector<uint8_t> &pattern)
{
    if (pattern.empty())
    {
        std::cout << "[error] Empty search pattern" << std::endl;
        return std::nullopt;
    }

    std::cout << "[debug] Searching pattern in RVA range: 0x" << std::hex << start 
              << " - 0x" << end << std::dec << std::endl;

    // 搜索范围不能为空
    if (start >= end)
    {
        std::cout << "[error] Invalid search range: start >= end" << std::endl;
        return std::nullopt;
    }

    // 按4KB块搜索，避免大范围转换问题
    const uint32_t BLOCK_SIZE = 4096;
    uint32_t current_rva = start;

    while (current_rva < end)
    {
        uint32_t block_end = std::min(current_rva + BLOCK_SIZE, end);
        uint32_t file_start = rva_to_file_offset(current_rva);
        
        if (file_start == 0)
        {
            // 跳过无法转换的RVA
            current_rva = block_end;
            continue;
        }

        // 计算实际可搜索的大小
        uint32_t search_size = block_end - current_rva;
        if (search_size < pattern.size())
        {
            current_rva = block_end;
            continue;
        }

        // 确保不会越界
        if (file_start + search_size > pe_data.size())
        {
            search_size = pe_data.size() - file_start;
        }

        if (search_size >= pattern.size())
        {
            // 在当前块中搜索
            for (uint32_t i = 0; i <= search_size - pattern.size(); ++i)
            {
                if (std::equal(pattern.begin(), pattern.end(), pe_data.begin() + file_start + i))
                {
                    uint32_t found_rva = current_rva + i;
                    std::cout << "[debug] Pattern found at RVA: 0x" << std::hex << found_rva << std::dec << std::endl;
                    return found_rva;
                }
            }
        }

        current_rva = block_end;
    }

    std::cout << "[debug] Pattern not found in specified range" << std::endl;
    return std::nullopt;
}

std::vector<uint32_t> PEAnalyzer::search_bytes_all(uint32_t start, uint32_t end,
                                                   const std::vector<uint8_t> &pattern)
{
    std::vector<uint32_t> results;
    if (pattern.empty() || start >= end)
    {
        return results;
    }

    // 按块搜索，类似于search_bytes
    const uint32_t BLOCK_SIZE = 4096;
    uint32_t current_rva = start;

    while (current_rva < end)
    {
        uint32_t block_end = std::min(current_rva + BLOCK_SIZE, end);
        uint32_t file_start = rva_to_file_offset(current_rva);
        
        if (file_start == 0)
        {
            current_rva = block_end;
            continue;
        }

        uint32_t search_size = block_end - current_rva;
        if (search_size < pattern.size())
        {
            current_rva = block_end;
            continue;
        }

        if (file_start + search_size > pe_data.size())
        {
            search_size = pe_data.size() - file_start;
        }

        if (search_size >= pattern.size())
        {
            for (uint32_t i = 0; i <= search_size - pattern.size(); ++i)
            {
                if (std::equal(pattern.begin(), pattern.end(), pe_data.begin() + file_start + i))
                {
                    results.push_back(current_rva + i);
                }
            }
        }

        current_rva = block_end;
    }

    return results;
}

std::vector<uint8_t> PEAnalyzer::get_data(uint32_t rva, uint32_t size)
{
    uint32_t file_offset = rva_to_file_offset(rva);
    
    if (file_offset == 0)
    {
        std::cout << "[warning] Failed to convert RVA 0x" << std::hex << rva << " to file offset" << std::dec << std::endl;
        return {};
    }
    
    if (file_offset + size > pe_data.size())
    {
        std::cout << "[warning] Data read beyond file bounds: offset=0x" << std::hex << file_offset 
                  << " size=0x" << size << " file_size=0x" << pe_data.size() << std::dec << std::endl;
        // 调整大小到文件末尾
        if (file_offset >= pe_data.size())
        {
            return {};
        }
        size = pe_data.size() - file_offset;
    }

    return std::vector<uint8_t>(pe_data.begin() + file_offset, pe_data.begin() + file_offset + size);
}

std::string PEAnalyzer::read_utf8_string(uint32_t rva)
{
    std::string result;
    uint32_t file_offset = rva_to_file_offset(rva);

    if (file_offset == 0)
    {
        return result;
    }

    while (file_offset < pe_data.size())
    {
        uint8_t byte = pe_data[file_offset];
        if (byte == 0)
        {
            break;
        }
        result += static_cast<char>(byte);
        ++file_offset;
    }

    return result;
}

std::vector<uint64_t> PEAnalyzer::find_service_register_calls(uint32_t offset_qqnt_service,
                                                              uint32_t max_bytes)
{
    std::vector<uint64_t> service_registers_function;

    auto code_bytes = get_data(offset_qqnt_service, max_bytes);
    if (code_bytes.empty())
    {
        std::cout << "[debug] No code data retrieved for service register search" << std::endl;
        return service_registers_function;
    }

    cs_insn *insn;
    size_t count = cs_disasm(capstone_handle, code_bytes.data(), code_bytes.size(),
                             offset_qqnt_service + image_base, 0, &insn);

    if (count == 0)
    {
        std::cout << "[debug] Failed to disassemble code for service register search" << std::endl;
        return service_registers_function;
    }

    bool prev_mov_rcx_rdi = false;
    bool prev_mov_rdx_rsi = false;

    for (size_t i = 0; i < count; ++i)
    {
        // Check for ret/retn
        if (strcmp(insn[i].mnemonic, "ret") == 0 || strcmp(insn[i].mnemonic, "retn") == 0)
        {
            break;
        }

        // Check mov rcx, rdi
        if (strcmp(insn[i].mnemonic, "mov") == 0 && strcmp(insn[i].op_str, "rcx, rdi") == 0)
        {
            prev_mov_rcx_rdi = true;
            continue;
        }

        // Check mov rdx, rsi
        if (prev_mov_rcx_rdi && strcmp(insn[i].mnemonic, "mov") == 0 &&
            strcmp(insn[i].op_str, "rdx, rsi") == 0)
        {
            prev_mov_rdx_rsi = true;
            continue;
        }

        // Check call
        if (prev_mov_rcx_rdi && prev_mov_rdx_rsi && strcmp(insn[i].mnemonic, "call") == 0)
        {
            uint64_t call_addr;
            if (strncmp(insn[i].op_str, "0x", 2) == 0)
            {
                call_addr = std::stoull(insn[i].op_str, nullptr, 16);
            }
            else
            {
                // Handle relative call
                int64_t offset = std::stoll(insn[i].op_str);
                call_addr = insn[i].address + insn[i].size + offset;
            }
            service_registers_function.push_back(call_addr);
            std::cout << "[result] Found call at 0x" << std::hex << insn[i].address
                      << " -> 0x" << call_addr << std::dec << std::endl;

            // Reset state
            prev_mov_rcx_rdi = false;
            prev_mov_rdx_rsi = false;
            continue;
        }

        // Reset state
        prev_mov_rcx_rdi = false;
        prev_mov_rdx_rsi = false;
    }

    cs_free(insn, count);
    std::cout << "[debug] Found " << service_registers_function.size() << " service register calls" << std::endl;
    return service_registers_function;
}

std::tuple<std::optional<uint64_t>, std::optional<uint64_t>, std::optional<uint32_t>>
PEAnalyzer::extract_service_info(uint32_t func_rva, uint32_t max_bytes)
{
    auto code_bytes = get_data(func_rva, max_bytes);
    if (code_bytes.empty())
    {
        return {std::nullopt, std::nullopt, std::nullopt};
    }

    cs_insn *insn;
    size_t count = cs_disasm(capstone_handle, code_bytes.data(), code_bytes.size(),
                             func_rva + image_base, 0, &insn);

    if (count == 0)
    {
        return {std::nullopt, std::nullopt, std::nullopt};
    }

    std::vector<uint64_t> lea_targets;
    std::optional<uint32_t> r8d_imm;

    for (size_t i = 0; i < count; ++i)
    {
        // Check lea rdx/rsi, [rip + imm]
        if (strcmp(insn[i].mnemonic, "lea") == 0)
        {
            std::string op_str(insn[i].op_str);
            if (op_str.find("rdx, [rip + ") == 0 || op_str.find("rsi, [rip + ") == 0)
            {
                try
                {
                    size_t plus_pos = op_str.find(" + ");
                    size_t bracket_pos = op_str.find(']');
                    if (plus_pos != std::string::npos && bracket_pos != std::string::npos)
                    {
                        std::string imm_str = op_str.substr(plus_pos + 3, bracket_pos - plus_pos - 3);
                        int64_t imm = std::stoll(imm_str, nullptr,
                                                 imm_str.find("0x") == 0 ? 16 : 10);
                        uint64_t target_addr = insn[i].address + insn[i].size + imm;
                        lea_targets.push_back(target_addr);
                    }
                }
                catch (...)
                {
                    continue;
                }
            }
        }

        // Check mov r8d, imm32
        if (strcmp(insn[i].mnemonic, "mov") == 0)
        {
            std::string op_str(insn[i].op_str);
            if (op_str.find("r8d, ") == 0)
            {
                try
                {
                    std::string imm_str = op_str.substr(5);
                    r8d_imm = std::stoul(imm_str, nullptr,
                                         imm_str.find("0x") == 0 ? 16 : 10);
                }
                catch (...)
                {
                    // Ignore parsing errors
                }
            }
        }

        // Stop after call or rep movsq
        if (strcmp(insn[i].mnemonic, "call") == 0 ||
            (strcmp(insn[i].mnemonic, "movsq") == 0 && strstr(insn[i].op_str, "rep") != nullptr))
        {
            if (lea_targets.size() >= 2)
            {
                break;
            }
        }
    }

    cs_free(insn, count);

    std::optional<uint64_t> vtable_address, service_name;
    if (lea_targets.size() >= 2)
    {
        vtable_address = lea_targets[0];
        service_name = lea_targets[1];
    }
    else if (lea_targets.size() == 1)
    {
        vtable_address = lea_targets[0];
    }

    return {vtable_address, service_name, r8d_imm};
}

std::pair<std::optional<uint64_t>, uint32_t> PEAnalyzer::read_aligned_qword(uint32_t addr)
{
    uint32_t cur_addr = addr;

    // 限制循环次数，避免无限循环
    const int max_iterations = 1024;
    int iterations = 0;

    while (iterations < max_iterations)
    {
        auto qword_bytes = get_data(cur_addr, 8);
        if (qword_bytes.size() < 8)
        {
            return {std::nullopt, cur_addr};
        }

        uint64_t qword = 0;
        for (int i = 0; i < 8; ++i)
        {
            qword |= static_cast<uint64_t>(qword_bytes[i]) << (i * 8);
        }

        if (qword != 0)
        {
            return {qword, cur_addr + 8};
        }
        
        cur_addr += 8;
        iterations++;
    }

    return {std::nullopt, cur_addr};
}

std::pair<std::optional<std::string>, uint32_t> PEAnalyzer::read_aligned_utf8_string(uint32_t addr)
{
    auto [string_addr, next_addr] = read_aligned_qword(addr);
    if (!string_addr)
    {
        return {std::nullopt, next_addr};
    }

    uint32_t rva = *string_addr - image_base;
    std::string function_name = read_utf8_string(rva);

    if (function_name.empty())
    {
        return {std::nullopt, next_addr};
    }

    return {function_name, next_addr};
}

std::vector<ServiceInfo> PEAnalyzer::scan_services()
{
    std::vector<ServiceInfo> services;

    // Get section ranges
    auto rdata_range = get_section_range_rva(".rdata");
    auto text_range = get_section_range_rva(".text");
    auto data_range = get_section_range_rva(".data");

    if (!rdata_range || !text_range || !data_range)
    {
        std::cout << "[error] Required sections not found" << std::endl;
        std::cout << "[debug] .rdata: " << (rdata_range ? "found" : "not found") << std::endl;
        std::cout << "[debug] .text: " << (text_range ? "found" : "not found") << std::endl;
        std::cout << "[debug] .data: " << (data_range ? "found" : "not found") << std::endl;
        return services;
    }

    // Search for QQNT string
    std::vector<uint8_t> qqnt_pattern = {0x00, 'Q', 'Q', 'N', 'T', 0x00};
    auto offset_qqnt_base = search_bytes(rdata_range->start, rdata_range->end, qqnt_pattern);
    if (!offset_qqnt_base)
    {
        std::cout << "[result] QQNT string not found" << std::endl;
        return services;
    }

    *offset_qqnt_base += 1; // Skip the leading null byte
    std::cout << "[debug] offset_qqnt_base: 0x" << std::hex << *offset_qqnt_base << std::dec << std::endl;

    // Find vtable reference
    uint64_t address_qqnt_base = *offset_qqnt_base + image_base;
    std::vector<uint8_t> qqnt_addr_bytes(8);
    for (int i = 0; i < 8; ++i)
    {
        qqnt_addr_bytes[i] = (address_qqnt_base >> (i * 8)) & 0xFF;
    }

    auto offset_db_qqnt_service = search_bytes(data_range->start, data_range->end, qqnt_addr_bytes);
    if (!offset_db_qqnt_service)
    {
        std::cout << "[result] QQNT service table not found" << std::endl;
        return services;
    }

    *offset_db_qqnt_service -= 8; // Go back 8 bytes
    std::cout << "[debug] offset_db_qqnt_service: 0x" << std::hex << *offset_db_qqnt_service << std::dec << std::endl;

    // Get service registration function
    auto service_func_bytes = get_data(*offset_db_qqnt_service, 8);
    if (service_func_bytes.size() < 8)
    {
        std::cout << "[error] Failed to read service function address" << std::endl;
        return services;
    }

    uint64_t service_func_addr = 0;
    for (int i = 0; i < 8; ++i)
    {
        service_func_addr |= static_cast<uint64_t>(service_func_bytes[i]) << (i * 8);
    }

    uint32_t offset_qqnt_service = service_func_addr - image_base;
    std::cout << "[debug] offset_qqnt_service: 0x" << std::hex << offset_qqnt_service << std::dec << std::endl;

    // Find all service register calls
    auto service_registers = find_service_register_calls(offset_qqnt_service);

    if (service_registers.empty())
    {
        std::cout << "[result] No matching call found" << std::endl;
        return services;
    }

    // Process each service
    for (auto service_register : service_registers)
    {
        auto [vtable_address, service_name_addr, descriptor_size] =
            extract_service_info(service_register - image_base);

        if (vtable_address && service_name_addr)
        {
            ServiceInfo service_info;

            uint32_t service_name_rva = *service_name_addr - image_base;
            service_info.service_name = read_utf8_string(service_name_rva);
            service_info.vtable_address = *vtable_address;
            service_info.descriptor_size = descriptor_size ? *descriptor_size : 16 * 8; // default 16 properties

            std::cout << "[result] service_name: " << service_info.service_name << std::endl;
            std::cout << "[result] vtable_address: 0x" << std::hex << service_info.vtable_address << std::dec << std::endl;
            std::cout << "[result] descriptor_size: 0x" << std::hex << service_info.descriptor_size << std::dec;
            if (!descriptor_size)
            {
                std::cout << " (default)";
            }
            std::cout << std::endl;

            // Parse method table
            uint32_t cur_addr = *vtable_address - image_base;
            while (true)
            {
                try
                {
                    auto [function_name, next_addr1] = read_aligned_utf8_string(cur_addr);
                    cur_addr = next_addr1;

                    auto [function_addr, next_addr2] = read_aligned_qword(cur_addr);
                    cur_addr = next_addr2;

                    if (!function_addr)
                    {
                        break;
                    }

                    // Check if function address is in text section
                    uint32_t func_rva = *function_addr - image_base;
                    if (func_rva < text_range->start || func_rva >= text_range->end)
                    {
                        break;
                    }

                    // Check descriptor size limit
                    if (service_info.descriptor_size &&
                        service_info.vtable_address + service_info.descriptor_size < cur_addr + image_base)
                    {
                        break;
                    }

                    if (function_name && function_name->length() > 1 &&
                        function_name->find('@') == std::string::npos &&
                        function_name->find('$') == std::string::npos)
                    {
                        service_info.methods.emplace_back(*function_name, *function_addr);
                        std::cout << "Service: " << service_info.service_name
                                  << " Name: " << *function_name
                                  << " Addr: 0x" << std::hex << *function_addr << std::dec << std::endl;
                    }
                }
                catch (const std::exception &e)
                {
                    std::cout << "[error] Exception while parsing method table: " << e.what() << std::endl;
                    break;
                }
            }

            services.push_back(std::move(service_info));
        }
    }

    return services;
}