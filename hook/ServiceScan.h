#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <optional>
#include "capstone/capstone.h"

struct SectionRange {
    uint32_t start;
    uint32_t end;
};

struct ServiceInfo {
    std::string service_name;
    uint64_t vtable_address;
    uint32_t descriptor_size;
    std::vector<std::pair<std::string, uint64_t>> methods;
};

class PEAnalyzer {
private:
    std::vector<uint8_t> pe_data;
    uint64_t image_base;
    csh capstone_handle;
    
    // PE Header structures
    struct DOSHeader {
        uint16_t e_magic;
        uint8_t padding[58];
        uint32_t e_lfanew;
    };
    
    struct NTHeaders {
        uint32_t signature;
        uint16_t machine;
        uint16_t number_of_sections;
        uint32_t time_date_stamp;
        uint32_t pointer_to_symbol_table;
        uint32_t number_of_symbols;
        uint16_t size_of_optional_header;
        uint16_t characteristics;
    };
    
    struct OptionalHeader {
        uint16_t magic;
        uint8_t major_linker_version;
        uint8_t minor_linker_version;
        uint32_t size_of_code;
        uint32_t size_of_initialized_data;
        uint32_t size_of_uninitialized_data;
        uint32_t address_of_entry_point;
        uint32_t base_of_code;
        uint64_t image_base;
        uint32_t section_alignment;
        uint32_t file_alignment;
        uint16_t major_operating_system_version;
        uint16_t minor_operating_system_version;
        uint16_t major_image_version;
        uint16_t minor_image_version;
        uint16_t major_subsystem_version;
        uint16_t minor_subsystem_version;
        uint32_t win32_version_value;
        uint32_t size_of_image;
        uint32_t size_of_headers;
        uint32_t checksum;
        uint16_t subsystem;
        uint16_t dll_characteristics;
    };
    
    struct SectionHeader {
        char name[8];
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
        uint32_t pointer_to_relocations;
        uint32_t pointer_to_line_numbers;
        uint16_t number_of_relocations;
        uint16_t number_of_line_numbers;
        uint32_t characteristics;
    };

public:
    explicit PEAnalyzer(const std::string& filename);
    ~PEAnalyzer();
    
    bool load_file(const std::string& filename);
    std::optional<SectionRange> get_section_range_rva(const std::string& section_name);
    std::optional<uint32_t> search_bytes(uint32_t start, uint32_t end, const std::vector<uint8_t>& pattern);
    std::vector<uint32_t> search_bytes_all(uint32_t start, uint32_t end, const std::vector<uint8_t>& pattern);
    std::vector<uint8_t> get_data(uint32_t rva, uint32_t size);
    std::string read_utf8_string(uint32_t rva);
    std::vector<uint64_t> find_service_register_calls(uint32_t offset_qqnt_service, uint32_t max_bytes = 1024);
    std::tuple<std::optional<uint64_t>, std::optional<uint64_t>, std::optional<uint32_t>> 
        extract_service_info(uint32_t func_rva, uint32_t max_bytes = 512);
    std::pair<std::optional<uint64_t>, uint32_t> read_aligned_qword(uint32_t addr);
    std::pair<std::optional<std::string>, uint32_t> read_aligned_utf8_string(uint32_t addr);
    
    uint64_t get_image_base() const { return image_base; }
    std::vector<ServiceInfo> scan_services();
};
