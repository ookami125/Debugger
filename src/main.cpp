#include "file.h"
#include "buffer_reader.h"

#include <stdint.h>
#include <vector>
#include <bit>
#include <cstring>

struct Elf;

struct ELFSectionHeader {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;

    std::string getName(const Elf* elf) const;
};

ErrorOr<std::vector<ELFSectionHeader>> ParseElfSectionHeaders(BufferReader& sectionHeaderTableReader, size_t shNum) {
    std::vector<ELFSectionHeader> sectionHeaders;
    for(size_t ndx = 0; ndx < shNum; ndx++) {
        ELFSectionHeader header;
        header.sh_name = TRY(sectionHeaderTableReader.Read<uint32_t>());
        header.sh_type = TRY(sectionHeaderTableReader.Read<uint32_t>());
        header.sh_flags = TRY(sectionHeaderTableReader.Read<uint64_t>());
        header.sh_addr = TRY(sectionHeaderTableReader.Read<uint64_t>());
        header.sh_offset = TRY(sectionHeaderTableReader.Read<uint64_t>());
        header.sh_size = TRY(sectionHeaderTableReader.Read<uint64_t>());
        header.sh_link = TRY(sectionHeaderTableReader.Read<uint32_t>());
        header.sh_info = TRY(sectionHeaderTableReader.Read<uint32_t>());
        header.sh_addralign = TRY(sectionHeaderTableReader.Read<uint64_t>());
        header.sh_entsize = TRY(sectionHeaderTableReader.Read<uint64_t>());

        sectionHeaders.push_back(header);
    }
    return sectionHeaders;
}

typedef uint64_t	Elf64_Addr;
typedef uint16_t	Elf64_Half;
typedef uint64_t	Elf64_Off;
typedef int32_t		Elf64_Sword;
typedef int64_t		Elf64_Sxword;
typedef uint32_t	Elf64_Word;
typedef uint64_t	Elf64_Lword;
typedef uint64_t	Elf64_Xword;

struct Elf {
    uint8_t* data;
    size_t length;

    unsigned char e_ident[16];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;

    std::vector<ELFSectionHeader> sectionHeaders;

    ErrorOr<size_t> getSectionID(std::string name) const {
        auto sectionNames = sectionHeaders[e_shstrndx];
        auto start = sectionNames.sh_offset;
        auto end = start + sectionNames.sh_size;
        auto sectionNamesBuf = (char*)&data[start];

        for(int i=0; i<e_shnum; ++i) {
            auto& header = sectionHeaders[i];
            std::string sectionName(&sectionNamesBuf[header.sh_name]);
            if(name == header.getName(this)) {
                return i;
            }
        }
        return Error{"No section with name \""+name+"\""};
    };
};

ErrorOr<Elf> ParseElf(const char* data, size_t len) {
    BufferReader elfReader((const uint8_t*)data, len);
    if(memcmp(data, "\x7F" "ELF", 4) != 0) {
        return Error{"Not an elf file!"};
    }

    Elf elf = {};
    
    elf.data = (uint8_t*)data;
    elf.length = len;

    memcpy(elf.e_ident, TRY(elfReader.ReadRaw(16)), 16);
    elf.e_type = TRY(elfReader.Read<Elf64_Half>());
    elf.e_machine = TRY(elfReader.Read<Elf64_Half>());
    elf.e_version = TRY(elfReader.Read<Elf64_Word>());
    elf.e_entry = TRY(elfReader.Read<Elf64_Addr>());
    elf.e_phoff = TRY(elfReader.Read<Elf64_Off>());
    elf.e_shoff = TRY(elfReader.Read<Elf64_Off>());
    elf.e_flags = TRY(elfReader.Read<Elf64_Word>());
    elf.e_ehsize = TRY(elfReader.Read<Elf64_Half>());
    elf.e_phentsize = TRY(elfReader.Read<Elf64_Half>());
    elf.e_phnum = TRY(elfReader.Read<Elf64_Half>());
    elf.e_shentsize = TRY(elfReader.Read<Elf64_Half>());
    elf.e_shnum = TRY(elfReader.Read<Elf64_Half>());
    elf.e_shstrndx = TRY(elfReader.Read<Elf64_Half>());

    BufferReader sectionHeaderReader((uint8_t*)data + elf.e_shoff, elf.e_shentsize * elf.e_shnum);
    elf.sectionHeaders = TRY(ParseElfSectionHeaders(sectionHeaderReader, elf.e_shnum));

    return elf;
}

std::string ELFSectionHeader::getName(const Elf* elf) const {
    auto sectionNames = elf->sectionHeaders[elf->e_shstrndx];
    auto start = sectionNames.sh_offset;
    auto end = start + sectionNames.sh_size;
    auto sectionNamesBuf = (char*)&elf->data[start];
    const char* name = &sectionNamesBuf[sh_name];
    size_t name_len = strlen(name);
    return std::string(name, name_len);
};


enum DwarfContent {
    DW_LNCT_path = 0x1,
    DW_LNCT_directory_index = 0x2,
    DW_LNCT_timestamp = 0x3,
    DW_LNCT_size = 0x4,
    DW_LNCT_MD5 = 0x5,
};

enum DwarfForm {
    DW_FORM_addr = 0x01,
    DW_FORM_block2 = 0x03,
    DW_FORM_block4 = 0x04,
    DW_FORM_data2 = 0x05,
    DW_FORM_data4 = 0x06,
    DW_FORM_data8 = 0x07,
    DW_FORM_string = 0x08,
    DW_FORM_block = 0x09,
    DW_FORM_block1 = 0x0A,
    DW_FORM_data1 = 0x0B,
    DW_FORM_flag = 0x0C,
    DW_FORM_sdata = 0x0D,
    DW_FORM_strp = 0x0E,
    DW_FORM_udata = 0x0F,
    DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1 = 0x11,
    DW_FORM_ref2 = 0x12,
    DW_FORM_ref4 = 0x13,
    DW_FORM_ref8 = 0x14,
    DW_FORM_ref_udata = 0x15,
    DW_FORM_indirect = 0x16,
    DW_FORM_sec_offset = 0x17,
    DW_FORM_exprloc = 0x18,
    DW_FORM_flag_present = 0x19,
    DW_FORM_strx = 0x1A,
    DW_FORM_addrx = 0x1B,
    DW_FORM_ref_sup4 = 0x1C,
    DW_FORM_strp_sup = 0x1D,
    DW_FORM_data16 = 0x1E,
    DW_FORM_line_strp = 0x1F,
    DW_FORM_ref_sig8 = 0x20,
    DW_FORM_implicit_const = 0x21,
    DW_FORM_loclistx = 0x22,
    DW_FORM_rnglistx = 0x23,
    DW_FORM_ref_sup8 = 0x24,
    DW_FORM_strx1 = 0x25,
    DW_FORM_strx2 = 0x26,
    DW_FORM_strx3 = 0x27,
    DW_FORM_strx4 = 0x28,
    DW_FORM_addrx1 = 0x29,
    DW_FORM_addrx2 = 0x2A,
    DW_FORM_addrx3 = 0x2B,
    DW_FORM_addrx4 = 0x2C,
};

struct DwarfContentForm {
    DwarfContent content;
    DwarfForm form;
};

union DwarfData {
    const char* str;
    uint64_t u64;
};

struct DwarfUnstructuredType {
    std::vector<DwarfContentForm> structure;
    std::vector<DwarfData> data;

    ErrorOr<std::pair<DwarfForm, DwarfData*>> getData(DwarfContent content) {
        int i=0;
        for(auto field : structure) {
            if(field.content == content) {
                return std::pair<DwarfForm, DwarfData*>{
                    field.form,
                    &data[i],
                };
            }
            i++;
        }
        return Error{ "DwarfUnstructuredType doesn't contain content: " + std::to_string(content) };
    }
};

struct DwarfInfo {
    uint64_t unit_length;
    bool dwarf64;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint64_t header_length;
    uint8_t min_instruction_length;
    uint8_t max_ops_per_instruction;
    uint8_t default_is_stmt;
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    uint8_t* std_opcode_lengths;
    std::vector<DwarfUnstructuredType> directories;
    std::vector<DwarfUnstructuredType> file_names;
};

enum DW_LN_opcode : uint8_t {
    DW_LNS_extended = 0x0,
    DW_LNS_copy = 0x1,
    DW_LNS_advance_pc,
    DW_LNS_advance_line,
    DW_LNS_set_file,
    DW_LNS_set_column,
    DW_LNS_negate_stmt,
    DW_LNS_set_basic_block,
    DW_LNS_const_add_pc,
    DW_LNS_fixed_advance_pc,
    DW_LNS_set_prologue_end,
    DW_LNS_set_epilogue_begin,
    DW_LNS_set_isa,
};

enum DW_LNE_opcode : uint8_t {
    DW_LNE_end_sequence = 0x1,
    DW_LNE_set_address = 0x2,
    DW_LNE_set_discriminator = 0x4,
};

struct LNMatrixRow{
    uint64_t address;
    uint64_t file;
    uint64_t line;
    uint64_t column;
    uint64_t isa;
    uint64_t discriminator;
    uint64_t opIndex;
    uint64_t flags;
};

ErrorOr<std::vector<LNMatrixRow>> LineNumberVM(DwarfInfo info, BufferReader lineReader)
{
    uint64_t address_register = 0;
    uint64_t op_index_register = 0;
    uint64_t file_register = 1;
    uint64_t line_register = 1;
    uint64_t column_register = 0;
    uint64_t is_stmt_register = info.default_is_stmt;
    bool basic_block = false;
    bool end_sequence = false;
    bool prologue_end = false;
    bool epilogue_begin = false;
    uint64_t isa_register = 0;
    uint64_t discriminator_register = 0;

    std::vector<LNMatrixRow> matrix;

    //Parse OpCode
    while(lineReader.len > lineReader.pos) {
        DW_LN_opcode opcode = TRY(lineReader.Read<DW_LN_opcode>());
        switch(opcode) {
            case DW_LNS_copy: {
                matrix.push_back(LNMatrixRow{
                    address_register,
                    file_register,
                    line_register,
                    column_register,
                    isa_register,
                    discriminator_register,
                    op_index_register,
                    0
                });
                discriminator_register = 0;
                basic_block = false;
                prologue_end = false;
                epilogue_begin = false;
            } break;
            case DW_LNS_advance_pc: {
                uint64_t operation_advance = TRY(lineReader.parseLEB128<int64_t>());
                auto new_address = address_register +
                    info.min_instruction_length *
                    ((op_index_register + operation_advance) / info.max_ops_per_instruction);
                auto new_op_index =
                    (op_index_register + operation_advance) % info.max_ops_per_instruction;
                address_register = new_address;
                op_index_register = new_op_index;
            } break;
            case DW_LNS_advance_line: {
                auto temp = TRY(lineReader.parseLEB128<int64_t>());
                line_register += temp;
            } break;
            case DW_LNS_set_file: {
                file_register = TRY(lineReader.parseLEB128<int64_t>());
            } break;
            case DW_LNS_set_column: {
                column_register = TRY(lineReader.parseLEB128<int64_t>());
            } break;
            case DW_LNS_negate_stmt: {
                is_stmt_register = !is_stmt_register;
            } break;
            case DW_LNS_const_add_pc: {
                auto adjusted_opcode = 255 - info.opcode_base;
                auto operation_advance = adjusted_opcode / info.line_range;
                auto new_address = address_register +
                    info.min_instruction_length *
                    ((op_index_register + operation_advance) / info.max_ops_per_instruction);
                auto new_op_index =
                    (op_index_register + operation_advance) % info.max_ops_per_instruction;
                address_register = new_address;
                op_index_register = new_op_index;
            } break;
            case DW_LNS_extended: {
                uint64_t ext_opcode_len = TRY(lineReader.parseULEB128<uint64_t>());
                DW_LNE_opcode ext_opcode = TRY(lineReader.Read<DW_LNE_opcode>());
                switch(ext_opcode) {
                    case DW_LNE_end_sequence: {
                        end_sequence = true;
                        matrix.push_back(LNMatrixRow{
                            address_register,
                            file_register,
                            line_register,
                            column_register,
                            isa_register,
                            discriminator_register,
                            op_index_register,
                            0
                        });
                        address_register = 0;
                        op_index_register = 0;
                        file_register = 1;
                        line_register = 1;
                        column_register = 0;
                        is_stmt_register = info.default_is_stmt;
                        basic_block = false;
                        end_sequence = false;
                        prologue_end = false;
                        epilogue_begin = false;
                        isa_register = 0;
                        discriminator_register = 0;
                    } break;
                    case DW_LNE_set_address: {
                        address_register = TRY(lineReader.ReadVarInt<uint64_t>(info.address_size));
                        op_index_register = 0;
                    }break;
                    case DW_LNE_set_discriminator: {
                        discriminator_register = TRY(lineReader.parseULEB128<uint64_t>());
                    }break;
                    default: 
                        return Error{ "Unimplemented opcode: " + std::to_string(opcode) + " [" + std::to_string(ext_opcode) + "]" };
                }
            }break;
            default: {
                if(opcode < info.opcode_base)
                    return Error{ "Unimplemented opcode: " + std::to_string(opcode) };
                auto adjusted_opcode = opcode - info.opcode_base;
                auto operation_advance = adjusted_opcode / info.line_range;
                auto new_address = address_register +
                    info.min_instruction_length *
                    ((op_index_register + operation_advance) / info.max_ops_per_instruction);
                auto new_op_index =
                    (op_index_register + operation_advance) % info.max_ops_per_instruction;
                auto line_increment = info.line_base + (adjusted_opcode % info.line_range);
                address_register = new_address;
                op_index_register = new_op_index;
                line_register += line_increment;
                matrix.push_back(LNMatrixRow{
                    address_register,
                    file_register,
                    line_register,
                    column_register,
                    isa_register,
                    discriminator_register,
                    op_index_register,
                    0
                });
            }
        }
    }
    return matrix;
}

ErrorOr<DwarfInfo> ParseDwarfInfo(const Elf* elf, const uint8_t* data, size_t size) {
    
    BufferReader sectionReader((const uint8_t*)data, size);
    DwarfInfo dwarf = {};
    
    dwarf.unit_length = TRY(sectionReader.Read<uint32_t>());
    
    BufferReader dwarfReader(sectionReader.start + sectionReader.pos, dwarf.unit_length);
    
    dwarf.dwarf64 = (dwarf.unit_length == 0xffffffff);
    if(dwarf.dwarf64) {
        dwarf.unit_length = TRY(dwarfReader.Read<uint64_t>());
    }
    
    dwarf.version = TRY(dwarfReader.Read<uint16_t>());
    if(dwarf.version != 5) return Error{ "Dwarf format " + std::to_string(dwarf.version) + " not supported!" };
    dwarf.address_size = TRY(dwarfReader.Read<uint8_t>());
    dwarf.segment_selector_size = TRY(dwarfReader.Read<uint8_t>());
    if(dwarf.dwarf64) {
        dwarf.header_length = TRY(dwarfReader.Read<uint64_t>());
    } else {
        dwarf.header_length = TRY(dwarfReader.Read<uint32_t>());
    }
    dwarf.min_instruction_length = TRY(dwarfReader.Read<uint8_t>());
    dwarf.max_ops_per_instruction = TRY(dwarfReader.Read<uint8_t>());
    dwarf.default_is_stmt = TRY(dwarfReader.Read<uint8_t>());
    dwarf.line_base = TRY(dwarfReader.Read<int8_t>());
    dwarf.line_range = TRY(dwarfReader.Read<uint8_t>());
    dwarf.opcode_base = TRY(dwarfReader.Read<uint8_t>());
    dwarf.std_opcode_lengths = (uint8_t*)malloc(dwarf.opcode_base-1);
    for(int i=0; i<dwarf.opcode_base-1; i++) {
        dwarf.std_opcode_lengths[i] = TRY(dwarfReader.Read<uint8_t>());
    }

    uint8_t directory_entry_format_count = TRY(dwarfReader.Read<uint8_t>());
    std::vector<DwarfContentForm> directory_entry_format;
    for(int i=0; i<directory_entry_format_count; ++i) {
        DwarfContent content_type = (DwarfContent)TRY(dwarfReader.parseULEB128<uint64_t>());
        DwarfForm form_code = (DwarfForm)TRY(dwarfReader.parseULEB128<uint64_t>());
        directory_entry_format.push_back(DwarfContentForm{
            content_type,
            form_code
        });
    }

    uint64_t directories_count = TRY(dwarfReader.parseULEB128<uint64_t>());

    char* debug_line_str = nullptr;
    for(int i=0; i<directories_count; ++i) {
        std::vector<DwarfData> directory;
        for(auto field : directory_entry_format) {
            switch(field.form) {
                case DW_FORM_line_strp: {
                    if(debug_line_str == nullptr) {
                        auto header = elf->sectionHeaders[TRY(elf->getSectionID(".debug_line_str"))];
                        debug_line_str = (char*)(elf->data + header.sh_offset);
                    }
                    uint64_t offset;
                    if(dwarf.dwarf64) {
                        offset = TRY(dwarfReader.Read<uint64_t>());
                    } else {
                        offset = TRY(dwarfReader.Read<uint32_t>());
                    }
                    directory.push_back(DwarfData{
                        .str = (char*)debug_line_str + offset
                    });
                } break;
                default: return Error{ "field form " + std::to_string(field.form) + " not supported" };
            }
        }
        dwarf.directories.push_back(DwarfUnstructuredType{
            directory_entry_format,
            directory,
        });
    }

    uint8_t file_name_entry_format_count = TRY(dwarfReader.Read<uint8_t>());

    std::vector<DwarfContentForm> file_name_entry_format;
    for(int i=0; i<file_name_entry_format_count; ++i) {
        DwarfContent content_type = (DwarfContent)TRY(dwarfReader.parseULEB128<uint64_t>());
        DwarfForm form_code = (DwarfForm)TRY(dwarfReader.parseULEB128<uint64_t>());
        file_name_entry_format.push_back(DwarfContentForm{
            content_type,
            form_code
        });
    }

    uint64_t file_names_count = TRY(dwarfReader.parseULEB128<uint64_t>());

    for(int i=0; i<file_names_count; ++i) {
        std::vector<DwarfData> file_name;
        for(auto field : file_name_entry_format) {
            switch(field.form) {
                case DW_FORM_line_strp: {
                    if(debug_line_str == nullptr) {
                        auto header = elf->sectionHeaders[TRY(elf->getSectionID(".debug_line_str"))];
                        debug_line_str = (char*)(elf->data + header.sh_offset);
                    }
                    uint64_t offset;
                    if(dwarf.dwarf64) {
                        offset = TRY(dwarfReader.Read<uint64_t>());
                    } else {
                        offset = TRY(dwarfReader.Read<uint32_t>());
                    }
                    file_name.push_back(DwarfData{
                        .str = (char*)debug_line_str + offset,
                    });
                } break;
                case DW_FORM_udata: {
                    uint64_t offset = TRY(dwarfReader.parseULEB128<uint64_t>());
                    file_name.push_back(DwarfData{
                        .u64 = offset,
                    });
                } break;
                default: return Error{ "field form " + std::to_string(field.form) + " not supported" };
            }
        }
        dwarf.file_names.push_back({
            file_name_entry_format,
            file_name,
        });
    }

    std::vector<LNMatrixRow> matrix = TRY(LineNumberVM(dwarf, dwarfReader));

    for(auto row : matrix) {
        auto file_name = dwarf.file_names[row.file-1];
        printf(" - file: %s/%s line %d:%d -> 0x%llx\n",
            TRY(dwarf.directories[TRY(file_name.getData(DW_LNCT_directory_index)).second->u64].getData(DW_LNCT_path)).second->str,
            TRY(file_name.getData(DW_LNCT_path)).second->str,
            row.line, row.column, row.address
        );
    }

    printf("read %d bytes\n", dwarfReader.pos);
    return dwarf;
}

int main(int argc, char** argv) {
    if(argc < 2) {
        const char* filename = argc>0?argv[0]:"MyDebugger";
        printf("usage: %s <elf_file>\n", filename);
        return 1;
    }
    size_t length = 0;
    char* file = CATCH(readFile(argv[1], length), {
        printf("Error: %s\n", ev.error().msg.c_str());
        return 1;
    });
    Elf elf = CATCH(ParseElf(file, length), {
        printf("Error: %s\n", ev.error().msg.c_str());
        return 1;
    });
    
    printf("Elf file parsed:\n");
    printf(" - e_ident: %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n",
        elf.e_ident[0], elf.e_ident[1], elf.e_ident[2], elf.e_ident[3],
        elf.e_ident[4], elf.e_ident[5], elf.e_ident[6], elf.e_ident[7],
        elf.e_ident[8], elf.e_ident[9], elf.e_ident[10], elf.e_ident[11],
        elf.e_ident[12], elf.e_ident[13], elf.e_ident[14], elf.e_ident[15]);
    printf(" - e_type: %d\n", elf.e_type);
    printf(" - e_machine: %d\n", elf.e_machine);
    printf(" - e_version: %d\n", elf.e_version);
    printf(" - e_entry: %d\n", elf.e_entry);
    printf(" - e_phoff: %d\n", elf.e_phoff);
    printf(" - e_shoff: %d\n", elf.e_shoff);
    printf(" - e_flags: %d\n", elf.e_flags);
    printf(" - e_ehsize: %d\n", elf.e_ehsize);
    printf(" - e_phentsize: %d\n", elf.e_phentsize);
    printf(" - e_phnum: %d\n", elf.e_phnum);
    printf(" - e_shentsize: %d\n", elf.e_shentsize);
    printf(" - e_shnum: %d\n", elf.e_shnum);
    printf(" - e_shstrndx: %d\n", elf.e_shstrndx);

    auto debug_line_sec_id = CATCH(elf.getSectionID(".debug_line"), {
        printf("Error: %s\n", ev.error().msg.c_str());
        return 1;
    });
    auto sectionHeader = elf.sectionHeaders[debug_line_sec_id];
    {
        printf(" - Section Header:\n");
        printf("   - sh_name: %d (%s)\n", sectionHeader.sh_name, sectionHeader.getName(&elf).c_str());
        printf("   - sh_type: %d\n", sectionHeader.sh_type);
        printf("   - sh_flags: %d\n", sectionHeader.sh_flags);
        printf("   - sh_addr: %d\n", sectionHeader.sh_addr);
        printf("   - sh_offset: %d\n", sectionHeader.sh_offset);
        printf("   - sh_size: %d\n", sectionHeader.sh_size);
        printf("   - sh_link: %d\n", sectionHeader.sh_link);
        printf("   - sh_info: %d\n", sectionHeader.sh_info);
        printf("   - sh_addralign: %d\n", sectionHeader.sh_addralign);
        printf("   - sh_entsize: %d\n", sectionHeader.sh_entsize);

        // CATCH(writeFile("../../file.dwo", (const char*)elf.data + sectionHeader.sh_offset, sectionHeader.sh_size), {
        //     printf("Error: %s\n", ev.error().msg.c_str());
        //     return 1;
        // });
        
        uint8_t* dwarfData = elf.data + sectionHeader.sh_offset;
        size_t dwarfSize = sectionHeader.sh_size;

        DwarfInfo dwarf = CATCH(ParseDwarfInfo(&elf, dwarfData, dwarfSize), {
            printf("Error: %s\n", ev.error().msg.c_str());
            return 1;
        });

        // printf("Dwarf data parsed:\n");
        // printf(" - unit_length: %d\n", dwarf.unit_length);
        // printf(" - dwarf64: %d\n", dwarf.dwarf64);
        // printf(" - version: %d\n", dwarf.version);
        // printf(" - address_size: %d\n", dwarf.address_size);
        // printf(" - segment_selector_size: %d\n", dwarf.segment_selector_size);
        // printf(" - header_length: %d\n", dwarf.header_length);
        // printf(" - min_instruction_length: %d\n", dwarf.min_instruction_length);
        // printf(" - max_ops_per_instruction: %d\n", dwarf.max_ops_per_instruction);
        // printf(" - default_is_stmt: %d\n", dwarf.default_is_stmt);
        // printf(" - line_base: %d\n", dwarf.line_base);
        // printf(" - line_range: %d\n", dwarf.line_range);
        // printf(" - opcode_base: %d\n", dwarf.opcode_base);
        // printf(" - std_opcode_lengths:\n");
        // for(int i=0; i<((int)dwarf.opcode_base)-1; ++i) {
        //     printf("   - Opcode %d has %d args\n", i+1, dwarf.std_opcode_lengths[i]);
        // }
        // printf(" - directories:\n");
        // for(auto directory : dwarf.directories) {
        //     printf("   - path: %s\n", CATCH(directory.getData(DW_LNCT_path), {
        //         printf("Error: %s\n", ev.error().msg.c_str());
        //         return 1;
        //     }).second->str);
        // }
        // printf(" - file_names:\n");
        // for(auto file_name : dwarf.file_names) {
        //     printf("   - path: %s/%s\n",
        //         CATCH(dwarf.directories[CATCH(file_name.getData(DW_LNCT_directory_index), {
        //             printf("Error: %s\n", ev.error().msg.c_str());
        //             return 1;
        //         }).second->u64].getData(DW_LNCT_path), {
        //             printf("Error: %s\n", ev.error().msg.c_str());
        //             return 1;
        //         }).second->str,
        //         CATCH(file_name.getData(DW_LNCT_path), {
        //             printf("Error: %s\n", ev.error().msg.c_str());
        //             return 1;
        //         }).second->str
        //     );
        // }
    }

    return 0;
}