#ifndef EMUL_CODE
#define EMUL_CODE 1
#define EMUL_IMP_VMP 150
#define EMUL_IMP_THEMIDA 250
#include "struct.h"

#include  "unicore_util.h"

#define ALIGN_DOWN(length, alig_size) \
    ((ULONG_PTR)(length) & ~(alig_size - 1))

#define ALIGN_UP(length, alig_size) \
    (ALIGN_DOWN(((ULONG_PTR)(length) + alig_size - 1), alig_size))


namespace emul_code
{
    NO_INLINE auto prutforce_command(PIMP_EMUL_INFO emul_info, size_t crypted_value, size_t reg_rva, size_t reg_base) -> BOOLEAN
    {
        uint32_t id_command_xor = INT_MAX;
        TYPE_OBF_COMMAND command_manual[] = {obf_sub, obf_xor, obf_and, obf_xor};
        for (size_t i = NULL; i < emul_info->count_command; i++)
        {
            if (emul_info->command[i].type == obf_xor && (emul_info->command[i].reg_value ^ emul_info->command[i].imm) == emul_info->imm_dump[2])
            {
                emul_info->imm_dump[1] = emul_info->command[i].imm;
                id_command_xor = i;
                emul_info->imm_dump[NULL] =  (uint32_t)crypted_value - (uint32_t)emul_info->command[i].reg_value;
                //printf("crypted_value ->\t%p\n", crypted_value);
                //printf("xor key ->\t%p\n", emul_info->imm_dump[1]);
                //printf("sub key ->\t%p\n", emul_info->imm_dump[NULL]);
                //printf("1 ->\t%p\n", (((crypted_value >> 0x20) ^ emul_info->imm_dump[3]) << 0x20) == reg_base);
                //printf("2 ->\t%p\n", (((crypted_value - emul_info->imm_dump[NULL]) ^ emul_info->imm_dump[1]) & UINT_MAX) == reg_rva);

                if (
                    (((crypted_value >> 0x20) ^ emul_info->imm_dump[3]) << 0x20) == reg_base &&
                    (((crypted_value - emul_info->imm_dump[NULL]) ^ emul_info->imm_dump[1]) & UINT_MAX) == reg_rva
                    )
                { 

                    emul_info->obf_imp_info->command[NULL].imm = emul_info->imm_dump[NULL];
                    emul_info->obf_imp_info->command[NULL].type = obf_sub;

                    emul_info->obf_imp_info->command[1].imm = emul_info->imm_dump[1];
                    emul_info->obf_imp_info->command[1].type = obf_xor;

                    emul_info->obf_imp_info->command[2].imm = emul_info->imm_dump[3];
                    emul_info->obf_imp_info->command[2].type = obf_xor;

                    emul_info->obf_imp_info->count_command = 3;
                    return TRUE;
                }
            }
         }
        return FALSE;
    }

    NO_INLINE auto get_imp_name(proc_info* proc_inform, uint8_t* addr, WCHAR** mod_name, CHAR** imp_name) -> BOOLEAN
    {
        uint32_t api_rva = NULL;

        PIMAGE_DOS_HEADER dos_head = NULL;
        PIMAGE_NT_HEADERS nt_head = NULL;
        PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

        for (size_t i = NULL; i < proc_inform->mod_list.size(); i++)
        {
            if (
                proc_inform->mod_list[i].orig_addr_mem != proc_inform->orig_addr_mem &&
                proc_inform->mod_list[i].is_any_export
                )
            {
                if (
                    addr >= proc_inform->mod_list[i].orig_addr_mem &&
                    proc_inform->mod_list[i].orig_addr_mem + proc_inform->mod_list[i].coped_size >= addr
                    )
                {
                    api_rva = addr - proc_inform->mod_list[i].orig_addr_mem;

                    if (mod_name)
                    {
                        *mod_name = (WCHAR*)proc_inform->mod_list[i].mod_name.c_str();
                    }
                    dos_head = reinterpret_cast<PIMAGE_DOS_HEADER>(proc_inform->mod_list[i].coped_mem);
                    if (dos_head->e_magic == IMAGE_DOS_SIGNATURE)
                    {
                        nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(proc_inform->mod_list[i].coped_mem + dos_head->e_lfanew);
                        export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(proc_inform->mod_list[i].coped_mem + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                        if (nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && export_dir)
                        {
                            auto names = (PDWORD)(proc_inform->mod_list[i].coped_mem + export_dir->AddressOfNames);
                            auto ordinals = (PWORD)(proc_inform->mod_list[i].coped_mem + export_dir->AddressOfNameOrdinals);
                            auto functions = (PDWORD)(proc_inform->mod_list[i].coped_mem + export_dir->AddressOfFunctions);

                            for (uint32_t j = NULL; j < export_dir->NumberOfFunctions; ++j)
                            {
                                if (functions[ordinals[j]] == api_rva)
                                {
                                    if (imp_name)
                                    {
                                        *imp_name = reinterpret_cast<CHAR*>(proc_inform->mod_list[i].coped_mem) + names[j];
                                    }
                                    return TRUE;
                                }
                            }
                        }
                    }
                }
            }
        }
        return FALSE;
    }

    NO_INLINE auto unmap_code(uc_engine* uc, std::vector<UC_MAP_CODE>& maped_code) -> VOID
    {
        for (size_t i = NULL; i < maped_code.size(); i++)
        {
            uc_mem_unmap(uc, maped_code[i].addr, maped_code[i].size_code);
        }
        maped_code.clear();

    }

    // callback for tracing instruction
    NO_INLINE void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
    {
        uc_err err;
        uint64_t r_reg[2] = { NULL };
        uint64_t r_rsp = NULL;

        size_t vip_cur_pointer = NULL;
        size_t imp_addr_pos = NULL;
        size_t key_crypt = NULL;
        size_t index_reg_value = NULL; 
        size_t reg_value[5] = { NULL };
        uint8_t  opcode_instr[MAX_LENGHT_INSTR];
        PIMP_EMUL_INFO emul_info = NULL;
        WCHAR* mod_name = NULL;
        CHAR* imp_name = NULL;
        ZydisDisassembledInstruction dis_instr = { NULL };
        emul_info = reinterpret_cast<PIMP_EMUL_INFO>(user_data);

        emul_info->emul_count++;


        err = uc_reg_read(uc, REG_VIP, &vip_cur_pointer);
        memset(&opcode_instr, NULL, sizeof(opcode_instr));

        if (err == UC_ERR_OK && vip_cur_pointer && uc_mem_read(uc, vip_cur_pointer, opcode_instr, sizeof(opcode_instr)) == UC_ERR_OK)
        {

            if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, opcode_instr)))
            { 
                if (emul_info->proc_information->prot_type == prot_vmp)
                { 
                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        (
                            dis_instr.operands[NULL].reg.value == dis_instr.operands[1].mem.base ||
                            dis_instr.operands[NULL].reg.value == dis_instr.operands[1].mem.index
                            )
                        )
                    {

                        unicore_util::read_reg(uc, &dis_instr.operands[1].mem.base, &imp_addr_pos);
                        //printf("reg value ->\t%p\n", imp_addr_pos);

                        if (dis_instr.operands[1].mem.index != ZYDIS_REGISTER_NONE)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].mem.index, &index_reg_value);
                            // printf("reg value 2 ->\t%p\n", index_reg_value);
                             //printf("scale value ->\t%p\n", dis_instr.operands[1].mem.scale);

                            if (dis_instr.operands[1].mem.scale)
                            {
                                index_reg_value = index_reg_value * dis_instr.operands[1].mem.scale;
                            }
                            key_crypt = index_reg_value;
                            imp_addr_pos = imp_addr_pos + index_reg_value;
                        }
                        if (dis_instr.operands[1].mem.disp.has_displacement)
                        {
                            key_crypt += dis_instr.operands[1].mem.disp.value;
                            imp_addr_pos += dis_instr.operands[1].mem.disp.value;
                        }
                        if (get_imp_name(emul_info->proc_information, reinterpret_cast<uint8_t*>(imp_addr_pos), &mod_name, &imp_name))
                        {
                            emul_info->obf_imp_info->is_get_imp = TRUE;
                            emul_info->obf_imp_info->mod_name = mod_name;
                            emul_info->obf_imp_info->imp_name = imp_name;
                            emul_info->obf_imp_info->count_command++;
                            emul_info->obf_imp_info->command[NULL].type = obf_lea;
                            emul_info->obf_imp_info->command[NULL].imm = key_crypt;

                            emul_info->obf_imp_info->imp_obf_ptr_rva = emul_info->obf_imp_info->imp_obf_ptr_addr - emul_info->cur_mod_addr;
                            uc_emu_stop(uc);
                        }
                    }
                }

                if (emul_info->proc_information->prot_type == prot_themida)
                {
#ifndef _WIN64
                    if (
                        (
                            dis_instr.info.mnemonic == ZYDIS_MNEMONIC_ADD ||
                            dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SUB
                            )
                        &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                            dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            )
                        )
                    {
                        if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[1]);
                        }
                        else if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            reg_value[1] = dis_instr.operands[1].imm.value.u;
                        }
                        if (
                            dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_RSP &&
                            dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_ESP
                            )
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[NULL]);

                            emul_info->command[emul_info->count_command].imm = reg_value[1];
                            emul_info->command[emul_info->count_command].reg_value = reg_value[NULL];

                            if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_ADD)
                            {
                                emul_info->command[emul_info->count_command].type = obf_add;
                            }
                            else if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SUB)
                            {
                                emul_info->command[emul_info->count_command].type = obf_sub;
                            }
                            emul_info->count_command++;
                        }
                    }

                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_XOR &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                            dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            )
                        )
                    {
                        if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[1]);
                        }
                        else if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            reg_value[1] = dis_instr.operands[1].imm.value.u;
                        }
                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[NULL]);

                        imp_addr_pos = reg_value[NULL] ^ reg_value[1];

                        if (get_imp_name(emul_info->proc_information, reinterpret_cast<uint8_t*>(imp_addr_pos), &mod_name, &imp_name))
                        {
                            emul_info->obf_imp_info->is_get_imp = TRUE;
                            emul_info->obf_imp_info->mod_name = mod_name;
                            emul_info->obf_imp_info->imp_name = imp_name;

                            uc_mem_read(uc, emul_info->obf_imp_info->imp_obf_ptr_addr, &reg_value[2], sizeof(reg_value[2]));
                            reg_value[3] = reg_value[2] - reg_value[NULL];//get lazy sub key

                            emul_info->obf_imp_info->command[NULL].imm = reg_value[3];
                            emul_info->obf_imp_info->command[NULL].type = obf_sub;
                            emul_info->obf_imp_info->count_command++;

                            emul_info->obf_imp_info->command[1].imm = reg_value[1];
                            emul_info->obf_imp_info->command[1].type = obf_xor;
                            emul_info->obf_imp_info->count_command++;

                            emul_info->obf_imp_info->imp_obf_ptr_rva = emul_info->obf_imp_info->imp_obf_ptr_addr - emul_info->cur_mod_addr;
                            uc_emu_stop(uc);
                        }
                    }
#else
  
                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SHR &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        dis_instr.operands[1].imm.value.u == 0x20 &&
                        emul_info->imm_dump[3] == NULL
                        )
                    {
                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[NULL]);
                        
                        uc_mem_read(uc, emul_info->obf_imp_info->imp_obf_ptr_addr, &reg_value[1], sizeof(reg_value[1]));
                        if (reg_value[NULL] == reg_value[1])
                        {
                            emul_info->count_shr++; 
                            //active copy xor and stop if execute shl
                        }
                    }

                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SHL &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        dis_instr.operands[1].imm.value.u == 0x20 &&
                        emul_info->count_shr &&
                        emul_info->imm_dump[3]
                        )
                    {
 
                        emul_info->count_shl++;
                    }

                    if (
                        (
                            dis_instr.info.mnemonic == ZYDIS_MNEMONIC_ADD ||
                            dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SUB
                            )
                        &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                            dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            )
                        )
                    {
                        if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[NULL]);
                        }
                        else if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            reg_value[NULL] = dis_instr.operands[1].imm.value.u;
                        }
                        if (
                            dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_RSP &&
                            dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_ESP
                            )
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[1]);

                            emul_info->command[emul_info->count_command].imm = reg_value[NULL];
                            emul_info->command[emul_info->count_command].reg_value = reg_value[1];

                            if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_ADD)
                            {
                                emul_info->command[emul_info->count_command].type = obf_add;
                            }
                            else if (dis_instr.info.mnemonic == ZYDIS_MNEMONIC_SUB)
                            {
                                emul_info->command[emul_info->count_command].type = obf_sub;
                            }
                            emul_info->count_command++;
                        }
                    }
                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_XOR &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (       dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                                dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                        )  
                        )
                    {
                        if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[NULL]);
                        }                       
                        else if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            reg_value[NULL] = dis_instr.operands[1].imm.value.u;
                        }
                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[1]);

                         emul_info->command[emul_info->count_command].imm = reg_value[NULL];
                         emul_info->command[emul_info->count_command].reg_value = reg_value[1];
                         emul_info->command[emul_info->count_command].type = obf_xor;
                         emul_info->count_command++;

                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[1]);

                        if (emul_info->obf_imp_info->imp_obf_ptr_addr)
                        {
                            uc_mem_read(uc, emul_info->obf_imp_info->imp_obf_ptr_addr, &reg_value[2], sizeof(reg_value[2]));
                        }

                        if (emul_info->count_shr && (reg_value[2] >> 0x20 == reg_value[1]))
                        {
                            emul_info->imm_dump[3] = reg_value[NULL];
                        }
                                    
                    }

                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_AND &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (
                            dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                            dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            )
                        )
                    {
                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[NULL]);
                        if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[1]);
                        }
                        else if (dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            reg_value[1] = dis_instr.operands[1].imm.value.u;
                        }

                        if (reg_value[1] == UINT_MAX)
                        {
                            emul_info->imm_dump[2] = reg_value[NULL];
                        }

                    }

                    if (
                        dis_instr.info.mnemonic == ZYDIS_MNEMONIC_OR &&
                        dis_instr.info.operand_count_visible == 2 &&
                        dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER

                        )
                    {
                        unicore_util::read_reg(uc, &dis_instr.operands[NULL].reg.value, &reg_value[NULL]);
                        unicore_util::read_reg(uc, &dis_instr.operands[1].reg.value, &reg_value[1]);

                        imp_addr_pos = reg_value[NULL] | reg_value[1];

                        if (get_imp_name(emul_info->proc_information, reinterpret_cast<uint8_t*>(imp_addr_pos), &mod_name, &imp_name))
                        {
                            //add brutforce
                             emul_info->obf_imp_info->is_get_imp = TRUE;
                            emul_info->obf_imp_info->mod_name = mod_name;
                            emul_info->obf_imp_info->imp_name = imp_name;

                            uc_mem_read(uc, emul_info->obf_imp_info->imp_obf_ptr_addr, &reg_value[2], sizeof(reg_value[2]));

                            //try get command (if fail -> just don't ret crypt key)
                            if (prutforce_command(emul_info, reg_value[2], reg_value[NULL], reg_value[1]))
                            {
                                // printf("reg_value[2] ->\t%p\n", reg_value[2]);
                                 //printf("reg_value[2] ->\t%p\n", reg_value[2] >> 0x20);
                                 //printf("reg_value[2] ->\t%p\n", (reg_value[2] >> 0x20) ^ emul_info->imm_dump[3]);
                                // printf("shr and shl res ->\t%p\n", (((reg_value[2] >> 0x20) ^ emul_info->imm_dump[3])  << 0x20));

                                 //printf("decrypted imp ->\t %p %p %p\n", reg_value[NULL], reg_value[1], reg_value[NULL] | reg_value[1]);
                                emul_info->obf_imp_info->imp_obf_ptr_rva = emul_info->obf_imp_info->imp_obf_ptr_addr - emul_info->cur_mod_addr;
                                uc_emu_stop(uc);
                            }
                        }
                    }

#endif // !_WIN64
                }
            }
        }
         
    }


    NO_INLINE static void hook_mem64(uc_engine* uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void* user_data)
    {
        uc_err err;
        uint64_t vip_cur_pointer = NULL;
        uint8_t  opcode_instr[MAX_LENGHT_INSTR];
        ZydisRegister reg_read_manual = ZYDIS_REGISTER_NONE;
        ZydisDisassembledInstruction dis_instr = { NULL };
        PIMP_EMUL_INFO emul_info = NULL;

        emul_info = reinterpret_cast<PIMP_EMUL_INFO>(user_data);
        
        if (type == UC_MEM_READ)
        {
            if (address >= emul_info->cur_mod_addr && emul_info->cur_mod_addr + emul_info->cur_mod_size > address + size)
            {

                err = uc_reg_read(uc, REG_VIP, &vip_cur_pointer);
                memset(&opcode_instr, NULL, sizeof(opcode_instr));

                if (err == UC_ERR_OK && vip_cur_pointer && uc_mem_read(uc, vip_cur_pointer, opcode_instr, sizeof(opcode_instr)) == UC_ERR_OK)
                {
                    if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, opcode_instr)))
                    {
                        if (emul_info->proc_information->prot_type == prot_vmp)
                        {
                            if (
                                dis_instr.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                dis_instr.info.operand_count_visible == 2 &&
                                dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                dis_instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                (
                                    dis_instr.operands[NULL].reg.value == dis_instr.operands[1].mem.base ||
                                    dis_instr.operands[NULL].reg.value == dis_instr.operands[1].mem.index
                                    ) &&
#ifndef _WIN64
                                    (
                                        dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_ESP &&
                                        dis_instr.operands[1].mem.index != ZYDIS_REGISTER_ESP
                                    )

#else
                                (
                                    dis_instr.operands[NULL].reg.value != ZYDIS_REGISTER_RSP &&
                                    dis_instr.operands[1].mem.index != ZYDIS_REGISTER_RSP
                                    )
#endif // !_WIN64
                                )

                            {
#ifndef _WIN64
                                reg_read_manual = ZYDIS_REGISTER_EIP;
#else
                                reg_read_manual = ZYDIS_REGISTER_RIP;
#endif // !_WIN64
                                emul_info->obf_imp_info->imp_obf_ptr_addr = address;

                                unicore_util::read_reg(uc, &reg_read_manual, &emul_info->obf_imp_info->imp_obf_read_instr_rva);
                                emul_info->obf_imp_info->imp_obf_read_instr_rva -= emul_info->cur_mod_addr;
                            }
                        }

                        if (emul_info->proc_information->prot_type == prot_themida)
                        {
                            if (
                                dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSH &&
                                dis_instr.info.operand_count_visible == 1 &&
                                dis_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY)
                            {
#ifndef _WIN64
                                reg_read_manual = ZYDIS_REGISTER_EIP;
#else
                                reg_read_manual = ZYDIS_REGISTER_RIP;
#endif // !_WIN64
                                emul_info->obf_imp_info->imp_obf_ptr_addr = address;

                                unicore_util::read_reg(uc, &reg_read_manual, &emul_info->obf_imp_info->imp_obf_read_instr_rva);
                                emul_info->obf_imp_info->imp_obf_read_instr_rva -= emul_info->cur_mod_addr;
                            }
                        }
                    }
                }
            }
        }
    }

    static uc_err emu_start_seh(uc_engine* uc, uint64_t begin, uint64_t until,  uint64_t timeout, size_t count) {
        __try {
            return uc_emu_start(uc, begin, until, timeout, count);
        }
        __except (1) 
        {
            return UC_ERR_EXCEPTION;
        }
        return UC_ERR_OK;
    }

     
     //re-allocates memory for each import emulation
    //need fix for address
    NO_INLINE auto safe_init_emu(proc_info& proc_information,protector_imp_info* obf_info, uint64_t mod_addr, uint32_t emul_count, BOOLEAN is_log = FALSE) -> BOOLEAN
    {
        //Add aligment
        uint32_t prot = NULL;
        uint32_t size_aligment = NULL;
        uint64_t addr_emu = NULL;
        uint64_t r_rsp_addr = ALIGN_UP(reinterpret_cast<uint64_t>(reinterpret_cast<CHAR*>(proc_information.orig_addr_mem) - (0x1000 * 20)), 0x1000);
        uint64_t r_rsp = NULL;
        uint64_t vip_exit = NULL;
        PIMAGE_NT_HEADERS nt_headers = NULL;
        PIMAGE_SECTION_HEADER sec = NULL;

        uc_engine* uc;
        uc_hook trace_read = NULL;
        uc_hook trace_execute = NULL;
        uc_err err;
        IMP_EMUL_INFO emul_info = { NULL };
        UC_MAP_CODE cur_maped_code = { NULL };
        std::vector<UC_MAP_CODE> maped_code;
        
        addr_emu = obf_info->addr_wrapper_imp - (size_t)proc_information.coped_mem + (size_t)proc_information.orig_addr_mem;

        err = uc_open(UC_ARCH_X86, EMU_MODE, &uc);
        if (err)
        {
            if (is_log)
            {
                printf("Failed on uc_open() with error returned: %u\n", err);
            }
            return FALSE;
        }

        nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<CHAR*>(mod_addr) + reinterpret_cast<IMAGE_DOS_HEADER*>(mod_addr)->e_lfanew);

        sec = IMAGE_FIRST_SECTION(nt_headers);
        
        err = uc_mem_map(uc, (size_t)proc_information.orig_addr_mem, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
        if (err)
        {
            if (is_log)
            {
                printf("Failed on uc_mem_map() with error returned: %u\n", err);
            }
            uc_close(uc);
            return FALSE;
        }
        cur_maped_code.addr = (size_t)proc_information.orig_addr_mem;
        cur_maped_code.size_code = ALIGN_UP(nt_headers->OptionalHeader.SizeOfHeaders, nt_headers->OptionalHeader.SectionAlignment);
        maped_code.push_back(cur_maped_code);

        err = uc_mem_write(uc, (size_t)proc_information.orig_addr_mem, reinterpret_cast<PVOID>(proc_information.coped_mem), nt_headers->OptionalHeader.SizeOfHeaders);
        if (err != UC_ERR_OK)
        {
            if (is_log)
            {
                printf("Failed on uc_mem_write() with error returned: %u\n", err);

            }
            unmap_code(uc, maped_code);
            uc_close(uc);
            return FALSE;
        }
        

        for (uint16_t i = NULL; i < nt_headers->FileHeader.NumberOfSections; i++)
        {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)
            {
                prot |= UC_PROT_READ;
            }
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            {
                prot |= UC_PROT_WRITE;
            }
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                prot |= UC_PROT_EXEC;
            }

            size_aligment = sec[i].Misc.VirtualSize;

            if (size_aligment % nt_headers->OptionalHeader.SectionAlignment != NULL)
            {
                size_aligment = ALIGN_UP(size_aligment, nt_headers->OptionalHeader.SectionAlignment);
            }
            err = uc_mem_map(uc, (size_t)proc_information.orig_addr_mem + sec[i].VirtualAddress, size_aligment, prot);
            if (err != UC_ERR_OK)
            {
                if (is_log)
                {
                    printf("Failed on uc_mem_map() with error returned: %u\n", err);
                }
                unmap_code(uc, maped_code);
                uc_close(uc);

                return FALSE;
            }

            cur_maped_code.addr = (size_t)proc_information.orig_addr_mem + sec[i].VirtualAddress;
            cur_maped_code.size_code = size_aligment;
            maped_code.push_back(cur_maped_code);

            err = uc_mem_write(uc, (size_t)proc_information.orig_addr_mem + sec[i].VirtualAddress, reinterpret_cast<PVOID>(proc_information.coped_mem + sec[i].VirtualAddress), size_aligment);
            if (err)
            {
                if (is_log)
                {
                    printf("Failed on uc_mem_write() with error returned: %u\n", err);
                }
                unmap_code(uc, maped_code);
                uc_close(uc);

                return FALSE;
            }
            prot = NULL;
        }
         
        emul_info.is_log = is_log;
        emul_info.obf_imp_info = obf_info;
        emul_info.addr_emul_start = addr_emu;
        emul_info.cur_mod_addr = (size_t)proc_information.orig_addr_mem;
        emul_info.cur_mod_size = nt_headers->OptionalHeader.SizeOfImage;
        emul_info.proc_information =  &proc_information;
        err = uc_hook_add(uc, &trace_read, UC_HOOK_MEM_READ, hook_mem64, &emul_info, 1, 0);
        if (err != UC_ERR_OK)
        {
            if (is_log)
            {
                printf("UC_HOOK_MEM_READ bad ->\t%p\n", err);

            }
            unmap_code(uc, maped_code);
            uc_close(uc);
            return FALSE;
        }


        err = uc_hook_add(uc, &trace_execute, UC_HOOK_CODE, hook_code, &emul_info, 1, 0);
        if (err != UC_ERR_OK)
        {
            if (is_log)
            {
                printf("UC_HOOK_CODE bad ->\t%p\n", err);
            }
            unmap_code(uc, maped_code);
            uc_close(uc);
            return FALSE;
        }

        //re-null emul_info
        unicore_util::init_reg(uc, r_rsp_addr);

        cur_maped_code.addr = r_rsp_addr;
        cur_maped_code.size_code = STACK_SIZE;

        maped_code.push_back(cur_maped_code);

        if (obf_info->is_virtulized)
        {
            vip_exit = mod_addr;
            emul_info.vip_exit = vip_exit;
            err = uc_reg_read(uc, REG_VSP, &r_rsp);
            if (err != UC_ERR_OK)
            {
                if (is_log)
                {
                    printf("Failed on uc_reg_read() with error returned: %u\n", err);
                }
                unmap_code(uc, maped_code);
                uc_close(uc);
                return FALSE;
            }

            err = uc_mem_write(uc, r_rsp, &vip_exit, sizeof(PVOID));

            if (err != UC_ERR_OK)
            {
                if (is_log)
                {
                    printf("Failed on uc_reg_read() with error returned: %u\n", err);
                }
                unmap_code(uc, maped_code);
                uc_close(uc);
                return FALSE;
            }
        }
        else
        {
            emul_info.vip_exit = addr_emu;
        }

        err = emu_start_seh(uc, addr_emu, /*mod_addr + nt_headers->OptionalHeader.SizeOfImage*/ NULL, NULL, emul_count);
  
        if (err != UC_ERR_OK)
        {
           
            if (is_log)
            {
                printf("uc_emu_start bad ->\t%p\n", err);
            }
        }
        unmap_code(uc, maped_code);
        uc_close(uc);
        return err == UC_ERR_OK;

    }
}
    
#endif // !EMUL_CODE
