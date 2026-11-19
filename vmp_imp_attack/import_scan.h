#ifndef IMPORT_SCAN
#define IMPORT_SCAN 1
#include "struct.h"
#include "disassembly_util.h"
#include "emul_code.h"
#define OPCODE_NOP 0x90

#define OPCODE_PUSH_IMM 0x68

#define OPCODE_IMM_CALL 0xE8
#define OPCODE_IMM_JMP 0xE9
#define OPCODE_PTR_CALL 0x15FF
#define OPCODE_PTR_JMP 0x25FF

#define DIS_IMP_VMP_WRAPPER_OLD 50
#define DIS_IMP_VMP_WRAPPER_NEXT_CALL 120
#define DIS_IMP_VMP_WRAPPER_CALL 120
#define DIS_IMP_THEMIDA_WRAPPER_CALL 350

#define MAX_JCC_EXECUTE 7
#define MAX_RECURS_EXECUTE 7

namespace imp_scan
{
    NO_INLINE auto is_push_eflag(uint8_t* addr) -> BOOLEAN
    {
#ifndef _WIN64
        return *addr == 0x9C;   //pushfd
#else
        return *addr == 0x9C;   //pushfq
#endif // !_WIN64
    }

  
    NO_INLINE auto is_vsp_change(uint8_t* addr) -> BOOLEAN
    {
#ifndef _WIN64
        return
         (
            (*addr == 0x83 || *addr == 0x81) && *(addr + 1) == 0xEC  // sub esp, imm
          )
           ||
          (
               *addr == 0x8D && (*(addr + 1) == 0x64 || *(addr + 1) == 0xA4) && *(addr +2) == 0x24 // lea esp,[esp+imm]
          );
#else
        return
        (
             *addr == 0x48 && (*(addr + 1) == 0x83 || *(addr + 1) == 0x81) && *(addr + 2) == 0xEC // sub rsp, imm
         ) 
        ||
         (
             *addr == 0x48 && *(addr + 1) == 0x8D && ( *(addr + 2) == 0x64 || *(addr + 2) == 0xA4) && *(addr + 3) == 0x24 // lea rsp,[rsp+imm]
         );

#endif // !_WIN64

    }


    NO_INLINE auto is_push(uint8_t* addr) -> BOOLEAN
    {

#ifndef _WIN64
        return
            (
                *addr == 0x50 ||							//push eax
                *addr == 0x53 ||							//push ebx
                *addr == 0x51 ||							//push ecx
                *addr == 0x52 ||							//push edx
                *addr == 0x55 ||							//push ebp
                *addr == 0x56 ||							//push esi
                *addr == 0x57								//push edi
                );
#else
        return
            (
                *addr == 0x50 ||							//push rax
                *addr == 0x53 ||							//push rbx
                *addr == 0x51 ||							//push rcx
                *addr == 0x52 ||							//push rdx
                *addr == 0x55 ||							//push rbp
                *addr == 0x56 ||							//push rsi
                *addr == 0x57 ||							//push rdi
                (*addr == 0x41 && *(addr + 1) == 0x50) ||	//push r8
                (*addr == 0x41 && *(addr + 1) == 0x51) ||	//push r9
                (*addr == 0x41 && *(addr + 1) == 0x52) ||	//push r10
                (*addr == 0x41 && *(addr + 1) == 0x53) ||	//push r11
                (*addr == 0x41 && *(addr + 1) == 0x54) ||	//push r12
                (*addr == 0x41 && *(addr + 1) == 0x55) ||	//push r13
                (*addr == 0x41 && *(addr + 1) == 0x56) ||	//push r14
                (*addr == 0x41 && *(addr + 1) == 0x57)		//push r15
                );
#endif // !_WIN64
    }


    NO_INLINE auto is_pop(uint8_t* addr) -> BOOLEAN
    {

#ifndef _WIN64
        return
            (
                *addr == 0x58 ||							//pop eax
                *addr == 0x5B ||							//pop ebx
                *addr == 0x59 ||							//pop ecx
                *addr == 0x5A ||							//pop edx
                *addr == 0x5D ||							//pop ebp
                *addr == 0x5E ||							//pop esi
                *addr == 0x5F 								//pop edi
                );
#else

        return
            (
                *addr == 0x58 ||							//pop rax
                *addr == 0x5B ||							//pop rbx
                *addr == 0x59 ||							//pop rcx
                *addr == 0x5A ||							//pop rdx
                *addr == 0x5D ||							//pop rbp
                *addr == 0x5E ||							//pop rsi
                *addr == 0x5F ||							//pop rdi
                (*addr == 0x41 && *(addr + 1) == 0x58) ||	//pop r8
                (*addr == 0x41 && *(addr + 1) == 0x59) ||	//pop r9
                (*addr == 0x41 && *(addr + 1) == 0x5A) ||	//pop r10
                (*addr == 0x41 && *(addr + 1) == 0x5B) ||	//pop r11
                (*addr == 0x41 && *(addr + 1) == 0x5C) ||	//pop r12
                (*addr == 0x41 && *(addr + 1) == 0x5D) ||	//pop r13
                (*addr == 0x41 && *(addr + 1) == 0x5E) ||	//pop r14
                (*addr == 0x41 && *(addr + 1) == 0x5F)		//pop r15
                );
#endif // !_WIN64

    }

    NO_INLINE auto is_insode_module(proc_info& proc_inform, uint8_t* addr) -> BOOLEAN
    {
#ifndef _WIN64
        //reloce
        if (
            addr >= proc_inform.orig_addr_mem &&
            proc_inform.orig_addr_mem + proc_inform.coped_size > addr
            )
        {
            return TRUE;
        }
#else
        if (
            addr >= proc_inform.coped_mem &&
            proc_inform.coped_mem + proc_inform.coped_size > addr
            )
        {
            return TRUE;
        }
#endif // !_WIN64

 
        return FALSE;

    }

    NO_INLINE auto is_inside_sec(uint8_t* addr,PVOID mod_addr, SEC_INFO* sections) -> BOOLEAN
    { 
        uint32_t rva_addr = NULL;
        rva_addr = addr - mod_addr;
        if (
            sections->rva <= rva_addr &&
            sections->rva + sections->virt_size > rva_addr
            )
        {
            return TRUE;
        }
        return FALSE;
    }

    NO_INLINE auto inside_sec_prot(proc_info& proc_inform, uint8_t* addr) -> BOOLEAN
    {
        size_t addr_rva = NULL;
        if (
            addr >= proc_inform.coped_mem &&
            proc_inform.coped_mem + proc_inform.coped_size > addr
            )
        {
            addr_rva = addr - proc_inform.coped_mem;
            for (size_t i = NULL; i < proc_inform.sec_list.size(); i++)
            {
                if (proc_inform.sec_list[i].sec_type_info == sec_type_prot)
                {
                    if (
                        addr_rva >= proc_inform.sec_list[i].rva &&
                        proc_inform.sec_list[i].rva + proc_inform.sec_list[i].virt_size > addr_rva
                        )
                    {
                        return TRUE;
                    }
                }
            }
        }
        return FALSE;
    }

   

    NO_INLINE auto read_lazy(proc_info& proc_inform, uint8_t* addr) -> size_t
    {
        size_t read_res = NULL;
        if (
            addr >= proc_inform.orig_addr_mem &&
            proc_inform.orig_addr_mem + proc_inform.coped_size > addr
            )
        {
            read_res = *reinterpret_cast<size_t*>(addr - proc_inform.orig_addr_mem + proc_inform.coped_mem);
        }
        return read_res;
    }
     
    NO_INLINE auto transform_addr_mod(proc_info& proc_inform, uint8_t* addr) -> uint8_t*
    {
        uint8_t* addr_res = NULL;
        if (
            addr >= proc_inform.orig_addr_mem &&
            proc_inform.orig_addr_mem + proc_inform.coped_size > addr
            )
        {
            addr_res = addr - proc_inform.orig_addr_mem + proc_inform.coped_mem;
        }
        return addr_res;
    }

    NO_INLINE auto get_imp_name(proc_info& proc_inform, uint8_t* addr, WCHAR** mod_name, CHAR** imp_name) -> BOOLEAN
    {
        uint32_t api_rva = NULL;
       
        PIMAGE_DOS_HEADER dos_head = NULL;
        PIMAGE_NT_HEADERS nt_head = NULL;
        PIMAGE_EXPORT_DIRECTORY export_dir = NULL;
        
        for (size_t i = NULL; i < proc_inform.mod_list.size(); i++)
        {
            if (
                proc_inform.mod_list[i].orig_addr_mem != proc_inform.orig_addr_mem &&
                proc_inform.mod_list[i].is_any_export
                )
            {
                if (
                    addr >=proc_inform.mod_list[i].orig_addr_mem &&
                   proc_inform.mod_list[i].orig_addr_mem + proc_inform.mod_list[i].coped_size >= addr
                    )
                {
                    api_rva = addr - proc_inform.mod_list[i].orig_addr_mem;

                    if (mod_name)
                    {
                        *mod_name = (WCHAR *)proc_inform.mod_list[i].mod_name.c_str();
                    }
                    dos_head = reinterpret_cast<PIMAGE_DOS_HEADER>(proc_inform.mod_list[i].coped_mem);
                    if (dos_head->e_magic == IMAGE_DOS_SIGNATURE)
                    {
                        nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(proc_inform.mod_list[i].coped_mem + dos_head->e_lfanew);
                        export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(proc_inform.mod_list[i].coped_mem + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                        if (nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && export_dir)
                        {
                            auto names = (PDWORD)(proc_inform.mod_list[i].coped_mem + export_dir->AddressOfNames);
                            auto ordinals = (PWORD)(proc_inform.mod_list[i].coped_mem + export_dir->AddressOfNameOrdinals);
                            auto functions = (PDWORD)(proc_inform.mod_list[i].coped_mem + export_dir->AddressOfFunctions);

                            for (uint32_t j = NULL; j < export_dir->NumberOfFunctions; ++j)
                            {
                                if (functions[ordinals[j]] == api_rva)
                                {
                                    if (imp_name)
                                    {
                                        *imp_name = reinterpret_cast<CHAR*>(proc_inform.mod_list[i].coped_mem)+ names[j];
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
     
    NO_INLINE auto is_exist_imp(std::vector<protector_imp_info>& imp_list, protector_imp_info* cur_imp) -> BOOLEAN
    {
        for (size_t i = NULL; i < imp_list.size(); i++)
        {
            if (
                imp_list[i].imp_obf_ptr_rva == cur_imp->imp_obf_ptr_rva &&
                !imp_list[i].imp_name.compare(cur_imp->imp_name) &&
                !imp_list[i].mod_name.compare(cur_imp->mod_name)
                )
            {
                return TRUE;
            }
        }
        return FALSE;
    }


    //always exist_push_eflag = FALSE
    NO_INLINE auto get_wrapper_themida(proc_info& proc_inform, uint8_t* addr, uint32_t cur_sec_id, THEMIDA_IMP_WRAPPER_DIS* wrapper_info = NULL, BOOLEAN is_virtualized = FALSE) -> BOOLEAN
    {
        // just ret lazy + just jcc + ret
        BOOLEAN ignore_add_lenght = FALSE;
        CHAR* imp_name = NULL;
        WCHAR* mod_name = NULL;
        uint8_t* pos_addr = NULL; 
        THEMIDA_IMP_WRAPPER_DIS cur_next_wrapper_info = { NULL };
        ZydisDisassembledInstruction dis_code = { NULL };


        for (size_t dis_count = NULL; dis_count < DIS_IMP_THEMIDA_WRAPPER_CALL && wrapper_info->count_dis < DIS_IMP_THEMIDA_WRAPPER_CALL; dis_count++)
        {
            if (ZYAN_SUCCESS(dis::get_dis(&dis_code, addr)))
            {
                if (is_virtualized)
                {
                    if (!is_inside_sec(addr, proc_inform.coped_mem, &proc_inform.sec_list[cur_sec_id]))
                    {
                        return FALSE;
                    }
                }
                else if (wrapper_info->count_dis >= 1) //ignore first call
                { 
                    if (!inside_sec_prot(proc_inform, addr))
                    {
                        return FALSE;
                    }
                }
                  
                //no exist push eflag
                if ( 
#ifndef _WIN64
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD
#else
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ
#endif // !_WIN64
                    )
                {
                    return FALSE;
                }

                if (
                    dis_code.info.operand_count_visible == 1 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dis_code.operands[NULL].mem.base != ZYDIS_REGISTER_NONE &&
                    dis_code.operands[NULL].mem.segment != ZYDIS_REGISTER_NONE &&
                    !dis_code.operands[NULL].mem.disp.has_displacement
                    )
                {
                    wrapper_info->count_push_mem++;
                }

                if (
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                        dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                        )
                    )
                {
                    if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_ADD)
                    {
                        wrapper_info->count_add++;
                    }
                    if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_SUB)
                    {
                        wrapper_info->count_sub++;
                    } 
                    if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_XOR)
                    {
                        wrapper_info->count_xor++;
                    }   
                    if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_AND)
                    {
                        wrapper_info->count_and++;
                    }
                    if (
                        dis_code.info.mnemonic == ZYDIS_MNEMONIC_OR && 
                        dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                        )
                    {
                        wrapper_info->count_or++;
                    }
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_RDTSC ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CPUID ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSENTER
                    )
                {
                    return FALSE;
                }
                 

                if (dis::is_jññ(&dis_code))
                {
                    wrapper_info->count_jcc++;
                    //we can ignore correct path code
                    if (wrapper_info->count_jcc >= 6) // Themida 3.0.x.x add call with fake api and some jcc
                    {
                        return FALSE;
                    }
                 }
 

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_RET
                    )
                {

#ifndef _WIN64
                    if (
                            wrapper_info->count_push_mem && //read crypted pointer
                            (wrapper_info->count_add || wrapper_info->count_sub) && //fist decrypt crypted pointer
                            wrapper_info->count_xor // final decrypt crypted pointer
                        )
                    {
                        return TRUE;
                    }
#else 
                    if (
                        wrapper_info->count_push_mem &&
                        (wrapper_info->count_add || wrapper_info->count_sub) && //decrypt value
                        wrapper_info->count_xor >= 2 && //xor for decrypt rva & base
                        wrapper_info->count_and && //and for rva
                        wrapper_info->count_or //calc res addr
                        )
                    {
                        return TRUE;
                    }
#endif // !_WIN64
                    return FALSE;
                }

                //if add get rva need check rva
                if (
                    !wrapper_info->count_dis &&
                    !is_virtualized &&
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
                    )
                {

                    if (
#ifndef _WIN64
                        dis_code.operands[NULL].mem.base == ZYDIS_REGISTER_NONE &&
                        dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
#else
                        dis_code.operands[NULL].mem.base == ZYDIS_REGISTER_RIP &&
                        dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
#endif
                        )
                    {

                        pos_addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                        if (!is_insode_module(proc_inform, pos_addr))
                        {
                            return FALSE;
                        } 
#ifndef _WIN64
                        pos_addr = reinterpret_cast<uint8_t*>(read_lazy(proc_inform,pos_addr));
                        pos_addr = transform_addr_mod(proc_inform, pos_addr);
#else
                        pos_addr = *reinterpret_cast<uint8_t**>(pos_addr);
                        pos_addr = transform_addr_mod(proc_inform, pos_addr);
#endif // !_WIN64

                       if (!pos_addr || !inside_sec_prot(proc_inform, pos_addr))
                       {
                           return FALSE;
                       }
                        addr = pos_addr;
                        ignore_add_lenght = TRUE;
                    }
                }

                if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_JMP)
                {
                    if (dis_code.info.operand_count_visible == 1 )
                    {
                        if (dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            pos_addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                            if (!inside_sec_prot(proc_inform, pos_addr)) //address outside sec
                            {
                                return FALSE;
                            }
                            if (!wrapper_info->first_jmp_next_addr)
                            {
                                wrapper_info->first_jmp_next_addr = addr + dis_code.info.length;
                            }
                            addr = pos_addr;
                        }
                        else if 
                        (
                            !wrapper_info->count_dis &&
                            !is_virtualized &&
                            dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
                        )
                        {

                            if (
#ifndef _WIN64
                                dis_code.operands[NULL].mem.base == ZYDIS_REGISTER_NONE &&
                                dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
#else
                                dis_code.operands[NULL].mem.base == ZYDIS_REGISTER_RIP &&
                                dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
#endif
                                )
                            {

                                pos_addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                                if (!is_insode_module(proc_inform, pos_addr))
                                {
                                    return FALSE;
                                }

#ifndef _WIN64
                                pos_addr = reinterpret_cast<uint8_t*>(read_lazy(proc_inform, pos_addr));
                                pos_addr = transform_addr_mod(proc_inform, pos_addr);
#else
                                pos_addr = *reinterpret_cast<uint8_t**>(pos_addr);
                                pos_addr = transform_addr_mod(proc_inform, pos_addr);
#endif // !_WIN64
                                if (!pos_addr || !inside_sec_prot(proc_inform, pos_addr))
                                {
                                    return FALSE;
                                }
                                addr = pos_addr;
                                ignore_add_lenght = TRUE;
                            }
                        }
                        else
                        {
                            return FALSE;
                        }
                    }
                    else 
                    {
                        return FALSE;
                    }
                }
                else
                {
                    if (!ignore_add_lenght)
                    {
                        addr += dis_code.info.length;

                    }
                }
            }
            else
            {
                return FALSE;
            }
            wrapper_info->count_dis++;
            ignore_add_lenght = FALSE;
        }
        return  FALSE;
    }
     

    NO_INLINE auto get_dis_import_vmp_old(proc_info& proc_inform, protector_imp_info* cur_vmp_info,uint8_t* addr, uint32_t sec_rva, BOOLEAN is_virtualized) -> BOOLEAN
    {
        CHAR* imp_name = NULL;
        WCHAR* mod_name = NULL;
        size_t readed_base_addr = NULL;
        VMP_IMP_WRAPPER_DIS_OLD wrapper_info = { NULL };
        ZydisDisassembledInstruction dis_code = { NULL };

        //cur_vmp_info->addr_wrapper_imp = reinterpret_cast<size_t>(addr);

        for (size_t dis_count = NULL; dis_count < DIS_IMP_VMP_WRAPPER_OLD; dis_count++)
        {
            if (ZYAN_SUCCESS(dis::get_dis(&dis_code, addr)))
            {
                if (!is_virtualized)
                {
                    if (
                        !dis_count &&
                        dis_code.info.mnemonic != ZYDIS_MNEMONIC_CALL
                        )
                    {
                        return FALSE;
                    }
                    if (
                        dis_count == 1 &&
                        dis_code.info.mnemonic != ZYDIS_MNEMONIC_NOP
                        )
                    {
                        return FALSE;
                    }
                }
                else
                {
                    if (!dis_count)
                    {
                        if (dis_code.info.mnemonic != ZYDIS_MNEMONIC_NOP)
                        {
                            return FALSE;
                        }
                    }
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[NULL].reg.value == wrapper_info.reg_base &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dis_code.operands[1].mem.base == wrapper_info.reg_base &&
                    dis_code.operands[1].mem.disp.has_displacement
                    )
                {

                    cur_vmp_info->diff_offset = dis_code.operands[1].mem.disp.value;
                }

#ifndef _WIN64
                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    dis_code.operands[1].imm.value.u
                    )
                {
                    wrapper_info.reg_base = dis_code.operands[NULL].reg.value; 
                    cur_vmp_info->base_obf_addr = dis_code.operands[1].imm.value.u;
                }
#else 
                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dis_code.operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                    dis_code.operands[1].mem.disp.has_displacement
                    )
                {
                    wrapper_info.reg_base = dis_code.operands[NULL].reg.value;
                    cur_vmp_info->base_obf_addr = dis::get_absolute_address(&dis_code, addr + reinterpret_cast<size_t>(proc_inform.orig_addr_mem) - reinterpret_cast<size_t>(proc_inform.coped_mem));
                }
#endif // !_WIN64


                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dis_code.operands[1].mem.base == wrapper_info.reg_base &&
                    dis_code.operands[1].mem.disp.has_displacement &&
                    cur_vmp_info->diff_offset
                    )
                {
                    cur_vmp_info->count_command++;
                    cur_vmp_info->command[NULL].type = obf_lea;
                    cur_vmp_info->command[NULL].imm = dis_code.operands[1].mem.disp.value;

                    readed_base_addr = read_lazy(proc_inform, reinterpret_cast<uint8_t*>(cur_vmp_info->base_obf_addr + cur_vmp_info->diff_offset));
                    if (get_imp_name(proc_inform, reinterpret_cast<uint8_t*>(readed_base_addr) + dis_code.operands[1].mem.disp.value, &mod_name,&imp_name)) //check is import
                    {
                        if (mod_name)
                        {
                            cur_vmp_info->mod_name = mod_name;
                        }
                        if (imp_name)
                        {
                            cur_vmp_info->imp_name = imp_name;
                        }
                         cur_vmp_info->imp_obf_ptr_addr = cur_vmp_info->base_obf_addr + cur_vmp_info->diff_offset;
                        cur_vmp_info->imp_obf_ptr_rva = cur_vmp_info->base_obf_addr + cur_vmp_info->diff_offset - reinterpret_cast<size_t>(proc_inform.orig_addr_mem);
                        return TRUE;
                    }
                }
 

                if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_JMP ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    if (
                        dis_code.info.operand_count_visible == 1 &&
                        dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                        )
                    {
                        addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                        if (!inside_sec_prot(proc_inform, addr)) //address outside sec
                        {
                            return FALSE;
                        }
                    }
                    else
                    {
                        return FALSE;
                    }
                }
                else
                {
                    addr += dis_code.info.length;
                }
            }
            else
            {
                return FALSE;
            }
        }
        return FALSE;

    }
      
    NO_INLINE auto get_next_wrapper_vmp(proc_info& proc_inform, uint8_t* addr, uint32_t cur_sec_id, VMP_IMP_WRAPPER_DIS_NEXT* wrapper_info = NULL, BOOLEAN is_virtualized = FALSE, BOOLEAN exist_push_eflag = FALSE, uint32_t recurs = NULL, uint32_t jcc = NULL) -> BOOLEAN
    {
        // just ret lazy + just jcc + ret
        CHAR* imp_name = NULL;
        WCHAR* mod_name = NULL;
        uint8_t* pos_addr = NULL;
        VMP_IMP_WRAPPER_DIS_NEXT cur_next_wrapper_info = { NULL };
        ZydisDisassembledInstruction dis_code = { NULL };


        for (size_t dis_count = NULL; dis_count < DIS_IMP_VMP_WRAPPER_NEXT_CALL && wrapper_info->count_dis < DIS_IMP_VMP_WRAPPER_NEXT_CALL; dis_count++)
        {
            if (ZYAN_SUCCESS(dis::get_dis(&dis_code, addr)))
            {
                if (is_virtualized)
                {
                    if (!is_inside_sec(addr, proc_inform.coped_mem, &proc_inform.sec_list[cur_sec_id]))
                    {
                        return FALSE;
                    }
                }
                else if (wrapper_info->count_dis >= 15)
                {
                    //check after call 
                    // (in 3.10.4 .text call imp_wrapper -> 
                    // .text command  (push)
                    // .text next_call
                    //.vmp command (pop)

                    if (!inside_sec_prot(proc_inform, addr))
                    {
                        return FALSE;
                    }
                }

                //Faster will be emulate ~150 instr
                if (recurs >= MAX_RECURS_EXECUTE || jcc >= MAX_JCC_EXECUTE)
                {
                    return TRUE;
                }

                if (
                    exist_push_eflag &&
#ifndef _WIN64
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD
#else
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ
#endif // !_WIN64
                    )
                {
                    wrapper_info->count_push_eflag++;
                }

                if (exist_push_eflag && !wrapper_info->count_push_eflag)
                {
                    if (dis::is_change_eflag(&dis_code))
                    {
                        return FALSE;
                    }

                    if (dis::is_check_eflag(&dis_code))
                    {
                        return FALSE;
                    }
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_ADC ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_ADD
                    )
                {
                    wrapper_info->count_add++;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SUB ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SBB
                    )
                {
                    wrapper_info->count_sub++;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_RDTSC ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CPUID ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSENTER
                    )
                {
                    return FALSE;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL &&
                    dis_code.info.operand_count_visible == 1 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    )
                {
                    wrapper_info->count_call_imm++;
                }

                if (dis::is_jññ(&dis_code))
                {
                    //pos_addr;
                    memcpy(&cur_next_wrapper_info, wrapper_info, sizeof(cur_next_wrapper_info));
                    pos_addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, reinterpret_cast<CHAR*>(dis_code.runtime_address)));
                    cur_next_wrapper_info.count_dis++;
                    if (inside_sec_prot(proc_inform,pos_addr))
                    {
                        recurs++;
                        if (get_next_wrapper_vmp(proc_inform, pos_addr, cur_sec_id, &cur_next_wrapper_info, is_virtualized, exist_push_eflag, recurs, jcc))
                        {
                            return TRUE;
                        }
                    }
                    jcc++;
                }

 

                if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_RET)
                {
                    if (
                            (wrapper_info->count_add || 
                            wrapper_info->count_sub
                            ) &&
                        wrapper_info->count_call_imm >= 1
                        )
                    { 
                        if (exist_push_eflag && wrapper_info->count_push_eflag)
                        {
                            return wrapper_info->count_push_eflag != NULL;
                        }
                        else
                        {
                            return !wrapper_info->count_push_eflag;
                        }
                    } 
                }

                if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_JMP ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    if (
                        dis_code.info.operand_count_visible == 1 &&
                        dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                        )
                    {
                        addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                        if (!inside_sec_prot(proc_inform, addr)) //address outside sec
                        {
                            return FALSE;
                        }
                    }
                    else
                    {
                        return FALSE;
                    }
                }
                else
                {
                    addr += dis_code.info.length;
                }
            }
            else
            {
                return FALSE;
            }
            wrapper_info->count_dis++;
        }                        
        return  FALSE;
    }


    NO_INLINE auto get_wrapper_vmp(proc_info& proc_inform, uint8_t* addr, uint32_t cur_sec_id, VMP_IMP_WRAPPER_DIS* wrapper_info = NULL, BOOLEAN is_virtualized = FALSE, BOOLEAN exist_push_eflag = FALSE, uint32_t recurs = NULL, uint32_t jcc = NULL) -> BOOLEAN
    { 
        CHAR* imp_name = NULL;
        WCHAR* mod_name = NULL;
        uint8_t* pos_addr = NULL;
        VMP_IMP_WRAPPER_DIS cur_wrapper_info = { NULL };
        ZydisDisassembledInstruction dis_code = { NULL };


        for (size_t dis_count = NULL; dis_count < DIS_IMP_VMP_WRAPPER_CALL && wrapper_info->count_dis < DIS_IMP_VMP_WRAPPER_CALL; dis_count++)
        {
            if (ZYAN_SUCCESS(dis::get_dis(&dis_code, addr)))
            {
                if (is_virtualized)
                {
                    if (!is_inside_sec(addr, proc_inform.coped_mem, &proc_inform.sec_list[cur_sec_id]))
                    {
                        return FALSE;
                    }
                }
                else if(wrapper_info->count_dis >= 15) //check after dis first call
                {
                    if (!inside_sec_prot(proc_inform,addr))
                    {

                        return FALSE;
                    }
                }
 

                //Faster will be emulate ~150 instr
                if (recurs >= MAX_RECURS_EXECUTE || jcc >= MAX_JCC_EXECUTE)
                {
                    return TRUE;
                }

                //check exist by in logic zydis push eflag change eflag...
                if (
                    exist_push_eflag &&
#ifndef _WIN64
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD
#else
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ
#endif // !_WIN64
                    )
                {
                    wrapper_info->count_push_eflag++;
                }

                if (exist_push_eflag && !wrapper_info->count_push_eflag)
                {
                    if (dis::is_change_eflag(&dis_code))
                    {
                        return FALSE;
                    }

                    if (dis::is_check_eflag(&dis_code))
                    {
                        return FALSE;
                    }
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_RDTSC ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CPUID ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_SYSENTER
                    )
                {
                    return FALSE;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL &&
                    dis_code.info.operand_count_visible == 1 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    )
                {
                    wrapper_info->count_call_imm++;
                }

                if(dis::is_jññ(&dis_code))
                {
                    //pos_addr;
                    memcpy(&cur_wrapper_info, wrapper_info, sizeof(cur_wrapper_info));
                    pos_addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, reinterpret_cast<CHAR*>(dis_code.runtime_address)));
                    cur_wrapper_info.count_dis++;
                    if (inside_sec_prot(proc_inform, pos_addr))
                    {
                        recurs++;
                        if (get_wrapper_vmp(proc_inform, pos_addr,  cur_sec_id, &cur_wrapper_info,is_virtualized,exist_push_eflag , recurs,  jcc))
                        {
                            return TRUE;
                        }
                    }
                    jcc++;
                }
                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
#ifndef _WIN64
                    dis_code.operands[1].mem.base == ZYDIS_REGISTER_ESP
#else
                    dis_code.operands[1].mem.base == ZYDIS_REGISTER_RSP
#endif // !_WIN64
                    )
                {
                    wrapper_info->reg_base = dis_code.operands[NULL].reg.value;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (
                        dis_code.operands[1].mem.base == wrapper_info->reg_base ||
                        dis_code.operands[1].mem.index == wrapper_info->reg_base
                        )
                    )
                {
                    wrapper_info->count_read_obf_imp++;
                }

                if (
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_LEA &&
                    dis_code.info.operand_count_visible == 2 &&
                    dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    dis_code.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dis_code.operands[1].mem.base == wrapper_info->reg_base &&
                    dis_code.operands[1].mem.disp.has_displacement
                    )
                {
                    wrapper_info->count_decrypt_imp++;
                    if (
                        wrapper_info->count_decrypt_imp &&
                        wrapper_info->count_call_imm &&
                        wrapper_info->count_read_obf_imp 
                        )
                    {
                        wrapper_info->addr_decrypt_imp = reinterpret_cast<size_t>(addr);
                        return TRUE;
                    }
                }

                if (dis_code.info.mnemonic == ZYDIS_MNEMONIC_JMP ||
                    dis_code.info.mnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    if (
                        dis_code.info.operand_count_visible == 1 &&
                        dis_code.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                        )
                    {
                        addr = reinterpret_cast<uint8_t*>(dis::get_absolute_address(&dis_code, addr));
                        if (!inside_sec_prot(proc_inform, addr)) //address outside sec
                        {
                            return FALSE;
                        }
                    }
                    else
                    {
                        return FALSE;
                    }
                }
                else
                {
                    addr += dis_code.info.length;
                } 
            }
            else
            {
                return FALSE;
            }
            wrapper_info->count_dis++;
        }
        return  FALSE;
    }

    NO_INLINE auto scan_obf_imp(std::vector<protector_imp_info>& imp_list, proc_info& proc_inform, BOOLEAN is_disassembly_check = FALSE) -> uint32_t
    {
        uint32_t imp_count_get = NULL;
        uint32_t imp_count_emul = NULL;
        protector_imp_info cur_imp_prot = { NULL };
        VMP_IMP_WRAPPER_DIS_NEXT cur_vmp_next_wrapper_info = { NULL };
        VMP_IMP_WRAPPER_DIS cur_vmp_wrapper_info = { NULL };
        THEMIDA_IMP_WRAPPER_DIS cur_themida_wrapper_info = { NULL };

        if (
            proc_inform.prot_type == prot_vmp
            )
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (
                    proc_inform.sec_list[sec_id].sec_type_info == sec_type_prog &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                    )
                {
                    for (size_t offset = NULL; offset < proc_inform.sec_list[sec_id].virt_size; offset++)
                    {
                        if (
                            *reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_IMM_CALL
                            )
                        {
                          
                            cur_imp_prot.count_command = NULL;
                            cur_imp_prot.is_virtulized = FALSE;
                            cur_imp_prot.is_get_imp = FALSE;
                            cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                            memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));

                            if (get_dis_import_vmp_old(proc_inform, &cur_imp_prot,reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), proc_inform.sec_list[sec_id].rva, FALSE))
                            {
                                if (!is_exist_imp(imp_list, &cur_imp_prot))
                                {
                                    imp_count_get++;
                                    imp_list.push_back(cur_imp_prot);
                                }
                             }
                            else 
                            {
                                memset(&cur_vmp_next_wrapper_info, NULL, sizeof(cur_vmp_next_wrapper_info));
                                memset(&cur_vmp_wrapper_info, NULL, sizeof(cur_vmp_wrapper_info));

                                if (
                                   get_next_wrapper_vmp(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id, &cur_vmp_next_wrapper_info,FALSE, TRUE, NULL, NULL) ||
                                    get_wrapper_vmp(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id, &cur_vmp_wrapper_info, FALSE, TRUE, NULL, NULL)
                                    )
                                {
                                    cur_imp_prot.count_command = NULL;
                                    cur_imp_prot.is_virtulized = FALSE;
                                    cur_imp_prot.is_get_imp = FALSE;
                                    cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                                    memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));

                                    emul_code::safe_init_emu(proc_inform, &cur_imp_prot, reinterpret_cast<size_t>(proc_inform.coped_mem), EMUL_IMP_VMP, FALSE);
                                    if (cur_imp_prot.is_get_imp && !is_exist_imp(imp_list, &cur_imp_prot))
                                    {
                                        imp_count_get++;
                                        imp_list.push_back(cur_imp_prot);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (
            proc_inform.prot_type == prot_themida
            )
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (
                    proc_inform.sec_list[sec_id].sec_type_info == sec_type_prog &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                    )
                {
                    for (size_t offset = NULL; offset < proc_inform.sec_list[sec_id].virt_size; offset++)
                    {
                        if (
                            *reinterpret_cast<uint16_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_PTR_CALL ||
                            *reinterpret_cast<uint16_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_PTR_JMP
                            )
                        {
                            memset(&cur_themida_wrapper_info, NULL, sizeof(cur_themida_wrapper_info));


                            if (get_wrapper_themida(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id, &cur_themida_wrapper_info, FALSE))
                            {

                                cur_imp_prot.count_command = NULL;
                                cur_imp_prot.is_virtulized = FALSE;
                                cur_imp_prot.is_get_imp = FALSE;
                                cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                                memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));

                                emul_code::safe_init_emu(proc_inform, &cur_imp_prot, reinterpret_cast<size_t>(proc_inform.coped_mem), EMUL_IMP_THEMIDA, FALSE);
                                if (cur_imp_prot.is_get_imp && !is_exist_imp(imp_list, &cur_imp_prot))
                                {
                                    imp_count_get++;
                                    imp_list.push_back(cur_imp_prot);
                                }
                            }
                        }
                    }
                }
            }

        }
         
        return imp_count_get;
    }

    NO_INLINE auto scan_virt_imp(std::vector<protector_imp_info>& imp_list, proc_info& proc_inform) -> uint32_t
    {
        uint32_t imp_count_get = NULL;
        uint32_t imp_count_emul = NULL;
        protector_imp_info cur_imp_prot = { NULL };
        VMP_IMP_WRAPPER_DIS cur_wrapper_info = { NULL };
        VMP_IMP_WRAPPER_DIS_NEXT cur_next_wrapper_info = { NULL };
        THEMIDA_IMP_WRAPPER_DIS cur_themida_wrapper_info = { NULL };

        if (
            proc_inform.prot_type == prot_vmp
            )
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (
                    proc_inform.sec_list[sec_id].sec_type_info == sec_type_prot &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                    )
                {
                    for (size_t offset = NULL; offset < proc_inform.sec_list[sec_id].virt_size; offset++)
                    {

                        if (
                            *reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_NOP
                            )
                        {
                            cur_imp_prot.count_command = NULL;
                            cur_imp_prot.is_virtulized = FALSE;
                            cur_imp_prot.is_get_imp = FALSE;
                            cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                            memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));

                            if (get_dis_import_vmp_old(proc_inform, &cur_imp_prot, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), proc_inform.sec_list[sec_id].rva, TRUE))
                            {
                                if (!is_exist_imp(imp_list, &cur_imp_prot))
                                {
                                    imp_count_get++;
                                    imp_list.push_back(cur_imp_prot);
                                }
                            }
                        }
                

                        if (
                            *reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_IMM_CALL ||
                            is_push(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset)) ||
                            is_push_eflag(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset)) ||
                            is_pop(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset)) ||
                            is_vsp_change(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset))
                            )
                        {
                            //disassembly and check                             
                            memset(&cur_next_wrapper_info, NULL, sizeof(cur_next_wrapper_info));
                            memset(&cur_wrapper_info, NULL, sizeof(cur_wrapper_info));
 
                           if (
                               get_next_wrapper_vmp(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id, &cur_next_wrapper_info, TRUE,TRUE, NULL, NULL) ||
                               get_wrapper_vmp(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id,&cur_wrapper_info,TRUE, TRUE,NULL,NULL)
                               )
                            {
                                //emul

                               cur_imp_prot.count_command = NULL;
                               cur_imp_prot.is_virtulized = TRUE;
                               cur_imp_prot.is_get_imp = FALSE;
                               cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                               memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));
                               emul_code::safe_init_emu(proc_inform, &cur_imp_prot, reinterpret_cast<size_t>(proc_inform.coped_mem), EMUL_IMP_VMP, FALSE);
                                if (cur_imp_prot.is_get_imp && !is_exist_imp(imp_list, &cur_imp_prot))
                                {
                                    imp_count_get++;
                                    imp_list.push_back(cur_imp_prot);
                                }
                            }
                        }
                    }
                }
            }
        }

        if (
            proc_inform.prot_type == prot_themida
            )
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (
                    proc_inform.sec_list[sec_id].sec_type_info == sec_type_prot &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_WRITE) &&
                    (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                    )
                {
                    for (size_t offset = NULL; offset < proc_inform.sec_list[sec_id].virt_size; offset++)
                    {  
                        if (
                            is_push(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset)) ||
                            *reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset) == OPCODE_PUSH_IMM ||
                            is_vsp_change(reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset))
                            )
                        {
                            memset(&cur_themida_wrapper_info, NULL, sizeof(cur_themida_wrapper_info));
                             
                            if (get_wrapper_themida(proc_inform, reinterpret_cast<uint8_t*>(proc_inform.sec_list[sec_id].sec_addr_coped + offset), sec_id, &cur_themida_wrapper_info, FALSE))
                            {
                                //add disassembly
                                cur_imp_prot.count_command = NULL;
                                cur_imp_prot.is_virtulized = FALSE;
                                cur_imp_prot.is_get_imp = FALSE;
                                cur_imp_prot.addr_wrapper_imp = reinterpret_cast<size_t>(proc_inform.sec_list[sec_id].sec_addr_coped) + offset;
                                memset(&cur_imp_prot.command[NULL], NULL, sizeof(cur_imp_prot.command));

                                emul_code::safe_init_emu(proc_inform, &cur_imp_prot, reinterpret_cast<size_t>(proc_inform.coped_mem), EMUL_IMP_THEMIDA, FALSE);
                                if (cur_imp_prot.is_get_imp && !is_exist_imp(imp_list, &cur_imp_prot))
                                {
                                    imp_count_get++;
                                    imp_list.push_back(cur_imp_prot);
                                }
                            }
                        }
                    }
                }
            }
        }
        for (size_t i = NULL; i < imp_count_emul; i++)
        {

        }
        return imp_count_get;
    }

}
#endif // !IMPORT_SCAN
