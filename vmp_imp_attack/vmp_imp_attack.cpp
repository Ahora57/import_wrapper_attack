#include "process_util.h" 
#include "get_protector.h"
#include "import_scan.h"
 
auto hook_imp_vmp(uint8_t* module_addr, uint32_t rva_pointer, uint32_t crypte_key_add, size_t hook) -> BOOLEAN
{
    BOOLEAN is_set_hook = FALSE;
    DWORD old_prot = NULL;
    HANDLE access = NULL;
    uint8_t* addr_hook = NULL;
    size_t crypted_hook = NULL;

    addr_hook = module_addr + rva_pointer;
    access = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (access)
    {
        if (VirtualProtectEx(access, addr_hook, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_prot))
        {
            crypted_hook = hook - crypte_key_add;
            *reinterpret_cast<size_t*>(addr_hook) = crypted_hook;
            is_set_hook = TRUE;
            VirtualProtectEx(access, addr_hook, sizeof(PVOID), old_prot, &old_prot);
            //MessageBoxW(NULL, L"Hook set!\n", L"Hook set!\n", MB_OK);
        }
        CloseHandle(access);
    }
    return is_set_hook;
}

//The protector sections have RWX permissions, so there is no need to modify page protections.
NO_INLINE auto hook_imp_themida_x32(uint8_t* module_addr, uint32_t rva_pointer, uint32_t crypte_key_xor, uint32_t crypte_key_sub, size_t hook)
{
    BOOLEAN is_set_hook = FALSE;
    DWORD old_prot = NULL;
    HANDLE access = NULL;
    uint8_t* addr_hook = NULL;
    size_t crypted_hook = NULL;

    addr_hook = module_addr + rva_pointer;
    access = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (access)
    {
        if (VirtualProtectEx(access, addr_hook, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_prot))
        {
            crypted_hook = (hook ^ crypte_key_xor) + crypte_key_sub;
            *reinterpret_cast<size_t*>(addr_hook) = crypted_hook;
            is_set_hook = TRUE;
            VirtualProtectEx(access, addr_hook, sizeof(PVOID), old_prot, &old_prot);
            //MessageBoxW(NULL, L"Hook set!\n", L"Hook set!\n", MB_OK);
        }
        CloseHandle(access);
    }
    return is_set_hook;
}

//The protector sections have RWX permissions, so there is no need to modify page protections.
NO_INLINE auto hook_imp_themida_x64(uint8_t* module_addr, uint32_t rva_pointer, uint32_t crypte_key_sub, uint32_t crypte_key_xor_1, uint32_t crypte_key_xor_2, size_t hook)
{
    BOOLEAN is_set_hook = FALSE;
    DWORD old_prot = NULL;
    HANDLE access = NULL;
    uint8_t* addr_hook = NULL;
    size_t crypted_hook = NULL;

    addr_hook = module_addr + rva_pointer;
    access = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (access)
    {
        if (VirtualProtectEx(access, addr_hook, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_prot))
        {
            crypted_hook = (((hook >> 0x20) ^ crypte_key_xor_2) << 0x20);
            crypted_hook |= (((hook & UINT_MAX) ^ crypte_key_xor_1) + crypte_key_sub);
            *reinterpret_cast<size_t*>(addr_hook) = crypted_hook;
            is_set_hook = TRUE;
            VirtualProtectEx(access, addr_hook, sizeof(PVOID), old_prot, &old_prot);
            //MessageBoxW(NULL, L"Hook set!\n", L"Hook set!\n", MB_OK);
        }
        CloseHandle(access);
    }
    return is_set_hook;
}
int main()
{
    BOOLEAN is_get_proc_info = FALSE;
    uint32_t obf_imp_count = NULL;
    uint32_t virt_imp_count = NULL; 
    proc_info proc_inform;
    std::vector<protector_imp_info> imp_list_obf;
    std::vector<protector_imp_info> imp_list_virt;

    SetConsoleTitleW(L"IMPORT");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    is_get_proc_info =  process_help::get_process_inform(proc_inform,L"themida_test_x64_protected.exe", L"themida_test_x64_protected.exe");
    if (is_get_proc_info)
    {
        if (prot_type_use::check_vmp_sec(proc_inform) || prot_type_use::check_themida_sec(proc_inform))
        {
            if (process_help::get_module_list_proc(proc_inform.proc_id, proc_inform.mod_list))
            { 
                obf_imp_count = imp_scan::scan_obf_imp(imp_list_obf, proc_inform);
                virt_imp_count = imp_scan::scan_virt_imp(imp_list_virt, proc_inform);
                 
                printf("\n--------------------[OBFUSCATED]--------------------\n\n");
                printf("[IMP COUNT ->\t%p\n", imp_list_obf.size());

                for (size_t i = NULL; i < imp_list_obf.size(); i++)
                {
                    printf("[OBF MOD NAME] ->\t%ls\n", imp_list_obf[i].mod_name.c_str());
                    printf("[OBF API NAME] ->\t%s\n", imp_list_obf[i].imp_name.c_str());
                    printf("[API RVA CRYPTED PTR] ->\t%x\n", imp_list_obf[i].imp_obf_ptr_rva);

                    for (size_t j = NULL; j < imp_list_obf[i].count_command; j++)
                    {
                        switch (imp_list_obf[i].command[j].type)
                        {
                        case obf_lea:
                        case obf_add:
                        {
                            printf("[KEY] command add\t");
                            break;
                        }
                        case obf_sub:
                        {
                            printf("[KEY] command sub\t");
                            break;
                        }
                        case obf_xor:
                        {
                            printf("[KEY] command xor\t");
                            break;
                        }
                        case obf_and:
                        {
                            printf("[KEY] command and\t");
                            break;
                        }
                        case obf_or:
                        {
                            printf("[KEY] command or\t");
                            break;
                        }
                        default:
                            break;
                        }
                       if (imp_list_obf[i].command[j].type != obf_unk)
                       {
                           printf(" with crypt_key ->\t%x\n", imp_list_obf[i].command[j].imm);
                       }
                    }

                }

                printf("\n--------------------[VIRTUALIZED]--------------------\n\n");
                printf("[IMP COUNT ->\t%p\n", imp_list_virt.size());
                for (size_t i = NULL; i < imp_list_virt.size(); i++)
                {
                    printf("[OBF MOD NAME] ->\t%ls\n", imp_list_virt[i].mod_name.c_str());
                    printf("[OBF API NAME] ->\t%s\n", imp_list_virt[i].imp_name.c_str());
                    printf("[API RVA CRYPTED PTR] ->\t%x\n", imp_list_virt[i].imp_obf_ptr_rva);

                    for (size_t j = NULL; j < imp_list_virt[i].count_command; j++)
                    {
                        switch (imp_list_virt[i].command[j].type)
                        {
                        case obf_lea:
                        case obf_add:
                        {
                            printf("[KEY] command add\t");
                            break;
                        }
                        case obf_sub:
                        {
                            printf("[KEY] command sub\t");
                            break;
                        }
                        case obf_xor:
                        {
                            printf("[KEY] command xor\t");
                            break;
                        }
                        case obf_and:
                        {
                            printf("[KEY] command and\t");
                            break;
                        }
                        case obf_or:
                        {
                            printf("[KEY] command or\t");
                            break;
                        }
                        default:
                            break;
                        }
                        if (imp_list_virt[i].command[j].type != obf_unk)
                        {
                            printf(" with crypt_key ->\t%x\n", imp_list_virt[i].command[j].imm);
                        }
                    }
                }
            }
        }
         
    }
     
    getchar();
    return EXIT_SUCCESS;
}
