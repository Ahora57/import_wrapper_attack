#ifndef GET_PROTECTOR_TYPE
#define GET_PROTECTOR_TYPE 1
#include "struct.h"
namespace prot_type_use
{

    //add more check
    auto check_vmp_sec(proc_info& proc_inform) -> BOOLEAN
    {
        BOOLEAN is_vmp = FALSE;
        uint32_t sec_execute_count = NULL;

        //.text, .vmp0, vmp1
        for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
        {
            if (
                (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                )
            {
                sec_execute_count++;
            }
        }

        if (sec_execute_count >= 3)
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                //ep addr sec is execute and read
                if (
                    sec_id &&
                    (
                        proc_inform.ep >= proc_inform.sec_list[sec_id].rva &&
                        proc_inform.sec_list[sec_id].rva + proc_inform.sec_list[sec_id].virt_size > proc_inform.ep
                        )
                    &&
                    (
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                        )
                    )
                {
                    if (
                        sec_id >= 1 &&
                        (proc_inform.sec_list[sec_id - 1].characteris & IMAGE_SCN_MEM_READ) &&
                        (proc_inform.sec_list[sec_id - 1].characteris & IMAGE_SCN_MEM_EXECUTE)
                        )
                    {
                        //possible vmp 3.x - 3.5
                        //add pattern vmp_get_proc_addree and check imp:LoadLibraryA GetModuleHandleA GetProcAddress
                        proc_inform.sec_list[sec_id].sec_type_info = sec_type_prot;
                        proc_inform.sec_list[sec_id - 1].sec_type_info = sec_type_prot;
                        is_vmp = TRUE;
                        break;
                    }

                    if (
                        sec_id >= 2 &&
                        (proc_inform.sec_list[sec_id - 1].characteris & IMAGE_SCN_MEM_READ) &&
                        !(proc_inform.sec_list[sec_id - 1].characteris & IMAGE_SCN_MEM_EXECUTE) &&
                        (proc_inform.sec_list[sec_id - 2].characteris & IMAGE_SCN_MEM_READ) &&
                        (proc_inform.sec_list[sec_id - 2].characteris & IMAGE_SCN_MEM_EXECUTE)
                        )
                    {
                        //possible vmp 3.6 - 3.10.x
                         //add pattern anti-vm? vmp_strcmp?
                        proc_inform.sec_list[sec_id].sec_type_info = sec_type_prot;
                        proc_inform.sec_list[sec_id - 1].sec_type_info = sec_type_prot;
                        proc_inform.sec_list[sec_id - 2].sec_type_info = sec_type_prot;

                        is_vmp = TRUE;
                        break;
                    }
                }
            }
        }

        if (is_vmp)
        {
            proc_inform.prot_type = prot_vmp;
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (proc_inform.sec_list[sec_id].sec_type_info != sec_type_prot)
                {
                    proc_inform.sec_list[sec_id].sec_type_info = sec_type_prog;
                }

            }
        }
        return is_vmp;
    }

    auto check_themida_sec(proc_info& proc_inform) -> BOOLEAN
    {
        BOOLEAN is_themida = FALSE;
        uint32_t sec_execute_count = NULL;

        //.text, .vmp0, vmp1
        for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
        {
            if (
                (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                )
            {
                sec_execute_count++;
            }
        }

        if (sec_execute_count >= 2)
        {
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                //ep addr sec is execute and read
                if (
                    sec_id &&
                    (
                        proc_inform.ep >= proc_inform.sec_list[sec_id].rva &&
                        proc_inform.sec_list[sec_id].rva + proc_inform.sec_list[sec_id].virt_size > proc_inform.ep
                    )
                    )
                {
                    if (
                        sec_id >= 1 &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_WRITE) &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE) &&
                        (proc_inform.sec_list[sec_id-1].characteris & IMAGE_SCN_MEM_READ)&&
                        (proc_inform.sec_list[sec_id-1].characteris & IMAGE_SCN_MEM_WRITE)
                        )
                    {
						proc_inform.sec_list[sec_id].sec_type_info = sec_type_prot;
                        proc_inform.sec_list[sec_id - 1].sec_type_info = sec_type_prot;
                        is_themida = TRUE;
                    }
                    else if (
                        sec_id >= 2 &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_READ) &&
                        !(proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_WRITE) &&
                        (proc_inform.sec_list[sec_id].characteris & IMAGE_SCN_MEM_EXECUTE)
                        )
                    {
                        if (
                            (proc_inform.sec_list[sec_id-1].characteris & IMAGE_SCN_MEM_READ) &&
                            (proc_inform.sec_list[sec_id-1].characteris & IMAGE_SCN_MEM_WRITE) &&
                            (proc_inform.sec_list[sec_id-1].characteris & IMAGE_SCN_MEM_EXECUTE) &&
                            (proc_inform.sec_list[sec_id-2].characteris & IMAGE_SCN_MEM_EXECUTE) &&
                            !(proc_inform.sec_list[sec_id - 2].characteris & IMAGE_SCN_MEM_READ) &&
                            (proc_inform.sec_list[sec_id - 2].characteris & IMAGE_SCN_MEM_WRITE)
                            )
                        {
							proc_inform.sec_list[sec_id].sec_type_info = sec_type_prot;
							proc_inform.sec_list[sec_id - 1].sec_type_info = sec_type_prot;
							proc_inform.sec_list[sec_id - 2].sec_type_info = sec_type_prot;
                            is_themida = TRUE;
                        }
                    }
                }
            }
        }
        
        if (is_themida)
        {
            proc_inform.prot_type = prot_themida;
            for (size_t sec_id = NULL; sec_id < proc_inform.sec_list.size(); sec_id++)
            {
                if (proc_inform.sec_list[sec_id].sec_type_info != sec_type_prot)
                {
                    proc_inform.sec_list[sec_id].sec_type_info = sec_type_prog;
                }

            }
        }
        return is_themida;
    }
}
#endif // !GET_PROTECTOR_TYPE
