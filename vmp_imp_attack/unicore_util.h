#ifndef UNICORE_UTIL
#define UNICORE_UTIL 1
#include "struct.h"
#include "disassembly_util.h"
#include <unicorn/unicorn.h>


#ifndef STACK_SIZE
#define STACK_SIZE 10 * 0x1000
#endif // !STACK_SIZE


#ifndef EMU_MODE
#ifndef _WIN64
#define EMU_MODE UC_MODE_32
#define REG_VSP UC_X86_REG_ESP
#define REG_VIP UC_X86_REG_EIP
#define REG_RAX UC_X86_REG_EAX
#define REG_RCX UC_X86_REG_ECX
#define REG_RDX UC_X86_REG_EDX
#define REG_RBX UC_X86_REG_EBX
#define REG_RBP UC_X86_REG_EBP
#define REG_RSI UC_X86_REG_ESI
#define REG_RDI UC_X86_REG_EDI
#else
#define EMU_MODE UC_MODE_64
#define REG_VSP UC_X86_REG_RSP
#define REG_VIP UC_X86_REG_RIP
#define REG_RAX UC_X86_REG_RAX
#define REG_RCX UC_X86_REG_RCX
#define REG_RDX UC_X86_REG_RDX
#define REG_RBX UC_X86_REG_RBX
#define REG_RBP UC_X86_REG_RBP
#define REG_RSI UC_X86_REG_RSI
#define REG_RDI UC_X86_REG_RDI

#define REG_R8 UC_X86_REG_R8
#define REG_R9 UC_X86_REG_R9
#define REG_R10 UC_X86_REG_R10
#define REG_R11 UC_X86_REG_R11
#define REG_R12 UC_X86_REG_R12
#define REG_R13 UC_X86_REG_R13
#define REG_R14 UC_X86_REG_R14
#define REG_R15 UC_X86_REG_R15 
#endif // !_WIN64 
#endif // !EMU_MODE

namespace unicore_util
{
 
    //sorry for the code, but FUCK wrong order and "magic" +old +2
   // 
   //ZYDIS_REGISTER_RAX,
   //ZYDIS_REGISTER_RCX,
   //ZYDIS_REGISTER_RDX,
   //ZYDIS_REGISTER_RBX,
   //ZYDIS_REGISTER_RSP,
   //ZYDIS_REGISTER_RBP,
   //ZYDIS_REGISTER_RSI,
   //ZYDIS_REGISTER_RDI,
   //ZYDIS_REGISTER_R8,
   //ZYDIS_REGISTER_R9,
   //ZYDIS_REGISTER_R10,
   //ZYDIS_REGISTER_R11,
   //ZYDIS_REGISTER_R12,
   //ZYDIS_REGISTER_R13,
   //ZYDIS_REGISTER_R14,
   //ZYDIS_REGISTER_R15,
   //
   //UC_X86_REG_RAX,
   //UC_X86_REG_RBP,
   //UC_X86_REG_RBX,
   //UC_X86_REG_RCX,
   //UC_X86_REG_RDI,
   //UC_X86_REG_RDX,
   //UC_X86_REG_RIP,
   //UC_X86_REG_RSI = UC_X86_REG_RIP + 2,
   //UC_X86_REG_RSP,

    auto reg_conv(ZydisRegister* reg) -> uint32_t
    {  
        ZydisRegister zydis_reg[] =
        {
            ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
            ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP,
            ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,
            ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
            ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14,
            ZYDIS_REGISTER_R15, ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX,
            ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_ESP,
            ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_EDI,
            ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R10D,
            ZYDIS_REGISTER_R11D,ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D,
            ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D, ZYDIS_REGISTER_AX,
            ZYDIS_REGISTER_CX,  ZYDIS_REGISTER_DX,  ZYDIS_REGISTER_BX,
            ZYDIS_REGISTER_SP,  ZYDIS_REGISTER_BP,  ZYDIS_REGISTER_SI,
            ZYDIS_REGISTER_DI,  ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R9W,
            ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R11W, ZYDIS_REGISTER_R12W,
            ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R15W,
            ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_CL,  ZYDIS_REGISTER_DL,
            ZYDIS_REGISTER_BL,  ZYDIS_REGISTER_AH,  ZYDIS_REGISTER_CH,
            ZYDIS_REGISTER_DH,  ZYDIS_REGISTER_BH,  ZYDIS_REGISTER_SPL,
            ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_SIL, ZYDIS_REGISTER_DIL,
            ZYDIS_REGISTER_R8B, ZYDIS_REGISTER_R9B, ZYDIS_REGISTER_R10B,
            ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B,
            ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,
            ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_EIP
        };

        uint32_t  uc_reg[] =
      {
            UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,
            UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_EAX, UC_X86_REG_ECX,
            UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP,
            UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
            UC_X86_REG_R8D, UC_X86_REG_R9D, UC_X86_REG_R10D,
            UC_X86_REG_R11D, UC_X86_REG_R12D, UC_X86_REG_R13D,
            UC_X86_REG_R14D, UC_X86_REG_R15D, UC_X86_REG_AX,
            UC_X86_REG_CX,  UC_X86_REG_DX,  UC_X86_REG_BX,
            UC_X86_REG_SP,  UC_X86_REG_BP,  UC_X86_REG_SI,
            UC_X86_REG_DI,  UC_X86_REG_R8W, UC_X86_REG_R9W,
            UC_X86_REG_R10W, UC_X86_REG_R11W, UC_X86_REG_R12W,
            UC_X86_REG_R13W, UC_X86_REG_R14W, UC_X86_REG_R15W,
            UC_X86_REG_AL,  UC_X86_REG_CL,  UC_X86_REG_DL,
            UC_X86_REG_BL,  UC_X86_REG_AH,  UC_X86_REG_CH,
            UC_X86_REG_DH,  UC_X86_REG_BH,  UC_X86_REG_SPL,
            UC_X86_REG_BPL, UC_X86_REG_SIL, UC_X86_REG_DIL,
            UC_X86_REG_R8B, UC_X86_REG_R9B, UC_X86_REG_R10B,
            UC_X86_REG_R11B, UC_X86_REG_R12B, UC_X86_REG_R13B,
            UC_X86_REG_R14B, UC_X86_REG_R15B,
            UC_X86_REG_RIP, UC_X86_REG_EIP
        };

        for (size_t i = NULL; i < _countof(zydis_reg); i++) 
        {
            if (zydis_reg[i] == *reg) 
            {
                return uc_reg[i];
            }
        } 
        return UC_X86_REG_INVALID;
    }

    auto read_reg(uc_engine* uc, ZydisRegister* reg, size_t* value) -> BOOLEAN
    {
        size_t cur_reg = NULL;


        cur_reg = reg_conv(reg);

        if (cur_reg != UC_X86_REG_INVALID)
        {
            return uc_reg_read(uc, cur_reg, value) == UC_ERR_OK;
        }
        return FALSE;
    }

    auto write_reg(uc_engine* uc, ZydisRegister* reg, uint64_t* value) -> BOOLEAN
    {
#ifndef _WIN64
        uint32_t cur_reg = NULL;
#else
        uint64_t cur_reg = NULL;
#endif // !_WIN64

        cur_reg = reg_conv(reg);

        if (cur_reg != UC_X86_REG_INVALID)
        {
            return uc_reg_write(uc, cur_reg, value) == UC_ERR_OK;
        }
        return FALSE;
    }


    /*
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

*/
    NO_INLINE  auto init_reg(uc_engine* uc, uint64_t r_rsp_addr) -> VOID
    {
        uint64_t reg = NULL;
        uc_err err;
        uint8_t stack_null[sizeof(PVOID) * 5] = { NULL };

        err = uc_mem_map(uc, r_rsp_addr, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
        if (err)
        {
            printf("Failed stack alloce uc_mem_map() with error returned: %u\n", err);
        }

        r_rsp_addr = reinterpret_cast<uint64_t>(reinterpret_cast<uint8_t*>(r_rsp_addr) + 0x1000 * 5);
        err = uc_reg_write(uc, REG_VSP, &r_rsp_addr);
        if (err)
        {
            printf("Failed VSP write uc_mem_write() with error returned: %u\n", err);
        }
        err = uc_mem_write(uc, r_rsp_addr, stack_null, sizeof(stack_null));
        if (err)
        {
            printf("Failed stack NULL 1 uc_mem_write() with error returned: %u\n", err);
        }

        err = uc_mem_write(uc, reinterpret_cast<uint64_t>(reinterpret_cast<uint8_t*>(r_rsp_addr) - 20), stack_null, sizeof(stack_null));
        if (err)
        {
            printf("Failed stack NULL 2 uc_mem_write() with error returned: %u\n", err);
        }
        err = uc_mem_write(uc, reinterpret_cast<uint64_t>(reinterpret_cast<uint8_t*>(r_rsp_addr) + 20), stack_null, sizeof(stack_null));
        if (err)
        {
            printf("Failed stack NULL 3 uc_mem_write() with error returned: %u\n", err);
        }
        uc_reg_write(uc, REG_RAX, &reg);
        uc_reg_write(uc, REG_RCX, &reg);
        uc_reg_write(uc, REG_RDX, &reg);
        uc_reg_write(uc, REG_RBX, &reg);
        uc_reg_write(uc, REG_RBP, &reg);
        uc_reg_write(uc, REG_RSI, &reg);
        uc_reg_write(uc, REG_RDI, &reg);


#ifdef _WIN64
        uc_reg_write(uc, REG_R8, &reg);
        uc_reg_write(uc, REG_R9, &reg);
        uc_reg_write(uc, REG_R10, &reg);
        uc_reg_write(uc, REG_R11, &reg);
        uc_reg_write(uc, REG_R12, &reg);
        uc_reg_write(uc, REG_R13, &reg);
        uc_reg_write(uc, REG_R14, &reg);
        uc_reg_write(uc, REG_R15, &reg);
#endif // _WIN64  
    }

    

}
#endif // !UNICORE_UTIL
