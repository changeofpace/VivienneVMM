/*++

Module Name:
    
    arch.h

Abstract:

    This header defines AMD64-specific types.

Author:

    changeofpace

Environment:

    Kernel and user mode.

--*/

#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <Windows.h>
#endif

//=============================================================================
// Paging
//=============================================================================
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

//=============================================================================
// Registers
//=============================================================================
typedef enum _X64_REGISTER
{
    REGISTER_INVALID = 0,

    //
    // General purpose or integer registers.
    //
    REGISTER_RIP,
    REGISTER_RAX,
    REGISTER_RCX,
    REGISTER_RDX,
    REGISTER_RDI,
    REGISTER_RSI,
    REGISTER_RBX,
    REGISTER_RBP,
    REGISTER_RSP,
    REGISTER_R8,
    REGISTER_R9,
    REGISTER_R10,
    REGISTER_R11,
    REGISTER_R12,
    REGISTER_R13,
    REGISTER_R14,
    REGISTER_R15,
    REGISTER_GP_MIN = REGISTER_RIP,
    REGISTER_GP_MAX = REGISTER_R15,

    //
    // SSE / AVX registers.
    //
    REGISTER_XMM0,
    REGISTER_XMM1,
    REGISTER_XMM2,
    REGISTER_XMM3,
    REGISTER_XMM4,
    REGISTER_XMM5,
    REGISTER_XMM6,
    REGISTER_XMM7,
    REGISTER_XMM8,
    REGISTER_XMM9,
    REGISTER_XMM10,
    REGISTER_XMM11,
    REGISTER_XMM12,
    REGISTER_XMM13,
    REGISTER_XMM14,
    REGISTER_XMM15,
    REGISTER_XMM_LIMIT = REGISTER_XMM15,
    REGISTER_XMM16,
    REGISTER_XMM17,
    REGISTER_XMM18,
    REGISTER_XMM19,
    REGISTER_XMM20,
    REGISTER_XMM21,
    REGISTER_XMM22,
    REGISTER_XMM23,
    REGISTER_XMM24,
    REGISTER_XMM25,
    REGISTER_XMM26,
    REGISTER_XMM27,
    REGISTER_XMM28,
    REGISTER_XMM29,
    REGISTER_XMM30,
    REGISTER_XMM31,
    REGISTER_XMM_MIN = REGISTER_XMM0,
    REGISTER_XMM_MAX = REGISTER_XMM31,

    REGISTER_YMM0,
    REGISTER_YMM1,
    REGISTER_YMM2,
    REGISTER_YMM3,
    REGISTER_YMM4,
    REGISTER_YMM5,
    REGISTER_YMM6,
    REGISTER_YMM7,
    REGISTER_YMM8,
    REGISTER_YMM9,
    REGISTER_YMM10,
    REGISTER_YMM11,
    REGISTER_YMM12,
    REGISTER_YMM13,
    REGISTER_YMM14,
    REGISTER_YMM15,
    REGISTER_YMM_LIMIT = REGISTER_YMM15,
    REGISTER_YMM16,
    REGISTER_YMM17,
    REGISTER_YMM18,
    REGISTER_YMM19,
    REGISTER_YMM20,
    REGISTER_YMM21,
    REGISTER_YMM22,
    REGISTER_YMM23,
    REGISTER_YMM24,
    REGISTER_YMM25,
    REGISTER_YMM26,
    REGISTER_YMM27,
    REGISTER_YMM28,
    REGISTER_YMM29,
    REGISTER_YMM30,
    REGISTER_YMM31,
    REGISTER_YMM_MIN = REGISTER_YMM0,
    REGISTER_YMM_MAX = REGISTER_YMM31,

    REGISTER_ZMM0,
    REGISTER_ZMM1,
    REGISTER_ZMM2,
    REGISTER_ZMM3,
    REGISTER_ZMM4,
    REGISTER_ZMM5,
    REGISTER_ZMM6,
    REGISTER_ZMM7,
    REGISTER_ZMM8,
    REGISTER_ZMM9,
    REGISTER_ZMM10,
    REGISTER_ZMM11,
    REGISTER_ZMM12,
    REGISTER_ZMM13,
    REGISTER_ZMM14,
    REGISTER_ZMM15,
    REGISTER_ZMM_LIMIT = REGISTER_ZMM15,
    REGISTER_ZMM16,
    REGISTER_ZMM17,
    REGISTER_ZMM18,
    REGISTER_ZMM19,
    REGISTER_ZMM20,
    REGISTER_ZMM21,
    REGISTER_ZMM22,
    REGISTER_ZMM23,
    REGISTER_ZMM24,
    REGISTER_ZMM25,
    REGISTER_ZMM26,
    REGISTER_ZMM27,
    REGISTER_ZMM28,
    REGISTER_ZMM29,
    REGISTER_ZMM30,
    REGISTER_ZMM31,
    REGISTER_ZMM_MIN = REGISTER_ZMM0,
    REGISTER_ZMM_MAX = REGISTER_ZMM31,

} X64_REGISTER, *PX64_REGISTER;

#pragma warning(push) // Nonstandard extension used: nameless struct/union
#pragma warning(disable : 4201)
typedef struct _RFLAGS
{
    union
    {
        ULONG_PTR All;
        struct
        {
            ULONG_PTR CF        : 1;    // [0]
            ULONG_PTR Reserved1 : 1;    // [1]
            ULONG_PTR PF        : 1;    // [2]
            ULONG_PTR Reserved2 : 1;    // [3]
            ULONG_PTR AF        : 1;    // [4]
            ULONG_PTR Reserved3 : 1;    // [5]
            ULONG_PTR ZF        : 1;    // [6]
            ULONG_PTR SF        : 1;    // [7]
            ULONG_PTR TF        : 1;    // [8]
            ULONG_PTR INTF      : 1;    // [9]
            ULONG_PTR DF        : 1;    // [10]
            ULONG_PTR OF        : 1;    // [11]
            ULONG_PTR IOPL      : 2;    // [12]
            ULONG_PTR NT        : 1;    // [13]
            ULONG_PTR Reserved4 : 1;    // [14]
            ULONG_PTR RF        : 1;    // [15]
            ULONG_PTR VM        : 1;    // [16]
            ULONG_PTR AC        : 1;    // [17]
            ULONG_PTR VIF       : 1;    // [18]
            ULONG_PTR VIP       : 1;    // [19]
            ULONG_PTR ID        : 1;    // [20]
            ULONG_PTR Reserved5 : 10;   // [21:30]
            ULONG_PTR Reserved6 : 1;    // [31]
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} RFLAGS, *PRFLAGS;
#pragma warning(pop)

//=============================================================================
// Instructions
//=============================================================================

//
// SIB bytes.
//
typedef enum SCALE_FACTOR
{
    SCALE_INVALID = 0,
    SCALE_BYTE = 1,
    SCALE_WORD = 2,
    SCALE_DWORD = 4,
    SCALE_QWORD = 8,
} SCALE_FACTOR, *PSCALE_FACTOR;

//
// Addressing modes.
//
typedef struct _INDIRECT_ADDRESS
{
    X64_REGISTER BaseRegister;
    X64_REGISTER IndexRegister;
    SCALE_FACTOR ScaleFactor;
    LONG_PTR Displacement;
} INDIRECT_ADDRESS, *PINDIRECT_ADDRESS;

//=============================================================================
// Hardware Breakpoints
//=============================================================================
#define DAR_COUNT   4
#define DR_COUNT    8

//
// Masks to determine the debug address register which caused a debug exception.
//
#define DB_DR0_MASK    (1 << 0)
#define DB_DR1_MASK    (1 << 1)
#define DB_DR2_MASK    (1 << 2)
#define DB_DR3_MASK    (1 << 3)

//
// Translate met breakpoint conditions specified by a debug exception exit
//  qualification to their corresponding debug address register.
//
#define DAR_INDEX_TO_BITMAP(Index) (1ull << Index)

typedef enum class _HWBP_TYPE
{
    Execute = 0,
    Write = 1,
    Io = 2,
    Access = 3,
    Undefined
} HWBP_TYPE, *PHWBP_TYPE;

typedef enum class _HWBP_SIZE
{
    Byte = 0,
    Word = 1,
    Qword = 2,
    Dword = 3,
    Undefined
} HWBP_SIZE, *PHWBP_SIZE;

//
// HwBpSizeToBytes
//
FORCEINLINE
ULONG
HwBpSizeToBytes(
    _In_ HWBP_SIZE BreakpointSize
)
{
    switch (BreakpointSize)
    {
        case HWBP_SIZE::Byte:   return sizeof(unsigned __int8);
        case HWBP_SIZE::Word:   return sizeof(unsigned __int16);
        case HWBP_SIZE::Qword:  return sizeof(unsigned __int64);
        case HWBP_SIZE::Dword:  return sizeof(unsigned __int32);
        default:                return 0;
    }
}

#pragma warning(push) // Nonstandard extension used: nameless struct/union
#pragma warning(disable : 4201)
typedef struct _DR6
{
    union
    {
        ULONG_PTR All;
        struct
        {
            ULONG_PTR B0 : 1;           // [0]
            ULONG_PTR B1 : 1;           // [1]
            ULONG_PTR B2 : 1;           // [2]
            ULONG_PTR B3 : 1;           // [3]
            ULONG_PTR Reserved1 : 8;    // [4:11]
            ULONG_PTR Reserved2 : 1;    // [12]
            ULONG_PTR BD : 1;           // [13]
            ULONG_PTR BS : 1;           // [14]
            ULONG_PTR BT : 1;           // [15]
            ULONG_PTR RTM : 1;          // [16]
            ULONG_PTR Reserved3 : 15;   // [17:31]
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} DR6, *PDR6;
#pragma warning(pop)

#pragma warning(push) // Nonstandard extension used: nameless struct/union
#pragma warning(disable : 4201)
typedef struct _DR7
{
    union
    {
        ULONG_PTR All;
        struct
        {
            ULONG_PTR L0 : 1;       // [0]
            ULONG_PTR G0 : 1;       // [1]
            ULONG_PTR L1 : 1;       // [2]
            ULONG_PTR G1 : 1;       // [3]
            ULONG_PTR L2 : 1;       // [4]
            ULONG_PTR G2 : 1;       // [5]
            ULONG_PTR L3 : 1;       // [6]
            ULONG_PTR G3 : 1;       // [7]

            ULONG_PTR LE : 1;       // [8]
            ULONG_PTR GE : 1;       // [9]
            ULONG_PTR Reserved1 : 1;// [10]
            ULONG_PTR RTM  : 1;     // [11]
            ULONG_PTR ICE  : 1;     // [12]
            ULONG_PTR GD   : 1;     // [13]
            ULONG_PTR TR1  : 1;     // [14]
            ULONG_PTR TR2  : 1;     // [15]

            ULONG_PTR RW0  : 2;     // [16:17]
            ULONG_PTR Len0 : 2;     // [18:19]
            ULONG_PTR RW1  : 2;     // [20:21]
            ULONG_PTR Len1 : 2;     // [22:23]
            ULONG_PTR RW2  : 2;     // [24:25]
            ULONG_PTR Len2 : 2;     // [26:27]
            ULONG_PTR RW3  : 2;     // [28:29]
            ULONG_PTR Len3 : 2;     // [30:31]
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} DR7, *PDR7;
#pragma warning(pop)
