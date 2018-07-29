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
// General Purpose Registers
//=============================================================================
#define REGISTER_INVALID    0x00000001
#define REGISTER_RIP        0x00000002
#define REGISTER_RAX        0x00000004
#define REGISTER_RCX        0x00000008
#define REGISTER_RDX        0x00000010
#define REGISTER_RDI        0x00000020
#define REGISTER_RSI        0x00000040
#define REGISTER_RBX        0x00000080
#define REGISTER_RBP        0x00000100
#define REGISTER_RSP        0x00000200
#define REGISTER_R8         0x00000400
#define REGISTER_R9         0x00000800
#define REGISTER_R10        0x00001000
#define REGISTER_R11        0x00002000
#define REGISTER_R12        0x00004000
#define REGISTER_R13        0x00008000
#define REGISTER_R14        0x00010000
#define REGISTER_R15        0x00020000

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
        case HWBP_SIZE::Byte:   return 1;
        case HWBP_SIZE::Word:   return 2;
        case HWBP_SIZE::Qword:  return 8;
        case HWBP_SIZE::Dword:  return 4;
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