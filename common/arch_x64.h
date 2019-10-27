/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

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
typedef enum _X64_REGISTER {
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

#pragma warning(push)
#pragma warning(disable : 4201) // Nonstandard extension: nameless struct/union
typedef struct _RFLAGS {
    union {
        ULONG_PTR All;
        struct {
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
typedef enum SCALE_FACTOR {
    SCALE_INVALID = 0,
    SCALE_BYTE = 1,
    SCALE_WORD = 2,
    SCALE_DWORD = 4,
    SCALE_QWORD = 8,
} SCALE_FACTOR, *PSCALE_FACTOR;

//
// Addressing modes.
//
typedef struct _INDIRECT_ADDRESS {
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
// Masks to determine the debug address register which caused a debug
//  exception.
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

typedef enum class _HWBP_TYPE {
    Execute = 0,
    Write = 1,
    Io = 2,
    Access = 3,
    Undefined
} HWBP_TYPE, *PHWBP_TYPE;

typedef enum class _HWBP_SIZE {
    Byte = 0,
    Word = 1,
    Qword = 2,
    Dword = 3,
    Undefined
} HWBP_SIZE, *PHWBP_SIZE;

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

//
// 17.2.3 Debug Status Register (DR6)
//
// Certain debug exceptions may clear bits 0-3. The remaining contents of the
//  DR6 register are never cleared by the processor. To avoid confusion in
//  identifying debug exceptions, debug handlers should clear the register
//  (except bit 16, which they should set) before returning to the interrupted
//  task.
//
#pragma warning(push)
#pragma warning(disable : 4201) // Nonstandard extension: nameless struct/union
typedef struct _DR6 {
    union {
        ULONG_PTR All;
        struct {
            //
            // B0 through B3 (breakpoint condition detected) flags.
            //
            // Indicates (when set) that its associated breakpoint condition
            //  was met when a debug exception was generated. These flags are
            //  set if the condition described for each breakpoint by the LENn,
            //  and R/Wn flags in debug control register DR7 is true. They may
            //  or may not be set if the breakpoint is not enabled by the Ln or
            //  the Gn flags in register DR7. Therefore on a #DB, a debug
            //  handler should check only those B0-B3 bits which correspond to
            //  an enabled breakpoint.
            //
            ULONG_PTR B0 : 1;           // [0]
            ULONG_PTR B1 : 1;           // [1]
            ULONG_PTR B2 : 1;           // [2]
            ULONG_PTR B3 : 1;           // [3]

            //
            // Reserved bits (always set). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR Reserved1 : 8;    // [4:11]

            //
            // Reserved bit (always unset). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR Reserved2 : 1;    // [12]

            //
            // BD (debug register access detected) flag.
            //
            // Indicates that the next instruction in the instruction stream
            //  accesses one of the debug registers (DR0 through DR7). This
            //  flag is enabled when the GD (general detect) flag in debug
            //  control register DR7 is set. See Section 17.2.4, "Debug Control
            //  Register (DR7)," for further explanation of the purpose of this
            //  flag.
            //
            ULONG_PTR BD : 1;           // [13]

            //
            // BS (single step) flag.
            //
            // Indicates (when set) that the debug exception was triggered by
            //  the single-step execution mode (enabled with the TF flag in the
            //  EFLAGS register). The single-step mode is the highest-priority
            //  debug exception. When the BS flag is set, any of the other
            //  debug status bits also may be set.
            //
            ULONG_PTR BS : 1;           // [14]

            //
            // BT (task switch) flag.
            //
            // Indicates (when set) that the debug exception resulted from a
            //  task switch where the T flag (debug trap flag) in the TSS of
            //  the target task was set. See Section 7.2.1, "Task-State Segment
            //  (TSS)," for the format of a TSS. There is no flag in debug
            //  control register DR7 to enable or disable this exception; the
            //  T flag of the TSS is the only enabling flag.
            //
            ULONG_PTR BT : 1;           // [15]

            //
            // RTM (restricted transactional memory).
            //
            // Indicates (when clear) that a debug exception (#DB) or
            //  breakpoint exception (#BP) occurred inside an RTM region while
            //  advanced debugging of RTM trans-actional regions was enabled
            //  (see Section 17.3.3). This bit is set for any other debug
            //  exception (including all those that occur when advanced
            //  debugging of RTM transactional regions is not enabled). This
            //  bit is always 1 if the processor does not support RTM.
            //
            ULONG_PTR RTM : 1;          // [16]

            //
            // Reserved bits (always set). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR Reserved3 : 15;   // [17:31]

            //
            // Reserved bits (always unset).
            //
            // In 64-bit mode, the upper 32 bits of DR6 and DR7 are reserved
            //  and must be written with zeros. Writing 1 to any of the upper
            //  32 bits results in a #GP(0) exception. (17.2.6 Debug Registers
            //  and Intel 64 Processors)
            //
            ULONG_PTR Reserved4 : 32;

        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} DR6, *PDR6;
#pragma warning(pop)

C_ASSERT(sizeof(DR6) == sizeof(ULONG_PTR));

#pragma warning(push)
#pragma warning(disable : 4201) // Nonstandard extension: nameless struct/union
typedef struct _DR7 {
    union {
        ULONG_PTR All;
        struct {
            //
            // L0 through L3 (local breakpoint enable) flags.
            //
            // Enables (when set) the breakpoint condition for the associated
            //  breakpoint for the current task. When a breakpoint condition is
            //  detected and its associated Ln flag is set, a debug exception
            //  is generated. The processor automatically clears these flags on
            //  every task switch to avoid unwanted breakpoint conditions in
            //  the new task.
            //
            // G0 through G3 (global breakpoint enable) flags.
            //
            // Enables (when set) the breakpoint condition for the associated
            //  breakpoint for all tasks. When a breakpoint condition is
            //  detected and its associated Gn flag is set, a debug exception
            //  is generated. The processor does not clear these flags on a
            //  task switch, allowing a breakpoint to be enabled for all tasks.
            //
            ULONG_PTR L0 : 1;       // [0]
            ULONG_PTR G0 : 1;       // [1]
            ULONG_PTR L1 : 1;       // [2]
            ULONG_PTR G1 : 1;       // [3]
            ULONG_PTR L2 : 1;       // [4]
            ULONG_PTR G2 : 1;       // [5]
            ULONG_PTR L3 : 1;       // [6]
            ULONG_PTR G3 : 1;       // [7]

            //
            // LE and GE (local and global exact breakpoint enable) flags.
            //
            // This feature is not supported in the P6 family processors,
            //  later IA-32 processors, and Intel 64 processors. When set,
            //  these flags cause the processor to detect the exact instruction
            //  that caused a data breakpoint condition. For backward and
            //  forward compatibility with other Intel processors, we recommend
            //  that the LE and GE flags be set to 1 if exact breakpoints are
            //  required.
            //
            ULONG_PTR LE : 1;       // [8]
            ULONG_PTR GE : 1;       // [9]

            //
            // Reserved bit (always set). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR Reserved1 : 1;// [10]

            //
            // RTM (restricted transactional memory) flag.
            //
            // Enables (when set) advanced debugging of RTM transactional
            //  regions (see Section 17.3.3). This advanced debugging is
            //  enabled only if IA32_DEBUGCTL.RTM is also set.
            //
            ULONG_PTR RTM : 1;     // [11]

            //
            // Reserved bit (always unset). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR ICE : 1;     // [12]

            //
            // GD (general detect enable) flag.
            //
            // Enables (when set) debug-register protection, which causes a
            //  debug exception to be generated prior to any MOV instruction
            //  that accesses a debug register. When such a condition is
            //  detected, the BD flag in debug status register DR6 is set prior
            //  to generating the exception. This condition is provided to
            //  support in-circuit emulators.
            //
            // When the emulator needs to access the debug registers, emulator
            //  software can set the GD flag to prevent interference from the
            //  program currently executing on the processor.
            //
            // The processor clears the GD flag upon entering to the debug
            //  exception handler, to allow the handler access to the debug
            //  registers.
            //
            ULONG_PTR GD : 1;     // [13]

            //
            // Reserved bits (always unset). (Figure 17-1 Debug Registers)
            //
            ULONG_PTR TR1 : 1;     // [14]
            ULONG_PTR TR2 : 1;     // [15]

            //
            // R/W0 through R/W3 (read/write) fields.
            //
            // Specifies the breakpoint condition for the corresponding
            //  breakpoint. The DE (debug extensions) flag in control register
            //  CR4 determines how the bits in the R/Wn fields are interpreted.
            //  When the DE flag is set, the processor interprets bits as
            //  follows:
            //
            //      00: Break on instruction execution only.
            //      01: Break on data writes only.
            //      10: Break on I/O reads or writes.
            //      11: Break on data reads or writes but not instruction
            //            fetches.
            // When the DE flag is clear, the processor interprets the R/Wn
            //  bits the same as for the Intel386 and Intel486 processors,
            //  which is as follows:
            //
            //      00: Break on instruction execution only.
            //      01: Break on data writes only.
            //      10: Undefined.
            //      11: Break on data reads or writes but not instruction
            //           fetches.
            //
            // LEN0 through LEN3 (Length) fields.
            //
            // Specify the size of the memory location at the address specified
            //  in the corresponding breakpoint address register (DR0 through
            //  DR3). These fields are interpreted as follows:
            //
            //      00: 1-byte length.
            //      01: 2-byte length.
            //      10: Undefined (or 8 byte length, see note below).
            //      11: 4-byte length.
            //
            // If the corresponding RWn field in register DR7 is 00
            //  (instruction execution), then the LENn field should also be 00.
            //  The effect of using other lengths is undefined. See Section
            //  17.2.5 Breakpoint Field Recognition.
            //
            ULONG_PTR RW0  : 2;     // [16:17]
            ULONG_PTR Len0 : 2;     // [18:19]
            ULONG_PTR RW1  : 2;     // [20:21]
            ULONG_PTR Len1 : 2;     // [22:23]
            ULONG_PTR RW2  : 2;     // [24:25]
            ULONG_PTR Len2 : 2;     // [26:27]
            ULONG_PTR RW3  : 2;     // [28:29]
            ULONG_PTR Len3 : 2;     // [30:31]

            //
            // Reserved bits (always unset).
            //
            // In 64-bit mode, the upper 32 bits of DR6 and DR7 are reserved
            //  and must be written with zeros. Writing 1 to any of the upper
            //  32 bits results in a #GP(0) exception. (17.2.6 Debug Registers
            //  and Intel 64 Processors)
            //
            ULONG_PTR Reserved4 : 32;

        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} DR7, *PDR7;
#pragma warning(pop)

C_ASSERT(sizeof(DR7) == sizeof(ULONG_PTR));
