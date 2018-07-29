/*++

Module Name:

    breakpoint_callbacks.cpp

Abstract:

    This module implements the default breakpoint callback.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "breakpoint_callbacks.h"

#include "log_util.h"


//=============================================================================
// Vmx Interface
//=============================================================================

//
// BpcVmxLogGeneralPurposeRegisters
//
// Log the state of the general purpose registers.
//
// NOTE This function acts as the default breakpoint callback.
//
_Use_decl_annotations_
NTSTATUS
BpcVmxLogGeneralPurposeRegisters(
    ULONG OwnerIndex,
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    ULONG_PTR GuestIp,
    PVOID pCallbackCtx
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pGuestFlags);
    UNREFERENCED_PARAMETER(pCallbackCtx);

    // Print the debug address register which caused this debug exception.
    info_print("#DB: Dr%u", OwnerIndex);

    // Raw print the guest register context to keep the message buffer size
    //  below 512 bytes.
#pragma warning(suppress : 6066) // Passing uint64 with '%p' format specifier.
    raw_info_print(
        "rip: %p\r\n"
        "rax: %p rbx: %p rbp: %p rsp: %p\r\n"
        "rcx: %p rdx: %p r8:  %p r9:  %p\r\n"
        "rdi: %p rsi: %p r10: %p r11: %p\r\n"
        "r12: %p r13: %p r14: %p r15: %p\r\n",
        GuestIp,
        pGuestRegisters->ax, pGuestRegisters->bx, pGuestRegisters->bp,
        pGuestRegisters->sp, pGuestRegisters->cx, pGuestRegisters->dx,
        pGuestRegisters->r8, pGuestRegisters->r9, pGuestRegisters->di,
        pGuestRegisters->si, pGuestRegisters->r10, pGuestRegisters->r11,
        pGuestRegisters->r12, pGuestRegisters->r13, pGuestRegisters->r14,
        pGuestRegisters->r15);

    return ntstatus;
}