/*++

Module Name:

    breakpoint_callback.cpp

Abstract:

    This module implements the default breakpoint callback.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "breakpoint_callback.h"

#include "log.h"


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
    PULONG_PTR pGuestIp,
    PVOID pCallbackCtx
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pGuestFlags);
    UNREFERENCED_PARAMETER(pCallbackCtx);

    //
    // Print the debug address register which caused this debug exception.
    //
    INF_PRINT("#DB: Dr%u", OwnerIndex);

    //
    // Raw print the guest register context to keep the message buffer size
    //  below 512 bytes.
    //
    INF_PRINT_RAW(
        "  rip: %p\r\n"
        "  rax: %p rbx: %p rbp: %p rsp: %p\r\n"
        "  rcx: %p rdx: %p r8:  %p r9:  %p\r\n"
        "  rdi: %p rsi: %p r10: %p r11: %p\r\n"
        "  r12: %p r13: %p r14: %p r15: %p\r\n",
        *pGuestIp,
        pGuestRegisters->ax, pGuestRegisters->bx, pGuestRegisters->bp,
        pGuestRegisters->sp, pGuestRegisters->cx, pGuestRegisters->dx,
        pGuestRegisters->r8, pGuestRegisters->r9, pGuestRegisters->di,
        pGuestRegisters->si, pGuestRegisters->r10, pGuestRegisters->r11,
        pGuestRegisters->r12, pGuestRegisters->r13, pGuestRegisters->r14,
        pGuestRegisters->r15);

    return ntstatus;
}
