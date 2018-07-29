/*++

Module Name:

    register_util.cpp

Abstract:

    This module implements register utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "register_util.h"

#include "..\common\arch_x64.h"


//=============================================================================
// Client Interface
//=============================================================================

//
// ReadGuestRegisterValue
//
// Utility to read a register value from guest state.
//
_Use_decl_annotations_
NTSTATUS
ReadGuestRegisterValue(
    ULONG Register,
    GpRegisters* pGuestRegisters,
    ULONG_PTR GuestIp,
    PULONG_PTR pRegisterValue
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    // Zero out parameters.
    *pRegisterValue = 0;

    switch (Register)
    {
        case REGISTER_RIP: *pRegisterValue = GuestIp; break;
        case REGISTER_RAX: *pRegisterValue = pGuestRegisters->ax; break;
        case REGISTER_RCX: *pRegisterValue = pGuestRegisters->cx; break;
        case REGISTER_RDX: *pRegisterValue = pGuestRegisters->dx; break;
        case REGISTER_RDI: *pRegisterValue = pGuestRegisters->di; break;
        case REGISTER_RSI: *pRegisterValue = pGuestRegisters->si; break;
        case REGISTER_RBX: *pRegisterValue = pGuestRegisters->bx; break;
        case REGISTER_RBP: *pRegisterValue = pGuestRegisters->bp; break;
        case REGISTER_RSP: *pRegisterValue = pGuestRegisters->sp; break;
        case REGISTER_R8:  *pRegisterValue = pGuestRegisters->r8; break;
        case REGISTER_R9:  *pRegisterValue = pGuestRegisters->r9; break;
        case REGISTER_R10: *pRegisterValue = pGuestRegisters->r10; break;
        case REGISTER_R11: *pRegisterValue = pGuestRegisters->r11; break;
        case REGISTER_R12: *pRegisterValue = pGuestRegisters->r12; break;
        case REGISTER_R13: *pRegisterValue = pGuestRegisters->r13; break;
        case REGISTER_R14: *pRegisterValue = pGuestRegisters->r14; break;
        case REGISTER_R15: *pRegisterValue = pGuestRegisters->r15; break;
        case REGISTER_INVALID:
        {
            __fallthrough;
        }
        default:
        {
            ntstatus = STATUS_INVALID_PARAMETER_1;
            break;
        }
    }

    return ntstatus;
}