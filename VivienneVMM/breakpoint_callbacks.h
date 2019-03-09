/*++

Module Name:
    
    breakpoint_callbacks.h

Abstract:

    This header defines the callback prototype for BPM-managed breakpoints and
     the default callback.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "HyperPlatform\ia32_type.h"

//=============================================================================
// Types
//=============================================================================

//
// A callback invoked when a BPM-managed breakpoint is triggered. The callback
//  will execute in VMX root mode inside the process which caused the
//  exception.
//
typedef NTSTATUS (FASTCALL* FPBREAKPOINT_CALLBACK)(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _In_ ULONG_PTR GuestIp,
    _In_ PVOID pCallbackCtx
    );

//=============================================================================
// Vmx Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
BpcVmxLogGeneralPurposeRegisters(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _In_ ULONG_PTR GuestIp,
    _In_ PVOID pCallbackCtx
);
