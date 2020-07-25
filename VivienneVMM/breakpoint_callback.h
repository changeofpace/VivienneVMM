/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    breakpoint_callback.h

Abstract:

    This header defines the callback prototype for BPM-managed breakpoints and
     the default callback.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>

#include "HyperPlatform\HyperPlatform\ia32_type.h"

//=============================================================================
// Types
//=============================================================================

//
// A callback invoked when a BPM-managed breakpoint is triggered. The callback
//  will execute in VMX root mode inside the process which caused the
//  exception.
//
// Callbacks can modify guest state using the guest registers, rflags, and
//  instruction pointer parameters. All guest state changes are applied to the
//  guest on VM entry.
//
// NOTE The breakpoint manager does not configure host CR3 before invoking
//  callbacks.
//
typedef NTSTATUS(FASTCALL* FPBREAKPOINT_CALLBACK)(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _Inout_ PULONG_PTR pGuestIp,
    _Inout_ PVOID pCallbackCtx
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
    _Inout_ PULONG_PTR pGuestIp,
    _Inout_ PVOID pCallbackCtx
);
