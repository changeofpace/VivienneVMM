/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    hardware_breakpoint_manager.h

Abstract:

    This header defines the hardware breakpoint manager interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>

#include "breakpoint_callback.h"

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

#include "HyperPlatform\HyperPlatform\ia32_type.h"

//=============================================================================
// Types
//=============================================================================
typedef struct _HARDWARE_BREAKPOINT {
    HANDLE ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
} HARDWARE_BREAKPOINT, *PHARDWARE_BREAKPOINT;

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
NTSTATUS
HbmDriverEntry();

VOID
HbmDriverUnload();

//=============================================================================
// Public Vmx Non-Root Interface
//=============================================================================
_Check_return_
NTSTATUS
HbmQuerySystemDebugState(
    _Out_ PSYSTEM_DEBUG_STATE pSystemDebugState,
    _In_ ULONG cbSystemDebugState
);

_Check_return_
NTSTATUS
HbmInitializeBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _Out_ PHARDWARE_BREAKPOINT pBreakpoint
);

_Check_return_
NTSTATUS
HbmSetHardwareBreakpoint(
    _In_ PHARDWARE_BREAKPOINT pBreakpoint,
    _In_ FPBREAKPOINT_CALLBACK pCallbackFn,
    _In_opt_ PVOID pCallbackCtx
);

_Check_return_
NTSTATUS
HbmSetHardwareBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ FPBREAKPOINT_CALLBACK pCallbackFn,
    _In_opt_ PVOID pCallbackCtx
);

_Check_return_
NTSTATUS
HbmClearHardwareBreakpoint(
    _In_ ULONG Index
);

_Check_return_
NTSTATUS
HbmCleanupBreakpoints();

//=============================================================================
// Public Vmx Root Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
VOID
HbmxSetHardwareBreakpoint(
    _In_ PVOID pVmxContext
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
HbmxProcessDebugExceptionEvent(
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _In_ PULONG_PTR pGuestIp
);
