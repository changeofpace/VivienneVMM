/*++

Module Name:
    
    breakpoint_manager.h

Abstract:

    This header defines the hardware breakpoint manager interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "breakpoint_callbacks.h"

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

#include "HyperPlatform\ia32_type.h"

//=============================================================================
// Types
//=============================================================================
typedef struct _HARDWARE_BREAKPOINT
{
    ULONG_PTR ProcessId;
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
BpmInitialization();

_Check_return_
NTSTATUS
BpmTermination();

//=============================================================================
// Client Interface
//=============================================================================
_Check_return_
NTSTATUS
BpmQuerySystemDebugState(
    _Out_ PSYSTEM_DEBUG_STATE pSystemDebugState,
    _In_ ULONG cbSystemDebugState
);

_Check_return_
NTSTATUS
BpmInitializeBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _Out_ PHARDWARE_BREAKPOINT pBreakpoint
);

_Check_return_
NTSTATUS
BpmSetHardwareBreakpoint(
    _In_ PHARDWARE_BREAKPOINT pBreakpoint,
    _In_ FPBREAKPOINT_CALLBACK pCallbackFn,
    _In_opt_ PVOID pCallbackCtx
);

_Check_return_
NTSTATUS
BpmSetHardwareBreakpoint(
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
BpmClearHardwareBreakpoint(
    _In_ ULONG Index
);

_Check_return_
NTSTATUS
BpmCleanupBreakpoints();

//=============================================================================
// Vmx Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
BpmVmxSetHardwareBreakpoint(
    _In_ PVOID pVmxContext
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
BpmVmxProcessDebugExceptionEvent(
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _In_ ULONG_PTR GuestIp
);
