/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoInitialization();

VOID
VivienneIoTermination();

//=============================================================================
// Public Interface
//=============================================================================
_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoGetProcessInformation(
    _In_ ULONG_PTR ProcessId,
    _Out_ PVIVIENNE_PROCESS_INFORMATION pProcessInfo
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoQuerySystemDebugState(
    _Out_writes_bytes_(cbSystemDebugState) PSYSTEM_DEBUG_STATE pSystemDebugState,
    _In_ ULONG cbSystemDebugState
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoSetHardwareBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoClearHardwareBreakpoint(
    _In_ ULONG DebugRegisterIndex
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoCaptureRegisterValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ X64_REGISTER Register,
    _In_ ULONG DurationInMilliseconds,
    _Out_writes_bytes_(cbValuesCtx) PCEC_REGISTER_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoCaptureMemoryValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ PCEC_MEMORY_DESCRIPTION pMemoryDescription,
    _In_ ULONG DurationInMilliseconds,
    _Out_writes_bytes_(cbValuesCtx) PCEC_MEMORY_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoQueryEptBreakpointInformationSize(
    _Out_ PULONG pcbRequired
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoQueryEptBreakpointInformation(
    _Out_writes_bytes_(cbEptBreakpointInfo)
        PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo,
    _In_ ULONG cbEptBreakpointInfo
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoSetEptBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG_PTR Address,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _In_opt_ X64_REGISTER RegisterKey,
    _Out_ PHANDLE phLog,
    _Out_ PEPT_BREAKPOINT_LOG* ppLog
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoDisableEptBreakpoint(
    _In_ HANDLE Handle
);

_Success_(return != FALSE)
_Check_return_
BOOL
VivienneIoClearEptBreakpoint(
    _In_ HANDLE Handle
);
