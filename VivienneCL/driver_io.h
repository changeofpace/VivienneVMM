#pragma once

#include <Windows.h>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

//
// NOTE All functions are synchronous.
//

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
BOOL
DrvInitialization();

_Check_return_
BOOL
DrvTermination();

//=============================================================================
// Driver Interface
//=============================================================================
_Check_return_
BOOL
DrvQuerySystemDebugState(
    _Out_writes_bytes_(cbSystemDebugState) PSYSTEM_DEBUG_STATE pSystemDebugState,
    _In_ ULONG cbSystemDebugState
);

_Check_return_
BOOL
DrvSetHardwareBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Check_return_
BOOL
DrvClearHardwareBreakpoint(
    _In_ ULONG DebugRegisterIndex
);

_Check_return_
BOOL
DrvCaptureRegisterValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ X64_REGISTER Register,
    _In_ ULONG DurationInMilliseconds,
    _Out_writes_bytes_(cbCapturedCtx) PCEC_REGISTER_VALUES pCapturedCtx,
    _In_ ULONG cbCapturedCtx
);