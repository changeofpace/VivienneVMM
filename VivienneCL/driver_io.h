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
DrvCaptureUniqueRegisterValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG DebugRegisterIndex,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ ULONG RegisterKey,
    _In_ ULONG DurationInMilliseconds,
    _Out_writes_bytes_(cbCapturedCtx) PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    _In_ ULONG cbCapturedCtx
);