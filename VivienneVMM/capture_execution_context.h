/*++

Module Name:
    
    capture_execution_context.h

Abstract:

    This header defines the capture execution context interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
NTSTATUS
CecInitialization();

//=============================================================================
// Client Interface
//=============================================================================
_Check_return_
NTSTATUS
CecCaptureUniqueRegisterValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ ULONG RegisterKey,
    _In_ ULONG DurationInMilliseconds,
    _Inout_bytecount_(cbCapturedCtx) PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    _In_ ULONG cbCapturedCtx
);