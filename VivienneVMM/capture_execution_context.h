/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

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
CecDriverEntry();

VOID
CecDriverUnload();

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_
NTSTATUS
CecCaptureRegisterValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ X64_REGISTER Register,
    _In_ ULONG DurationInMilliseconds,
    _Inout_bytecount_(cbValuesCtx) PCEC_REGISTER_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx
);

_Check_return_
NTSTATUS
CecCaptureMemoryValues(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size,
    _In_ PCEC_MEMORY_DESCRIPTION pMemoryDescription,
    _In_ ULONG DurationInMilliseconds,
    _Inout_bytecount_(cbValuesCtx) PCEC_MEMORY_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx
);
