/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include "../common/driver_io_types.h"

_Success_(return != FALSE)
_Check_return_
BOOL
EbpQueryEptBreakpointInformation(
    _Outptr_result_nullonfailure_
        PEPT_BREAKPOINT_INFORMATION* ppEptBreakpointInfo,
    _Out_opt_ PULONG pcbEptBreakpointInfo
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpSetEptBreakpointBasic(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG_PTR Address,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _Out_ PHANDLE phLog,
    _Out_ PEPT_BREAKPOINT_LOG* ppLog
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpSetEptBreakpointGeneralRegisterContext(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG_PTR Address,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _Out_ PHANDLE phLog,
    _Out_ PEPT_BREAKPOINT_LOG* ppLog
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpSetEptBreakpointKeyedRegisterContext(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG_PTR Address,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _In_ X64_REGISTER RegisterKey,
    _Out_ PHANDLE phLog,
    _Out_ PEPT_BREAKPOINT_LOG* ppLog
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpDisableEptBreakpoint(
    _In_ HANDLE hLog
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpClearEptBreakpoint(
    _In_ HANDLE hLog
);

VOID
EbpPrintEptBreakpointInformation(
    _In_ PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo
);

VOID
EbpPrintEptBreakpointLogHeader(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG_HEADER pHeader
);

_Success_(return != FALSE)
_Check_return_
BOOL
EbpPrintEptBreakpointElements(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG pLog,
    _In_ ULONG StartIndex,
    _In_opt_ ULONG nPrint
);
