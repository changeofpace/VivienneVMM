#pragma once

#include <Windows.h>

#include "../common/arch_x64.h"

_Success_(return != FALSE)
_Check_return_
BOOL
ThuSetThreadHardwareBreakpoint(
    _In_ DWORD ThreadId,
    _In_ ULONG DebugRegisterIndex,
    _In_ PVOID pAddress,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Success_(return != FALSE)
_Check_return_
BOOL
ThuClearThreadHardwareBreakpoint(
    _In_ DWORD ThreadId,
    _In_ ULONG DebugRegisterIndex
);
