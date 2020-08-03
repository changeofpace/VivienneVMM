/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    ept_breakpoint_manager.h

Abstract:

    This header defines the ept breakpoint manager interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

#include "HyperPlatform\HyperPlatform\ia32_type.h"
#include "HyperPlatform\HyperPlatform\ept.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
NTSTATUS
EbmDriverEntry();

VOID
EbmDriverUnload();

//=============================================================================
// Public Vmx Non-Root Interface
//=============================================================================
_Check_return_
NTSTATUS
EbmRegisterClient(
    _In_ HANDLE ProcessId
);

_Check_return_
NTSTATUS
EbmUnregisterClient(
    _In_ HANDLE ProcessId
);

_Check_return_
BOOLEAN
EbmIsClientRegistered();

_Check_return_
NTSTATUS
EbmQueryEptBreakpointInformationSize(
    _Out_ PULONG pcbRequired
);

_Check_return_
NTSTATUS
EbmQueryEptBreakpointInformation(
    _Out_writes_bytes_(cbEptBreakpointInfo)
        PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo,
    _In_ ULONG cbEptBreakpointInfo,
    _Out_ PULONG pcbReturned
);

_Check_return_
NTSTATUS
EbmSetEptBreakpoint(
    _In_ HANDLE ProcessId,
    _In_ PVOID pVirtualAddress,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _In_opt_ X64_REGISTER RegisterKey,
    _Outptr_result_nullonfailure_ PHANDLE phLog,
    _Outptr_result_nullonfailure_ PEPT_BREAKPOINT_LOG* ppLog
);

_Check_return_
NTSTATUS
EbmDisableEptBreakpoint(
    _In_ HANDLE Handle
);

_Check_return_
NTSTATUS
EbmClearEptBreakpoint(
    _In_ HANDLE Handle
);

//=============================================================================
// Public Vmx Root Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
VOID
EbmxInstallEptBreakpoint(
    _In_ EptData* pEptData,
    _In_ PVOID pContext
);

_IRQL_requires_(HIGH_LEVEL)
VOID
EbmxUninstallEptBreakpoint(
    _In_ EptData* pEptData,
    _In_ PVOID pContext
);

_IRQL_requires_(HIGH_LEVEL)
VOID
EbmxUninstallEptBreakpointsByProcessId(
    _In_ EptData* pEptData,
    _In_ PVOID pContext
);

_IRQL_requires_(HIGH_LEVEL)
VOID
EbmxUninstallAllEptBreakpoints(
    _In_ EptData* pEptData,
    _In_ PVOID pContext
);

_IRQL_requires_(HIGH_LEVEL)
_Success_(return != FALSE)
_Check_return_
BOOLEAN
EbmxHandleEptViolation(
    _In_ struct GuestContext* pGuestContext
);

_IRQL_requires_(HIGH_LEVEL)
VOID
EbmxHandleMonitorTrapFlag(
    _In_ struct GuestContext* pGuestContext
);
