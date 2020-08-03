/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    system_util.h

Abstract:

    This header defines system utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>

typedef
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
_Check_return_
NTSTATUS
SYSTEM_PROCESSOR_CALLBACK_ROUTINE (
    _In_ PVOID pContext
    );

typedef SYSTEM_PROCESSOR_CALLBACK_ROUTINE *PSYSTEM_PROCESSOR_CALLBACK_ROUTINE;

_IRQL_requires_max_(APC_LEVEL)
_Check_return_
NTSTATUS
SysExecuteProcessorCallback(
    _In_ PSYSTEM_PROCESSOR_CALLBACK_ROUTINE pCallbackRoutine,
    _In_opt_ PVOID pCallbackContext,
    _In_opt_ PSYSTEM_PROCESSOR_CALLBACK_ROUTINE pUnwindRoutine,
    _In_opt_ PVOID pUnwindContext
);
