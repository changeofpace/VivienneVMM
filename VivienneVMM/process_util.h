/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    process_util.h

Abstract:

    This header defines the process utility interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "../common/driver_io_types.h"

_Check_return_
NTSTATUS
PsuGetProcessInformation(
    _In_ HANDLE ProcessId,
    _Out_ PVIVIENNE_PROCESS_INFORMATION pProcessInfo
);
