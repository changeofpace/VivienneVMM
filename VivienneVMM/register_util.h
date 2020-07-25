/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    register_util.h

Abstract:

    This header defines register utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>

#include "..\common\arch_x64.h"

#include "HyperPlatform\HyperPlatform\ia32_type.h"

_Check_return_
NTSTATUS
ReadGuestGpRegisterValue(
    _In_ X64_REGISTER Register,
    _In_ GpRegisters* pGuestRegisters,
    _In_ ULONG_PTR GuestIp,
    _Out_ PULONG_PTR pValue
);
