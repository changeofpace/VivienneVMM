/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    debug_register_facade.h

Abstract:

    This header defines the debug register facade interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>

#include "HyperPlatform\HyperPlatform\ia32_type.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
NTSTATUS
FcdDriverEntry();

VOID
FcdDriverUnload();

_IRQL_requires_(HIGH_LEVEL)
VOID
FcdVmxDriverEntry();

_IRQL_requires_(HIGH_LEVEL)
VOID
FcdVmxDriverUnload();

//=============================================================================
// Vmx Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
VOID
FcdVmxLogMovDrEvent(
    _In_ MovDrQualification ExitQualification,
    _In_ PULONG_PTR pRegisterUsed
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
FcdVmxProcessMovDrEvent(
    _In_ MovDrQualification ExitQualification,
    _Inout_ PULONG_PTR pRegisterUsed
);
