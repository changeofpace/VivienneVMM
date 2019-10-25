/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    ioctl_validation.h

Abstract:

    This header defines IO validation routines.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

_Check_return_
NTSTATUS
IvValidateGeneralPurposeRegister(
    _In_ X64_REGISTER Register
);

_Check_return_
NTSTATUS
IvValidateDebugRegisterIndex(
    _In_ ULONG DebugRegisterIndex
);

_Check_return_
NTSTATUS
IvValidateMemoryDescription(
    _In_ PCEC_MEMORY_DESCRIPTION pMemoryDescription
);
