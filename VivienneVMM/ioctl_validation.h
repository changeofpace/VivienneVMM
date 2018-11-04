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
