#pragma once

#include <fltKernel.h>

#include "..\common\arch_x64.h"

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
