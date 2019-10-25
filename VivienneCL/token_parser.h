/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include <string>
#include <vector>

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

_Check_return_
BOOL
IsBreakpointAddressAligned(
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Check_return_
BOOL
ParseDebugRegisterIndexToken(
    _In_ const std::string& Token,
    _Out_ PULONG pDebugRegisterIndex
);

_Check_return_
BOOL
ParseDebugRegisterIndexToken(
    _In_ const std::string& Token,
    _Out_ PULONG pDebugRegisterIndex
);

_Check_return_
BOOL
ParseProcessIdToken(
    _In_ const std::string& Token,
    _Out_ PULONG_PTR pProcessId
);

_Check_return_
BOOL
ParseAddressToken(
    _In_ const std::string& Token,
    _Out_ PULONG_PTR pAddress
);

_Check_return_
BOOL
ParseAccessSizeToken(
    _In_ const std::string& Token,
    _Out_ PHWBP_TYPE pType,
    _Out_ PHWBP_SIZE pSize
);

_Check_return_
BOOL
ParseRegisterToken(
    _In_ const std::string& Token,
    _Out_ PX64_REGISTER pRegister
);

_Check_return_
BOOL
ParseMemoryDataTypeToken(
    _In_ const std::string& Token,
    _Out_ PMEMORY_DATA_TYPE pMemoryDataType
);

_Check_return_
BOOL
ParseScaleFactorToken(
    _In_ const std::string& Token,
    _Out_ PSCALE_FACTOR pScaleFactor
);

_Check_return_
BOOL
ParseIndirectAddressToken(
    _In_ const std::string& Token,
    _Out_ PINDIRECT_ADDRESS pIndirectAddress
);

_Check_return_
BOOL
ParseMemoryDescriptionToken(
    _In_ const std::string& Token,
    _In_ MEMORY_DATA_TYPE MemoryDataType,
    _Out_ PCEC_MEMORY_DESCRIPTION pMemoryDescription
);

_Check_return_
BOOL
ParseDurationToken(
    _In_ const std::string& Token,
    _Out_ PULONG pDurationInMilliseconds
);
