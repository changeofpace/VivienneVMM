/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include <string>
#include <vector>

#include "../common/driver_io_types.h"

_Success_(return != FALSE)
_Check_return_
BOOL
PsLookupProcessIdByName(
    _In_z_ PCSTR pszProcessName,
    _Out_ std::vector<ULONG_PTR>& ProcessIds
);

_Success_(return != FALSE)
_Check_return_
BOOL
PsGetProcessInformation(
    _In_ ULONG_PTR ProcessId,
    _Out_ PVIVIENNE_PROCESS_INFORMATION pProcessInfo
);
