/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include <string>
#include <vector>

_Check_return_
BOOL
PsLookupProcessIdByName(
    _In_z_ PCSTR pszProcessName,
    _Out_ std::vector<ULONG_PTR>& ProcessIds
);
