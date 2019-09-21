#pragma once

#include <Windows.h>

#include <string>
#include <vector>

//=============================================================================
// Client Interface
//=============================================================================
_Check_return_
BOOL
PsLookupProcessIdByName(
    _In_z_ PCSTR pszProcessName,
    _Out_ std::vector<ULONG_PTR>& ProcessIds
);
