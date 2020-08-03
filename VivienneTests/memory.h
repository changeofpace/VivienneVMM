#pragma once

#include <Windows.h>

_Check_return_
BOOL
IsVirtualAddressValid(
    _In_ PVOID pAddress,
    _Out_ PBOOL pValid
);
