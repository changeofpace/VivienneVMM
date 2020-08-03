#pragma once

#include <Windows.h>

_Check_return_
DWORD
AfnGetLogicalProcessorCount();

_Check_return_
BOOL
AfnSetProcessAffinityAllProcessors(
    _In_ HANDLE hProcess,
    _In_ DWORD cProcessors
);
