#pragma once

#include <Windows.h>

#define MAKE_THREAD_AFFINITY_MASK(ProcessorIndex, NumberOfProcessors) \
    (1 << ((ProcessorIndex) % (NumberOfProcessors)))

_Check_return_
DWORD
AfnGetLogicalProcessorCount();

_Check_return_
BOOL
AfnSetProcessAffinityAllProcessors(
    _In_ HANDLE hProcess,
    _In_ DWORD cProcessors
);
