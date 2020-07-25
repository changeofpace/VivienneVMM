#pragma once

#include <ntddk.h>

#define IS_ALIGNED(_pointer, _alignment) \
    ((((ULONG_PTR) (_pointer)) & ((_alignment) - 1)) == 0)

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
EXTERN_C
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
);
