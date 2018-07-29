#pragma once

#include <Windows.h>

#include <cstdio>

#include "..\common\arch_x64.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
BOOL
InitializeRngSeed();

//=============================================================================
// Debugger Configuration
//=============================================================================
VOID
PromptDebuggerExceptionConfiguration(
    _In_z_ PCSTR pszPromptMessage,
    _In_z_ PCSTR pszCommandMessage
);

//=============================================================================
// Exception Handlers
//=============================================================================
_Check_return_
LONG
CALLBACK
StealthCheckVectoredHandler(
    _In_ PEXCEPTION_POINTERS pExceptionInfo
);

_Check_return_
LONG
WINAPI
StealthCheckFilter(
    _In_ unsigned long ExceptionCode,
    _In_ PEXCEPTION_POINTERS pExceptionInfo
);

//=============================================================================
// Breakpoints
//=============================================================================
_Check_return_
BOOL
BreakpointStealthCheck();

_Check_return_
BOOL
VerifyThreadLocalBreakpointByIndex(
    _In_ ULONG Index,
    _In_ HANDLE hThread,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Check_return_
BOOL
AreAllHardwareBreakpointsCleared();

_Check_return_
BOOL
SetThreadLocalHardwareBreakpoint(
    _In_ ULONG Index,
    _In_ HANDLE hThread,
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
);

_Check_return_
BOOL
ClearThreadLocalHardwareBreakpoint(
    _In_ ULONG Index,
    _In_ HANDLE hThread
);

//=============================================================================
// Random
//=============================================================================
_Check_return_
ULONG
GenerateRandomValue();

#define RANDOM_ULONG    (GenerateRandomValue())

_Check_return_
ULONG_PTR
GenerateBoundedRandomValue(
    _In_ ULONG_PTR MinValue,
    _In_ ULONG_PTR MaxValue
);

VOID
GenerateUniqueRandomValues(
    _In_count_c_(cValues) ULONG pValues[],
    _In_ ULONG cValues
);

//=============================================================================
// Logging
//=============================================================================
#define TEST_DELIM_MAJOR "=================================================\n"

#define PRINT_TEST_HEADER           \
    printf(TEST_DELIM_MAJOR);       \
    printf("%s\n", __FUNCTION__);   \
    printf(TEST_DELIM_MAJOR);

#define PRINT_TEST_FOOTER \
    printf("Test succeeded.\n\n");

VOID
PrintDebugRegisterContext(
    _In_ PCONTEXT pContext
);

//=============================================================================
// Process Termination
//=============================================================================
_Analysis_noreturn_
VOID
DisplayFailureWindowThenExit(
    _In_ const char* pszFileName,
    _In_ const char* pszFunctionName,
    _In_ int LineNumber,
    _In_z_ _Printf_format_string_ const char* pszFormat,
    ...
);

#define FAIL_TEST(Format, ...)      \
    DisplayFailureWindowThenExit(   \
        __FILE__,                   \
        __FUNCTION__,               \
        __LINE__,                   \
        Format,                     \
        __VA_ARGS__)