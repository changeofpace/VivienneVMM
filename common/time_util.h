/*++

Module Name:
    
    time_util.h

Abstract:

    This header defines time utilities.

Author:

    changeofpace

Environment:

    Kernel and user mode.

--*/

#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <Windows.h>
#endif

static_assert(sizeof(LONGLONG) == sizeof(LARGE_INTEGER), "Size check");

//=============================================================================
// Constants and Macros
//=============================================================================
#define SECOND_IN_MILLISECONDS 1000
#define SECOND_IN_MICROSECONDS 1000000
#define SECOND_IN_NANOSECONDS  1000000000

#define SECONDS_TO_MILLISECONDS(Seconds) (Seconds * SECOND_IN_MILLISECONDS)
#define SECONDS_TO_MICROSECONDS(Seconds) (Seconds * SECOND_IN_MICROSECONDS)
#define SECONDS_TO_NANOSECONDS(Seconds)  (Seconds * SECOND_IN_NANOSECONDS)

// Relative interval for NtDelayExecution.
#define MILLISECONDS_TO_RELATIVE_NTINTERVAL(Milliseconds) \
    ((LONGLONG)Milliseconds * (-10000))

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
#ifdef _KERNEL_MODE
NTSTATUS
#else
BOOL
#endif
TiInitialization();

//=============================================================================
// Client Interface
//=============================================================================
_Check_return_
LONGLONG
TiGetProcessorFrequency();

_Check_return_
LONGLONG
TiMillisecondsToTicks(
    _In_ ULONG Milliseconds
);

_Check_return_
LONGLONG
TiMicrosecondsToTicks(
    _In_ ULONG Microseconds
);

_Check_return_
LONGLONG
TiTicksToMilliseconds(
    _In_ PLARGE_INTEGER pTicks
);

_Check_return_
LONGLONG
TiTicksToMicroseconds(
    _In_ PLARGE_INTEGER pTicks
);
