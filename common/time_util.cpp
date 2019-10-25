/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    time_util.cpp

Abstract:

    This module implements time utilities.

Author:

    changeofpace

Environment:

    Kernel and user mode.

--*/

#include "time_util.h"

#ifdef _KERNEL_MODE
#include "..\VivienneVMM\log.h"
#else
#include "..\VivienneCL\log.h"
#endif


//=============================================================================
// Module Globals
//=============================================================================
static LARGE_INTEGER g_ProcessorFrequency = {};


//=============================================================================
// Meta Interface
//=============================================================================
#ifdef _KERNEL_MODE

_Use_decl_annotations_
NTSTATUS
TiDriverEntry()
{
    LARGE_INTEGER Frequency = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT("Initializing time util.");

    (VOID)KeQueryPerformanceCounter(&Frequency);
    if (!Frequency.QuadPart)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    g_ProcessorFrequency.QuadPart = Frequency.QuadPart;

    INF_PRINT(
        "Processor frequency: %lld (0x%llX)",
        g_ProcessorFrequency.QuadPart,
        g_ProcessorFrequency.QuadPart);

exit:
    return ntstatus;
}

#else

_Use_decl_annotations_
BOOL
TiInitialization()
{
    LARGE_INTEGER Frequency = {};
    BOOL status = TRUE;

    INF_PRINT("Initializing time util.");

    if (!QueryPerformanceFrequency(&Frequency))
    {
        status = FALSE;
        goto exit;
    }

    g_ProcessorFrequency.QuadPart = Frequency.QuadPart;

    INF_PRINT(
        "Processor frequency: %lld (0x%llX)",
        g_ProcessorFrequency.QuadPart,
        g_ProcessorFrequency.QuadPart);

exit:
    return status;
}

#endif


//=============================================================================
// Public Interface
//=============================================================================
_Use_decl_annotations_
LONGLONG
TiGetProcessorFrequency()
{
    return g_ProcessorFrequency.QuadPart;
}


_Use_decl_annotations_
LONGLONG
TiMillisecondsToTicks(
    ULONG Milliseconds
)
{
    return (Milliseconds * g_ProcessorFrequency.QuadPart)
        / SECOND_IN_MILLISECONDS;
}


_Use_decl_annotations_
LONGLONG
TiMicrosecondsToTicks(
    ULONG Microseconds
)
{
    return (Microseconds * g_ProcessorFrequency.QuadPart)
        / SECOND_IN_MICROSECONDS;
}


_Use_decl_annotations_
LONGLONG
TiTicksToMilliseconds(
    PLARGE_INTEGER Ticks
)
{
    return (Ticks->QuadPart * SECOND_IN_MILLISECONDS)
        / g_ProcessorFrequency.QuadPart;
}


_Use_decl_annotations_
LONGLONG
TiTicksToMicroseconds(
    PLARGE_INTEGER pTicks
)
{
    return (pTicks->QuadPart * SECOND_IN_MICROSECONDS)
        / g_ProcessorFrequency.QuadPart;
}
