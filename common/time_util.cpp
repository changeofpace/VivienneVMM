/*++

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
#include <cstdio>
#endif


//=============================================================================
// Module Globals
//=============================================================================
static LARGE_INTEGER g_ProcessorFrequency = {};


//=============================================================================
// Meta Interface
//=============================================================================

//
// TiInitialization
//
#ifdef _KERNEL_MODE

_Use_decl_annotations_
NTSTATUS
TiInitialization()
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

    printf("Initializing time util.\n");

    if (!QueryPerformanceFrequency(&Frequency))
    {
        status = FALSE;
        goto exit;
    }

    g_ProcessorFrequency.QuadPart = Frequency.QuadPart;

    printf(
        "Processor frequency: %lld (0x%llX)\n",
        g_ProcessorFrequency.QuadPart,
        g_ProcessorFrequency.QuadPart);

exit:
    return status;
}

#endif


//=============================================================================
// Client Interface
//=============================================================================

//
// TiGetProcessorFrequency
//
_Use_decl_annotations_
LONGLONG
TiGetProcessorFrequency()
{
    return g_ProcessorFrequency.QuadPart;
}


//
// TiMillisecondsToTicks
//
_Use_decl_annotations_
LONGLONG
TiMillisecondsToTicks(
    ULONG Milliseconds
)
{
    return (Milliseconds * g_ProcessorFrequency.QuadPart)
        / SECOND_IN_MILLISECONDS;
}


//
// TiMicrosecondsToTicks
//
_Use_decl_annotations_
LONGLONG
TiMicrosecondsToTicks(
    ULONG Microseconds
)
{
    return (Microseconds * g_ProcessorFrequency.QuadPart)
        / SECOND_IN_MICROSECONDS;
}


//
// TiTicksToMilliseconds
//
_Use_decl_annotations_
LONGLONG
TiTicksToMilliseconds(
    PLARGE_INTEGER Ticks
)
{
    return (Ticks->QuadPart * SECOND_IN_MILLISECONDS)
        / g_ProcessorFrequency.QuadPart;
}


//
// TiTicksToMicroseconds
//
_Use_decl_annotations_
LONGLONG
TiTicksToMicroseconds(
    PLARGE_INTEGER pTicks
)
{
    return (pTicks->QuadPart * SECOND_IN_MICROSECONDS)
        / g_ProcessorFrequency.QuadPart;
}
