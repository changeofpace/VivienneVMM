#pragma once

#include <Windows.h>

//=============================================================================
// Globals
//=============================================================================

// NOTE These values must be kept synchronized with their associated tests.
EXTERN_C ULONG_PTR g_AcCaptureTargetR12CaptureAddress;
EXTERN_C ULONG_PTR g_AcUnownedHwBpAccessAddress1;
EXTERN_C ULONG_PTR g_AcUnownedHwBpAccessAddress2;
EXTERN_C ULONG_PTR g_UnownedHwBpAccessTarget;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress1;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress2;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress3;
EXTERN_C ULONG_PTR g_UnownedHwBpWriteTarget;

//=============================================================================
// Client Interface
//=============================================================================
EXTERN_C
VOID
AcCaptureTargetR12(
    _In_ ULONG_PTR Value
);

EXTERN_C
VOID
AcExerciseUnownedHardwareBreakpoints(
    _In_ ULONG_PTR Value
);