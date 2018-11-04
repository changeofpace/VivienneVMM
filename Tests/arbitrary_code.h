#pragma once

#include <Windows.h>

//=============================================================================
// Globals
//=============================================================================

// NOTE These values must be kept synchronized with their associated tests.

//
// AcCaptureRegister
//
EXTERN_C ULONG_PTR g_AcCecrCaptureAddress;

//
// AcCaptureMemoryDouble
//
EXTERN_C ULONG_PTR g_AcCecrDoubleCaptureAddress;

//
// AcCaptureMemoryFpuState
//
EXTERN_C ULONG_PTR g_AcCecmFpuStateCaptureAddress1;
EXTERN_C ULONG_PTR g_AcCecmFpuStateCaptureAddress2;
EXTERN_C ULONG_PTR g_AcCecmFpuStateCaptureAddress3;

//
// AcExerciseUnownedHardwareBreakpoints
//
EXTERN_C ULONG_PTR g_AcUnownedHwBpAccessAddress1;
EXTERN_C ULONG_PTR g_AcUnownedHwBpAccessAddress2;
EXTERN_C ULONG_PTR g_AcUnownedHwBpAccessTarget;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress1;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress2;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteAddress3;
EXTERN_C ULONG_PTR g_AcUnownedHwBpWriteTarget;

//=============================================================================
// Client Interface
//=============================================================================
EXTERN_C
VOID
AcCaptureRegister(
    _In_ ULONG_PTR Value
);

EXTERN_C
DOUBLE
AcCaptureMemoryDouble(
    _In_count_(cValues) DOUBLE pValues[],
    _In_ SIZE_T cValues,
    _In_ SIZE_T Index
);

EXTERN_C
FLOAT
AcCaptureMemoryFpuState(
    _In_count_(cValues) FLOAT pValues[],
    _In_ SIZE_T cValues,
    _In_ SIZE_T Index
);

EXTERN_C
VOID
AcExerciseUnownedHardwareBreakpoints(
    _In_ ULONG_PTR Value
);
