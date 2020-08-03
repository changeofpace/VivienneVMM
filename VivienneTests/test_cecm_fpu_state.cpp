#include "tests.h"

#include <cstdio>

#include "arbitrary_code.h"
#include "test_util.h"

#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"
#include "..\VivienneCL\ntdll.h"
#include "..\VivienneCL\token_parser.h"


//=============================================================================
// Constants
//=============================================================================

//
// This value must be synchronized with arbitrary_code!g_CecmFpuStateSentinel.
//
#define SENTINEL_FLOAT_VALUE            77777.75f
#define FLOAT_PRNG_VALUE                1348.151251f
#define CECM_TARGET_TEXT                "rcx+rax*4"
#define NUMBER_OF_UNIQUE_RANDOM_VALUES  16
#define NUMBER_OF_THREADS               4
#define DEBUG_REGISTER_INDEX            1
#define CONTEXT_BUFFER_SIZE             (PAGE_SIZE)
#define REQUEST_DURATION_MS             (SECONDS_TO_MILLISECONDS(10))
#define WAIT_TIMEOUT_MS                 (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Types
//=============================================================================
typedef struct _FPU_STATE_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
    FLOAT RandomValues[NUMBER_OF_UNIQUE_RANDOM_VALUES];
} FPU_STATE_CONTEXT, *PFPU_STATE_CONTEXT;


//=============================================================================
// Internal Interface
//=============================================================================

//
// ExerciseCecm
//
static
DWORD
WINAPI
ExerciseCecm(
    _In_ LPVOID lpParameter
)
{
    PFPU_STATE_CONTEXT pContext = (PFPU_STATE_CONTEXT)lpParameter;
    FLOAT SentinelCheck = 0;
    SIZE_T ValueIndex = 0;
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    //
    // Wait until all threads have been created.
    //
    waitstatus = WaitForSingleObject(pContext->BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    while (pContext->Active)
    {
        ValueIndex = (ValueIndex + 1) % ARRAYSIZE(pContext->RandomValues);

        SentinelCheck = AcCaptureMemoryFpuState(
            pContext->RandomValues,
            ARRAYSIZE(pContext->RandomValues),
            ValueIndex);
        if (SENTINEL_FLOAT_VALUE != SentinelCheck)
        {
            FAIL_TEST(
                "Invalid sentinel float: %f (tid = %u)\n",
                SentinelCheck,
                GetCurrentThreadId());
        }

        (VOID)NtYieldExecution();
    }

    return status;
}


//
// InitializeFpuStateContext
//
_Check_return_
static
BOOL
InitializeFpuStateContext(
    _Out_ PFPU_STATE_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pContext, sizeof(*pContext));

    BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!BarrierEvent)
    {
        printf("CreateEvent failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Manually generate float values.
    //
    for (ULONG i = 0; i < ARRAYSIZE(pContext->RandomValues); ++i)
    {
        pContext->RandomValues[i] = (FLOAT)((i + 1) * FLOAT_PRNG_VALUE);
        printf("    %02u: %f\n", i, pContext->RandomValues[i]);
    }

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;

exit:
    if (!status)
    {
        if (BarrierEvent)
        {
            if (!CloseHandle(BarrierEvent))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// ReleaseFpuStateContext
//
_Check_return_
static
BOOL
ReleaseFpuStateContext(
    _In_ PFPU_STATE_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->BarrierEvent)
    {
        if (!CloseHandle(pContext->BarrierEvent))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}


//
// ExecuteCecmForInstructionAddress
//
static
BOOL
ExecuteCecmForInstructionAddress(
    _In_ ULONG_PTR Address,
    _In_ PCEC_MEMORY_DESCRIPTION pMemoryDescription
)
{
    FPU_STATE_CONTEXT Context = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    PMEMORY_DATA_VALUE pMemoryDataValue = NULL;
    DWORD waitstatus = 0;
    BOOL status = FALSE;

    printf("Executing CECM fpu state validation for 0x%IX\n", Address);

    //
    // Initialize the exercise thread context.
    //
    status = InitializeFpuStateContext(&Context);
    if (!status)
    {
        printf("InitializeFpuStateContext failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Allocate the captured context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Creating %Iu exercise threads...\n", ARRAYSIZE(hThreads));

    //
    // Create threads which exercise the code from which we will be capturing
    //  memory context.
    //
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        hThreads[i] = CreateThread(
            NULL,
            0,
            ExerciseCecm,
            &Context,
            0,
            &ThreadIds[i]);
        if (!hThreads[i])
        {
            printf("CreateThread failed: %u\n", GetLastError());
            status = FALSE;
            goto exit;
        }

        printf("    tid: %u (0x%X)\n", ThreadIds[i], ThreadIds[i]);
    }

    //
    // Activate the exercise threads.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    printf(
        "Requesting memory values for [%s] at 0x%IX\n",
        CECM_TARGET_TEXT,
        Address);

    //
    // Issue the synchronous CECM request.
    //
    status = VivienneIoCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        Address,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        pMemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("VivienneIoCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Lazily signal that all threads should terminate.
    //
    Context.Active = FALSE;

    //
    // Wait for all threads to terminate.
    //
    waitstatus = WaitForMultipleObjects(
        ARRAYSIZE(hThreads),
        hThreads,
        TRUE,
        WAIT_TIMEOUT_MS);
    if (waitstatus < WAIT_OBJECT_0 || waitstatus >= ARRAYSIZE(hThreads))
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Print the results.
    //
    printf(
        "Cecm request completed with %u unique values:\n",
        pValuesCtx->NumberOfValues);

    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        pMemoryDataValue = (PMEMORY_DATA_VALUE)(&pValuesCtx->Values[i]);

        printf("    %02u: %f\n", i, pMemoryDataValue->Float);
    }

    //
    // Examine the captured unique register values. The returned list of values
    //  should be equal to the random value array generated earlier.
    //
    if (ARRAYSIZE(Context.RandomValues) != pValuesCtx->NumberOfValues)
    {
        printf(
            "Unexpected number of captured values: actual = %u, expected = %Iu\n",
            pValuesCtx->NumberOfValues,
            ARRAYSIZE(Context.RandomValues));
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the returned list of values matches the random values in the
    //  thread context.
    //
    for (SIZE_T i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        PMEMORY_DATA_VALUE pValuesMdt =
            (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];
        BOOLEAN ValueFound = FALSE;

        for (SIZE_T j = 0; j < ARRAYSIZE(Context.RandomValues); ++j)
        {
            PMEMORY_DATA_VALUE pRandomMdt =
                (PMEMORY_DATA_VALUE)&Context.RandomValues[j];

            if (pRandomMdt->Float == pValuesMdt->Float)
            {
                //
                // Check for duplicate matches.
                //
                if (ValueFound)
                {
                    printf("Duplicate value found.\n");
                    status = FALSE;
                    goto exit;
                }

                ValueFound = TRUE;
            }
        }

        //
        // If we do not match a value then our captured context is bugged.
        //
        if (!ValueFound)
        {
            printf("Unmatched value: %f.\n", pValuesMdt->Double);
            status = FALSE;
            goto exit;
        }
    }

    //
    // Verify that there were no validation errors.
    //
    if (pValuesCtx->Statistics.ValidationErrors)
    {
        printf(
            "Unexpected number of validation errors: %Iu\n",
            pValuesCtx->Statistics.ValidationErrors);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that all debug registers on all processors were cleared.
    //
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        printf("Failed to clear a hardware breakpoint.\n");
        goto exit;
    }

exit:
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        if (hThreads[i])
        {
#pragma warning(suppress : 6001) // Using uninitialized memory.
            if (!CloseHandle(hThreads[i]))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
                status = FALSE;
            }
        }
    }

    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (!ReleaseFpuStateContext(&Context))
    {
        printf("ReleaseFpuStateContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestCaptureMemoryValuesFpuState
//
// This test verifies that installing hardware breakpoints (via a CECM request)
//  does not corrupt SSE/AVX registers.
//
VOID
TestCaptureMemoryValuesFpuState()
{
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    //
    // Initialize the target memory description.
    //
    status = ParseMemoryDescriptionToken(
        CECM_TARGET_TEXT,
        MDT_FLOAT,
        &MemoryDescription);
    if (!status)
    {
        FAIL_TEST("ParseMemoryDescriptionToken failed.\n");
    }

    //
    // Execute a CECM request for a few different addresses.
    //
    status = ExecuteCecmForInstructionAddress(
        (ULONG_PTR)&g_AcCecmFpuStateCaptureAddress1,
        &MemoryDescription);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmForInstructionAddress failed. (1)\n");
    }

    status = ExecuteCecmForInstructionAddress(
        (ULONG_PTR)&g_AcCecmFpuStateCaptureAddress2,
        &MemoryDescription);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmForInstructionAddress failed. (2)\n");
    }

    status = ExecuteCecmForInstructionAddress(
        (ULONG_PTR)&g_AcCecmFpuStateCaptureAddress3,
        &MemoryDescription);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmForInstructionAddress failed. (3)\n");
    }

    PRINT_TEST_FOOTER;
}
