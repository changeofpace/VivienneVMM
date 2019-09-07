#include "tests.h"

#include <cstdio>

#include "arbitrary_code.h"
#include "test_util.h"

#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define NUMBER_OF_UNIQUE_RANDOM_VALUES  16
#define NUMBER_OF_THREADS               3
#define DEBUG_REGISTER_INDEX            3
#define CONTEXT_BUFFER_SIZE             (PAGE_SIZE)
#define REQUEST_DURATION_MS             (SECONDS_TO_MILLISECONDS(10))
#define SLEEP_DURATION_MS               200
#define WAIT_TIMEOUT_MS                 (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Module Globals
//=============================================================================
static HANDLE g_BarrierEvent = NULL;
static ULONG_PTR g_RandomValues[NUMBER_OF_UNIQUE_RANDOM_VALUES] = {};
static BOOLEAN g_Active = FALSE;


//=============================================================================
// Internal Interface
//=============================================================================

//
// ExerciseCecr
//
static
DWORD
WINAPI
ExerciseCecr(
    _In_ LPVOID lpParameter
)
{
    SIZE_T ValueIndex = 0;
    DWORD SleepDuration = {};
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    // Wait until all threads have been created.
    waitstatus = WaitForSingleObject(g_BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    while (g_Active)
    {
        // Stealth check.
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        // Calculate the effective index.
        ValueIndex = (ValueIndex + 1) % ARRAYSIZE(g_RandomValues);

        // Generate a random delay duration in range [0, 25] milliseconds.
        SleepDuration = RANDOM_ULONG % 25;

        // Exercise the target register.
        AcCaptureRegister(g_RandomValues[ValueIndex]);

        // Delay execution to allow the log buffer to flush.
        Sleep(SleepDuration);
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestCaptureRegisterValues
//
// This test captures the unique values in register R12 from a line of code
//  inside AcCaptureRegister.
//
VOID
TestCaptureRegisterValues()
{
    PVOID pVectoredHandler = NULL;
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    PCEC_REGISTER_VALUES pValuesCtx = NULL;
    BOOLEAN ValueFound = FALSE;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    // Initialize the thread barrier event.
    g_BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_BarrierEvent)
    {
        FAIL_TEST("CreateEvent failed: %u.\n", GetLastError());
    }

    // Install the stealth check VEH.
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        StealthCheckVectoredHandler);
    if (!pVectoredHandler)
    {
        FAIL_TEST(
            "AddVectoredExceptionHandler failed: %u\n",
            GetLastError());
    }

    printf("Generating random control values:\n");

    // Initialize an array of random values which will be passed to our target
    //  capture function by a set of threads.
    GenerateUniqueRandomValues(g_RandomValues, ARRAYSIZE(g_RandomValues));

    for (ULONG i = 0; i < ARRAYSIZE(g_RandomValues); ++i)
    {
        printf("    %02u: %Iu\n", i, g_RandomValues[i]);
    }

    // Allocate the captured context buffer.
    // NOTE This memory will leak if this test fails.
    pValuesCtx = (PCEC_REGISTER_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        FAIL_TEST("HeapAlloc failed: %u\n", GetLastError());
    }

    printf("Creating %Iu access threads...\n", ARRAYSIZE(hThreads));

    // Reset our event flag so that the threads exercise the breakpoint.
    g_Active = TRUE;

    // Create threads which exercise the code from which we will be capturing
    //  register context.
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        hThreads[i] = CreateThread(
            NULL,
            0,
            ExerciseCecr,
            NULL,
            0,
            &ThreadIds[i]);
        if (!hThreads[i])
        {
            FAIL_TEST("CreateThread failed: %u\n", GetLastError());
        }

        printf("    tid: %u (0x%X)\n", ThreadIds[i], ThreadIds[i]);
    }

    // Activate the exercise threads.
    status = SetEvent(g_BarrierEvent);
    if (!status)
    {
        FAIL_TEST("SetEvent failed: %u\n", GetLastError());
    }

    printf(
        "Requesting unique register values for R12 at 0x%IX\n",
        (ULONG_PTR)&g_AcCecrCaptureAddress);

    // Issue the synchronous CECR request.
    status = DrvCaptureRegisterValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)&g_AcCecrCaptureAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        REGISTER_R12,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        FAIL_TEST("DrvCaptureRegisterValues failed: %u\n", GetLastError());
    }

    // Lazily signal that all threads should terminate.
    g_Active = FALSE;

    // Wait for all threads to terminate.
    waitstatus = WaitForMultipleObjects(
        ARRAYSIZE(hThreads),
        hThreads,
        TRUE,
        WAIT_TIMEOUT_MS);
    if (waitstatus < WAIT_OBJECT_0 || waitstatus >= ARRAYSIZE(hThreads))
    {
        FAIL_TEST("WaitForMultipleObjects failed: %u\n", GetLastError());
    }

    // Close thread handles.
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
#pragma warning(suppress : 6001) // Using uninitialized memory.
        status = CloseHandle(hThreads[i]);
        if (!status)
        {
            FAIL_TEST("CloseHandle failed: %u\n", GetLastError());
        }
    }

    // Print the results.
    printf(
        "Cecr request completed with %u unique values:\n",
        pValuesCtx->NumberOfValues);

    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        printf("    %02u: %Iu\n", i, pValuesCtx->Values[i]);
    }

    // Examine the captured unique register values. The returned list of values
    //  should be equal to the random value array generated earlier.
    if (ARRAYSIZE(g_RandomValues) != pValuesCtx->NumberOfValues)
    {
        FAIL_TEST(
            "Unexpected number of captured values: actual = %u, expected = %Iu\n",
            pValuesCtx->NumberOfValues,
            ARRAYSIZE(g_RandomValues));
    }

    // There should be a 1-to-1 mapping of values in the CECR reply to the
    //  randomly generated values.
    for (ULONG i = 0; i < ARRAYSIZE(g_RandomValues); ++i)
    {
        ValueFound = FALSE;

        // NOTE We perform a full iteration, even after matching a value, to
        //  ensure that we do not have duplicate matches.
        for (ULONG j = 0; j < pValuesCtx->NumberOfValues; ++j)
        {
            if (g_RandomValues[i] == pValuesCtx->Values[j])
            {
                // Check for duplicate matches.
                if (ValueFound)
                {
                    FAIL_TEST(
                        "Found duplicate match for: %Iu\n",
                        g_RandomValues[i]);
                }

                ValueFound = TRUE;
            }
        }

        // If we do not match a value then our captured context is bugged.
        if (!ValueFound)
        {
            FAIL_TEST(
                "Failed to find %Iu in captured context.\n",
                g_RandomValues[i]);
        }
    }

    // Verify that all debug registers on all processors were cleared.
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        FAIL_TEST("Failed to clear a hardware breakpoint.\n");
    }

    // Release context.
    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            FAIL_TEST("HeapFree failed: %u\n", GetLastError());
        }
    }

    // Remove the VEH.
    status = RemoveVectoredExceptionHandler(pVectoredHandler);
    if (!status)
    {
        FAIL_TEST(
            "RemoveVectoredExceptionHandler failed: %u\n",
            GetLastError());
    }

    // Release the barrier event.
    if (!CloseHandle(g_BarrierEvent))
    {
        FAIL_TEST("CloseHandle failed: %u.\n", GetLastError());
    }

    PRINT_TEST_FOOTER;
}
