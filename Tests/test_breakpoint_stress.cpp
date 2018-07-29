#include "tests.h"

#include "test_util.h"

#include "..\common\arch_x64.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define NUMBER_OF_THREADS           3
#define NUMBER_OF_ITERATIONS        100
#define NUMBER_OF_ACCESS_TARGETS    10
#define NUMBER_OF_WRITE_TARGETS     10
#define SLEEP_DURATION_MS           200
#define SLEEP_VARIANCE_MS           100
#define WAIT_TIMEOUT_MS             (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Types
//=============================================================================
typedef struct _STRESSTEST_CONTEXT
{
    ULONG SleepDuration;
    ULONG AccessIndex;
    ULONG WriteIndex;
    ULONG RandomValue;
    LPTHREAD_START_ROUTINE Exerciser;
} STRESSTEST_CONTEXT, *PSTRESSTEST_CONTEXT;


//=============================================================================
// Module Globals
//=============================================================================
static ULONG g_pAccessTargets[NUMBER_OF_ACCESS_TARGETS] = {};
static ULONG g_pWriteTargets[NUMBER_OF_WRITE_TARGETS] = {};
static BOOLEAN g_Active = FALSE;


//=============================================================================
// Internal Interface
//=============================================================================

//
// StressTest functions.
//
static
DWORD
WINAPI
StressTest1(
    _In_ LPVOID lpParameter
)
{
    PSTRESSTEST_CONTEXT pContext = (PSTRESSTEST_CONTEXT)lpParameter;
    ULONG AccessValue = 0;
    DWORD status = ERROR_SUCCESS;

    while (g_Active)
    {
        AccessValue = g_pAccessTargets[pContext->AccessIndex];
        
        g_pWriteTargets[pContext->WriteIndex] =
            AccessValue * pContext->RandomValue;

        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        Sleep(pContext->SleepDuration);
    }

    return status;
}
//
static
DWORD
WINAPI
StressTest2(
    _In_ LPVOID lpParameter
)
{
    PSTRESSTEST_CONTEXT pContext = (PSTRESSTEST_CONTEXT)lpParameter;
    ULONG AccessValue = 0;
    DWORD status = ERROR_SUCCESS;

    while (g_Active)
    {
        AccessValue = g_pAccessTargets[pContext->AccessIndex];

        g_pWriteTargets[pContext->WriteIndex] =
            AccessValue / pContext->RandomValue;

        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        Sleep(pContext->SleepDuration);
    }

    return status;
}
//
static
DWORD
WINAPI
StressTest3(
    _In_ LPVOID lpParameter
)
{
    PSTRESSTEST_CONTEXT pContext = (PSTRESSTEST_CONTEXT)lpParameter;
    ULONG AccessValue = 0;
    DWORD status = ERROR_SUCCESS;

    while (g_Active)
    {
        AccessValue = g_pAccessTargets[pContext->AccessIndex];

        g_pWriteTargets[pContext->WriteIndex] =
            AccessValue << pContext->RandomValue;

        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        Sleep(pContext->SleepDuration);
    }

    return status;
}


//
// InitializeStressTestContext
//
static
BOOL
InitializeStressTestContext(
    _Inout_ PSTRESSTEST_CONTEXT pContext,
    _In_ ULONG Index
)
{
    BOOL status = TRUE;

    // Zero out parameters.
    RtlZeroMemory(pContext, sizeof(*pContext));

    pContext->SleepDuration =
        SLEEP_DURATION_MS + (RANDOM_ULONG % SLEEP_VARIANCE_MS);
    pContext->AccessIndex = RANDOM_ULONG % ARRAYSIZE(g_pAccessTargets);
    pContext->WriteIndex = RANDOM_ULONG % ARRAYSIZE(g_pWriteTargets);
    pContext->RandomValue = RANDOM_ULONG;

    switch (Index)
    {
        case 0: pContext->Exerciser = StressTest1; break;
        case 1: pContext->Exerciser = StressTest2; break;
        case 2: pContext->Exerciser = StressTest3; break;
        default:
        {
            status = FALSE;
            goto exit;
        }
    }

exit:
    return status;
}


//
// SetRandomBreakpoint
//
static
VOID
SetRandomBreakpoint()
{
    ULONG Index = 0;
    ULONG_PTR Address = 0;
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    BOOL status = TRUE;

    Index = RANDOM_ULONG % DAR_COUNT;

    switch (RANDOM_ULONG % (DAR_COUNT - 1))
    {
        // Execution.
        case 0:
        {
            Address = (RANDOM_ULONG % 2)
                ? (ULONG_PTR)&BreakpointStealthCheck
                : (ULONG_PTR)&Sleep;
            Type = HWBP_TYPE::Execute;
            Size = HWBP_SIZE::Byte;
            break;
        }
        // Access.
        case 1:
        {
            Address = (ULONG_PTR)&g_pAccessTargets[
                RANDOM_ULONG % (ARRAYSIZE(g_pAccessTargets) - 1)
            ];
            Type = HWBP_TYPE::Access;
            Size = HWBP_SIZE::Dword;
            break;
        }
        // Write.
        case 2:
        {
            Address = (ULONG_PTR)&g_pWriteTargets[
                RANDOM_ULONG % (ARRAYSIZE(g_pWriteTargets) - 1)
            ];
            Type = HWBP_TYPE::Write;
            Size = HWBP_SIZE::Dword;
            break;
        }
        default:
        {
            FAIL_TEST("Unexpected index: %u", Index);
        }
    }

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        Index,
        Address,
        Type,
        Size);
    if (!status)
    {
        FAIL_TEST("DrvSetHardwareBreakpoint failed: %u", GetLastError());
    }
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestHardwareBreakpointStress
//
// This test requires manual validation by checking the log file for unhandled
//  debug exceptions.
//
VOID
TestHardwareBreakpointStress()
{
    PVOID pVectoredHandler = NULL;
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    STRESSTEST_CONTEXT pContexts[NUMBER_OF_THREADS] = {};
    ULONG SleepDuration = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    static_assert(ARRAYSIZE(hThreads) == ARRAYSIZE(ThreadIds), "Size check");

    PRINT_TEST_HEADER;

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

    printf("Generating random control values...\n");

    // Initialize the access and write target arrays with random values.
    GenerateUniqueRandomValues(g_pAccessTargets, ARRAYSIZE(g_pAccessTargets));

    printf("Access Target Values:\n");

    for (ULONG i = 0; i < ARRAYSIZE(g_pAccessTargets); ++i)
    {
        printf(
            "    %02u: %8u %8X\n",
            i,
            g_pAccessTargets[i],
            g_pAccessTargets[i]);
    }

    GenerateUniqueRandomValues(g_pWriteTargets, ARRAYSIZE(g_pWriteTargets));

    printf("Write Target Values:\n");

    for (ULONG i = 0; i < ARRAYSIZE(g_pWriteTargets); ++i)
    {
        printf(
            "    %02u: %8u %8X\n",
            i,
            g_pWriteTargets[i],
            g_pWriteTargets[i]);
    }

    // Initialize thread contexts.
    for (ULONG i = 0; i < ARRAYSIZE(pContexts); ++i)
    {
        if (!InitializeStressTestContext(&pContexts[i], i))
        {
            FAIL_TEST("InitializeStressTestContext failed.\n");
        }
    }

    // Reset our event flag so that the threads spin during the stress test.
    g_Active = TRUE;

    printf("Starting stress test...\n");

    // Create threads which exercise each type of breakpoint (excluding size
    //  variants).
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        hThreads[i] = CreateThread(
            NULL,
            0,
            pContexts[i].Exerciser,
            &pContexts[i],
            0,
            &ThreadIds[i]);
        if (!hThreads[i])
        {
            FAIL_TEST("CreateThread %u failed: %u\n", i, GetLastError());
        }
    }

    //
    // Begin the stress test by setting 'random' breakpoints at a random
    //  interval. The idea here is to constantly overwrite the debug registers
    //  to verify that the breakpoint manager is correctly locking and handling
    //  each breakpoint.
    //
    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        SetRandomBreakpoint();
        SleepDuration = SLEEP_DURATION_MS + (RANDOM_ULONG % SLEEP_VARIANCE_MS);
        Sleep(SleepDuration);
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
        FAIL_TEST(
            "WaitForMultipleObjects failed: %u\n",
            GetLastError());
    }

    // Close thread handles.
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        status = CloseHandle(hThreads[i]);
        if (!status)
        {
            FAIL_TEST("CloseHandle failed: %u\n", GetLastError());
        }
    }

    printf("Clearing breakpoints...\n");

    // Clear all breakpoints.
    status =
        DrvClearHardwareBreakpoint(0) &&
        DrvClearHardwareBreakpoint(1) &&
        DrvClearHardwareBreakpoint(2) &&
        DrvClearHardwareBreakpoint(3);
    if (!status)
    {
        FAIL_TEST("DrvClearHardwareBreakpoint failed: %u.\n", GetLastError());
    }

    // Verify that all debug registers on all processors were cleared.
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        FAIL_TEST("Failed to clear a hardware breakpoint.\n");
    }

    // Remove the VEH.
    status = RemoveVectoredExceptionHandler(pVectoredHandler);
    if (!status)
    {
        FAIL_TEST(
            "RemoveVectoredExceptionHandler failed: %u\n",
            GetLastError());
    }

    PRINT_TEST_FOOTER;
}