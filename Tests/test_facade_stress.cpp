#include <windows.h>

#include <cstdio>

#include "test_util.h"

#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"
#include "..\VivienneCL\ntdll.h"


//=============================================================================
// Constants
//=============================================================================
#define MIN_VALID_USER_ADDRESS      0x00000010000
#define MAX_VALID_USER_ADDRESS      0x7FFFFFEFFFF

#define NUMBER_OF_THREADS           (DAR_COUNT + 1)
#define NUMBER_OF_ITERATIONS        200

// This timeout must allow enough time for InstallVvmmBreakpoints to execute
//  its loop NUMBER_OF_ITERATIONS times. This may take a significant amount of
//  time if a kernel debugger is attached because of logging lag. If
//  InstallVvmmBreakpoints fails because of a timeout then increase this time
//  or reduce NUMBER_OF_ITERATIONS.
#define WAIT_TIMEOUT_MS             (SECONDS_TO_MILLISECONDS(300))

#define THREADLOCAL_SLEEP_MIN_MS    1
#define THREADLOCAL_SLEEP_MAX_MS    200


//=============================================================================
// Types
//=============================================================================
typedef struct _FACADE_STRESS_CONTEXT
{
    ULONG DebugRegisterIndex;
} FACADE_STRESS_CONTEXT, *PFACADE_STRESS_CONTEXT;


//=============================================================================
// Module Globals
//=============================================================================
static HANDLE g_BarrierEvent = NULL;
static volatile LONGLONG g_ThreadLocalIterations = 0;
static volatile LONGLONG g_VvmmManagedIterations = 0;
static volatile LONGLONG g_ThreadStopCondition = 0;


//=============================================================================
// Internal Interface
//=============================================================================

//
// GenerateRandomThreadLocalBreakpointParameters
//
static
VOID
GenerateRandomThreadLocalBreakpointParameters(
    _Out_ PULONG_PTR pAddress,
    _Out_ PHWBP_TYPE pType,
    _Out_ PHWBP_SIZE pSize
)
{
    ULONG_PTR Address = 0;
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};

    // Zero out parameters.
    *pAddress = NULL;
    *pType = {};
    *pSize = {};

    // Address must be a valid userspace address.
    *pAddress = (ULONG_PTR)GenerateBoundedRandomValue(
        MIN_VALID_USER_ADDRESS,
        MAX_VALID_USER_ADDRESS);

    // Type.
    switch ((HWBP_TYPE)(RANDOM_ULONG % 3))
    {
        case HWBP_TYPE::Execute: Type = HWBP_TYPE::Execute; break;
        case HWBP_TYPE::Write:   Type = HWBP_TYPE::Write;   break;
        case HWBP_TYPE::Access:  __fallthrough;
        default:                 Type = HWBP_TYPE::Access;  break;
    }

    // Size.
    //
    // NOTE Data breakpoints must be aligned based on the size-condition.
    switch ((HWBP_SIZE)(RANDOM_ULONG % 4))
    {
        case HWBP_SIZE::Byte:
        {
            Size = HWBP_SIZE::Byte;
            break;
        }
        case HWBP_SIZE::Word:
        {
            Size = HWBP_SIZE::Word;
            ALIGN_DOWN_POINTER_BY(pAddress, sizeof(WORD));
            break;
        }
        case HWBP_SIZE::Qword:
        {
            Size = HWBP_SIZE::Qword;
            ALIGN_DOWN_POINTER_BY(pAddress, sizeof(DWORD64));
            break;
        }
        case HWBP_SIZE::Dword:
        {
            __fallthrough;
        }
        default:
        {
            Size = HWBP_SIZE::Dword;
            ALIGN_DOWN_POINTER_BY(pAddress, sizeof(DWORD));
            break;
        }
    }

    // Set out parameters.
    *pAddress = Address;
    *pType = Type;
    *pSize = Size;
}


//
// InstallThreadLocalBreakpoints
//
static
DWORD
WINAPI
InstallThreadLocalBreakpoints(
    _In_ LPVOID lpParameter
)
{
    PFACADE_STRESS_CONTEXT pContext = (PFACADE_STRESS_CONTEXT)lpParameter;
    DWORD waitstatus = 0;
    DWORD threadstatus = ERROR_SUCCESS;

    // Wait until all threads have been created.
    waitstatus = WaitForSingleObject(g_BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    // NOTE This check should be atomic, but the presence of a race condition
    //  here will not negatively impact the test.
    while (NUMBER_OF_ITERATIONS > g_ThreadStopCondition)
    {
        ULONG_PTR Address = 0;
        HWBP_TYPE Type = {};
        HWBP_SIZE Size = {};
        ULONG SleepDuration = 0;
        BOOL status = TRUE;

        InterlockedIncrement64(&g_ThreadLocalIterations);
        
        // Set a random thread-local breakpoint.
        // NOTE This breakpoint will not (and cannot) be triggered.
        GenerateRandomThreadLocalBreakpointParameters(&Address, &Type, &Size);

        status = SetThreadLocalHardwareBreakpoint(
            pContext->DebugRegisterIndex,
            GetCurrentThread(),
            Address,
            Type,
            Size);
        if (!status)
        {
            FAIL_TEST(
                "SetThreadLocalHardwareBreakpoint failed: %u\n",
                GetLastError());
        }

        // Sleep for a bit.
        SleepDuration = (ULONG)GenerateBoundedRandomValue(
            THREADLOCAL_SLEEP_MIN_MS,
            THREADLOCAL_SLEEP_MAX_MS);

        Sleep(SleepDuration);

        // Verify the contents of the debug address register.
        status = VerifyThreadLocalBreakpointByIndex(
            pContext->DebugRegisterIndex,
            GetCurrentThread(),
            Address,
            Type,
            Size);
        if (!status)
        {
            FAIL_TEST(
                "VerifyThreadLocalBreakpointByIndex failed: %u\n",
                GetLastError());
        }
    }

    return threadstatus;
}


//
// InstallVvmmBreakpoints
//
static
DWORD
WINAPI
InstallVvmmBreakpoints(
    _In_ LPVOID lpParameter
)
{
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(lpParameter);

    // Wait until all threads have been created.
    waitstatus = WaitForSingleObject(g_BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    // Atomic operations are not required because only one thread will write
    //  to the stop-condition global. This laziness is to reduce complexity.
    while (NUMBER_OF_ITERATIONS > g_ThreadStopCondition)
    {
        ULONG Index = RANDOM_ULONG % DAR_COUNT;
        ULONG_PTR Address = 0;
        HWBP_TYPE Type = {};
        HWBP_SIZE Size = {};
        ULONG SleepDuration = 0;
        BOOL status = TRUE;

        InterlockedIncrement64(&g_VvmmManagedIterations);

        // Set a random VVMM-breakpoint.
        GenerateRandomThreadLocalBreakpointParameters(&Address, &Type, &Size);

        status = DrvSetHardwareBreakpoint(
            GetCurrentProcessId(),
            Index,
            Address,
            Type,
            Size);
        if (!status)
        {
            FAIL_TEST("DrvSetHardwareBreakpoint failed: %u\n", GetLastError());
        }

        // Occasionally clear a random breakpoint.
        if (0 == RANDOM_ULONG % 5)
        {
            status = DrvClearHardwareBreakpoint(RANDOM_ULONG % DAR_COUNT);
            if (!status)
            {
                FAIL_TEST(
                    "DrvClearHardwareBreakpoint failed: %u\n",
                    GetLastError());
            }
        }

        // Sleep for a bit.
        SleepDuration = (ULONG)GenerateBoundedRandomValue(
            THREADLOCAL_SLEEP_MIN_MS,
            THREADLOCAL_SLEEP_MAX_MS);

        Sleep(SleepDuration);

        InterlockedIncrement64(&g_ThreadStopCondition);
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestDebugRegisterFacadeStress
//
VOID
TestDebugRegisterFacadeStress()
{
    PVOID pVectoredHandler = NULL;
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    FACADE_STRESS_CONTEXT ThreadContexts[NUMBER_OF_THREADS] = {};
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    static_assert(ARRAYSIZE(hThreads) == ARRAYSIZE(ThreadIds), "Size check");
    static_assert(ARRAYSIZE(hThreads) == ARRAYSIZE(ThreadContexts), "Size check");
    static_assert(ARRAYSIZE(ThreadIds) == ARRAYSIZE(ThreadContexts), "Size check");

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

    printf("Starting facade stress test...\n");

    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        LPTHREAD_START_ROUTINE pThreadRoutine = NULL;

        // Create as many threads as debug address registers. These threads
        //  will constantly install random, thread-local breakpoints in their
        //  assigned debug register index. We do not use random indices to
        //  reduce complexity.
        if (i < DAR_COUNT)
        {
            pThreadRoutine = InstallThreadLocalBreakpoints;
            ThreadContexts[i].DebugRegisterIndex = i;

            printf("Thread local Dr%u:    ", i);
        }
        // The remaining thread will constantly install random, VVMM-managed
        //  breakpoints in random debug address registers.
        else
        {
            pThreadRoutine = InstallVvmmBreakpoints;
            ThreadContexts[i].DebugRegisterIndex = ULONG_MAX;

            printf("Vvmm managed thread: ");
        }

        hThreads[i] = CreateThread(
            NULL,
            0,
            pThreadRoutine,
            &ThreadContexts[i],
            0,
            &ThreadIds[i]);
        if (!hThreads[i])
        {
            FAIL_TEST("CreateThread %u failed: %u\n", i, GetLastError());
        }

        printf("tid = 0x%IX\n", (ULONG_PTR)ThreadIds[i]);
    }

    // Activate the exercise threads.
    status = SetEvent(g_BarrierEvent);
    if (!status)
    {
        FAIL_TEST("SetEvent failed: %u\n", GetLastError());
    }

    // Allow the threads to execute until the iteration count is met.
    waitstatus = WaitForMultipleObjects(
        ARRAYSIZE(hThreads),
        hThreads,
        TRUE,
        WAIT_TIMEOUT_MS);
    if (waitstatus < WAIT_OBJECT_0 || waitstatus >= ARRAYSIZE(hThreads))
    {
        FAIL_TEST(
            "WaitForMultipleObjects failed: waitstatus=%u, lasterror=%u\n",
            waitstatus,
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

    // The main thread should not have breakpoints set.
    status = BreakpointStealthCheck();
    if (!status)
    {
        FAIL_TEST("BreakpointStealthCheck failed: %u\n", GetLastError());
    }

    // Clear all VVMM-managed breakpoints.
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

    // Release the barrier event.
    if (!CloseHandle(g_BarrierEvent))
    {
        FAIL_TEST("CloseHandle failed: %u.\n", GetLastError());
    }

    // Print statistics.
    printf("%llu thread-local breakpoints generated.\n",
        g_ThreadLocalIterations);
    printf("%llu VVMM-managed breakpoints generated.\n",
        g_VvmmManagedIterations);

    PRINT_TEST_FOOTER;
}
