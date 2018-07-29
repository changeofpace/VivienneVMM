#include "tests.h"

#include <iostream>

#include "arbitrary_code.h"
#include "test_util.h"

#include "..\common\debug.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define WINDBG_PROMPT "Execute the following command if WinDbg is attached:\n"
#define WINDBG_PRE_TEST_COMMAND     "sxd sse; sxd ssec;"
#define WINDBG_POST_TEST_COMMAND    "sxr;"
#define FLUSH_DURATION_MS           (SECONDS_TO_MILLISECONDS(2))

#define NUMBER_OF_ITERATIONS        100
#define SLEEP_DURATION_MS           200
#define WAIT_TIMEOUT_MS             (SECONDS_TO_MILLISECONDS(10))

#define BREAKPOINT_FACTOR_EXECUTE   1
#define BREAKPOINT_FACTOR_ACCESS    (BREAKPOINT_FACTOR_EXECUTE + 1)
#define BREAKPOINT_FACTOR_WRITE     (BREAKPOINT_FACTOR_ACCESS + 1)

static_assert(BREAKPOINT_FACTOR_EXECUTE != BREAKPOINT_FACTOR_ACCESS, "unique check");
static_assert(BREAKPOINT_FACTOR_EXECUTE != BREAKPOINT_FACTOR_WRITE, "unique check");
static_assert(BREAKPOINT_FACTOR_ACCESS != BREAKPOINT_FACTOR_WRITE, "unique check");


//=============================================================================
// Module Globals
//=============================================================================

// Each hit count should have a final total value equal to the number of
//  exercise iterations.
static volatile LONG g_ExecuteHitCount = 0;
static volatile LONG g_AccessHitCount = 0;
static volatile LONG g_WriteHitCount = 0;


//=============================================================================
// Internal Interface
//=============================================================================

//
// UnownedBreakpointVectoredHandler
//
static
LONG
CALLBACK
UnownedBreakpointVectoredHandler(
    _In_ PEXCEPTION_POINTERS pExceptionInfo
)
{
    PVOID pExceptionAddress = pExceptionInfo->ExceptionRecord->ExceptionAddress;
    PRFLAGS Rflags = (PRFLAGS)&pExceptionInfo->ContextRecord->EFlags;

    // Thread-local breakpoints should only cause single-step exceptions.
    if (STATUS_SINGLE_STEP != pExceptionInfo->ExceptionRecord->ExceptionCode)
    {
        FAIL_TEST(
            "Encountered unexpected exception at 0x%IX: 0x%X",
            (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress,
            pExceptionInfo->ExceptionRecord->ExceptionCode);
    }

    // Update the hit counts.
    if (pExceptionAddress == AcExerciseUnownedHardwareBreakpoints)
    {
        // Execution breakpoint.
        InterlockedIncrement(&g_ExecuteHitCount);
    }
    else if (pExceptionAddress == &g_AcUnownedHwBpAccessAddress1 ||
        pExceptionAddress == &g_AcUnownedHwBpAccessAddress2)
    {
        // Access breakpoints.
        InterlockedIncrement(&g_AccessHitCount);
    }
    else if (pExceptionAddress == &g_AcUnownedHwBpWriteAddress1 ||
        pExceptionAddress == &g_AcUnownedHwBpWriteAddress2 ||
        pExceptionAddress == &g_AcUnownedHwBpWriteAddress3)
    {
        // Write breakpoints.
        InterlockedIncrement(&g_WriteHitCount);
    }
    else
    {
        FAIL_TEST(
            "Encountered single-step exception at unexpected address: 0x%IX",
            (ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress);
    }

    // Resume execution.
    Rflags->RF = 1;

    return EXCEPTION_CONTINUE_EXECUTION;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestProcessUnownedHardwareBreakpoint
//
// This test is intended to verify that the breakpoint manager is correctly
//  ignoring hardware breakpoints set by other parties. We manually set an
//  execution, access, and write breakpoint by modifying the thread context of
//  the current thread. We then exercise each breakpoint and tally the hit
//  counts inside a new VEH.
//
// NOTE To run this test when WinDbg is attached as a kernel debugger, you
//  must execute the following command to pass single-step exceptions:
//
//      sxd sse; sxd ssec;
//
// The command to revert the changes caused by the above command:
//
//      sxr;
//
VOID
TestProcessUnownedHardwareBreakpoint()
{
    PVOID pVectoredHandler = NULL;
    LONG ExpectedHitCount = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    // Break if WinDbg is attached so we can execute the required command.
    PromptDebuggerExceptionConfiguration(
        WINDBG_PROMPT,
        WINDBG_PRE_TEST_COMMAND);

    // Install a VEH to catch the debug exceptions instead of using masm SEH
    //  for the exercise function.
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        UnownedBreakpointVectoredHandler);
    if (!pVectoredHandler)
    {
        FAIL_TEST(
            "AddVectoredExceptionHandler failed: %u\n",
            GetLastError());
    }

    // Install the breakpoints.
    //
    // Dr0 = Execute breakpoint.
    status = SetThreadLocalHardwareBreakpoint(
        0,
        GetCurrentThread(),
        (ULONG_PTR)AcExerciseUnownedHardwareBreakpoints,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte);
    if (!status)
    {
        FAIL_TEST(
            "SetThreadLocalHardwareBreakpoint (exec) failed: %u\n",
            GetLastError());
    }

    // Dr1 = Access breakpoint.
    status = SetThreadLocalHardwareBreakpoint(
        1,
        GetCurrentThread(),
        (ULONG_PTR)&g_UnownedHwBpAccessTarget,
        HWBP_TYPE::Access,
        HWBP_SIZE::Qword);
    if (!status)
    {
        FAIL_TEST(
            "SetThreadLocalHardwareBreakpoint (access) failed: %u\n",
            GetLastError());
    }

    // Dr2 = Write breakpoint.
    status = SetThreadLocalHardwareBreakpoint(
        2,
        GetCurrentThread(),
        (ULONG_PTR)&g_UnownedHwBpWriteTarget,
        HWBP_TYPE::Write,
        HWBP_SIZE::Qword);
    if (!status)
    {
        FAIL_TEST(
            "SetThreadLocalHardwareBreakpoint (write) failed: %u\n",
            GetLastError());
    }

    printf("Exercising thread-local breakpoints...\n");

    // Exercise the breakpoints.
    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        // NOTE Executing this function will break into an attached kernel
        //  debugger unless the debugger is configured to ignore single-step
        //  exceptions.
        AcExerciseUnownedHardwareBreakpoints(i);

        // Delay execution to allow the log buffer to flush.
        Sleep(SLEEP_DURATION_MS);
    }

    // Verify that each type of breakpoint was triggered the expected number
    //  of times.
    //
    // Verify execute hit count.
    ExpectedHitCount = NUMBER_OF_ITERATIONS * BREAKPOINT_FACTOR_EXECUTE;
    if (g_ExecuteHitCount != ExpectedHitCount)
    {
        FAIL_TEST(
            "Unexpected execution bp hit count: actual = %d, expected = %d\n",
            g_ExecuteHitCount,
            ExpectedHitCount);
    }

    // Verify access hit count.
    ExpectedHitCount = NUMBER_OF_ITERATIONS * BREAKPOINT_FACTOR_ACCESS;
    if (g_AccessHitCount != ExpectedHitCount)
    {
        FAIL_TEST(
            "Unexpected access bp hit count: actual = %d, expected = %d\n",
            g_AccessHitCount,
            ExpectedHitCount);
    }

    // Verify write hit count.
    ExpectedHitCount = NUMBER_OF_ITERATIONS * BREAKPOINT_FACTOR_WRITE;
    if (g_WriteHitCount != ExpectedHitCount)
    {
        FAIL_TEST(
            "Unexpected write bp hit count: actual = %d, expected = %d\n",
            g_WriteHitCount,
            ExpectedHitCount);
    }

    printf("Clearing thread-local breakpoints...\n");

    // Clear the breakpoints.
    status =
        ClearThreadLocalHardwareBreakpoint(0, GetCurrentThread()) &&
        ClearThreadLocalHardwareBreakpoint(1, GetCurrentThread()) &&
        ClearThreadLocalHardwareBreakpoint(2, GetCurrentThread());
    if (!status)
    {
        FAIL_TEST(
            "ClearThreadLocalHardwareBreakpoint failed: %u\n",
            GetLastError());
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

    // Break if WinDbg is attached so we can revert the previous command.
    PromptDebuggerExceptionConfiguration(
        WINDBG_PROMPT,
        WINDBG_POST_TEST_COMMAND);

    PRINT_TEST_FOOTER;
}