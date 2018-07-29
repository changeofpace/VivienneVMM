#include "tests.h"

#include "test_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define NUMBER_OF_ITERATIONS    100
#define SLEEP_DURATION_MS       200


//=============================================================================
// Module Globals
//=============================================================================
static USHORT g_AccessTarget = 1;
static ULONGLONG g_WriteTarget = 0;


//=============================================================================
// Internal Interface
//=============================================================================

//
// ExecuteTarget
//
static
BOOL
ExecuteTarget()
{
    return TRUE;
}


//
// ExerciseBreakpoints
//
static
VOID
ExerciseBreakpoints()
{
    USHORT temp = 0;

    // Exercise execution breakpoint.
    (VOID)ExecuteTarget();

    // Exercise access breakpoint.
    temp = g_AccessTarget;

    // Exercise write breakpoint.
    g_WriteTarget = temp + 2;

    // Stealth check.
    if (!BreakpointStealthCheck())
    {
        FAIL_TEST("BreakpointStealthCheck failed.\n");
    }
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestSetClearHardwareBreakpoint
//
// This test requires manual validation by checking the log file to see that
//  each type of breakpoint is logged correctly.
//
VOID
TestSetClearHardwareBreakpoint()
{
    PVOID pVectoredHandler = NULL;
    BOOL status = TRUE;

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

    // Install one of each type of hardware breakpoint.
    //
    // Dr0 = Execute breakpoint.
    printf(
        "Installing execution breakpoint at 0x%IX\n",
        (ULONG_PTR)ExecuteTarget);

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        0,
        (ULONG_PTR)ExerciseBreakpoints,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (execute) failed: %u\n",
            GetLastError());
    }

    // Dr1 = Access breakpoint.
    printf(
        "Installing access breakpoint at    0x%IX\n",
        (ULONG_PTR)&g_AccessTarget);

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        1,
        (ULONG_PTR)&g_AccessTarget,
        HWBP_TYPE::Access,
        HWBP_SIZE::Word);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (access) failed: %u\n",
            GetLastError());
    }

    // Dr2 = Write breakpoint.
    printf(
        "Installing write breakpoint at     0x%IX\n",
        (ULONG_PTR)&g_WriteTarget);

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        2,
        (ULONG_PTR)&g_WriteTarget,
        HWBP_TYPE::Write,
        HWBP_SIZE::Qword);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (write) failed: %u\n",
            GetLastError());
    }

    printf("Exercising breakpoints...\n");

    // Exercise the breakpoints.
    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        ExerciseBreakpoints();

        // Delay execution to allow the driver log buffer to flush.
        Sleep(SLEEP_DURATION_MS);
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