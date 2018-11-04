#include "tests.h"

#include <cstdio>

#include "test_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define NUMBER_OF_ITERATIONS    100
#define SLEEP_DURATION_MS       100


//=============================================================================
// Module Globals
//=============================================================================
static DWORD g_AccessTarget = 1;


//=============================================================================
// Internal Interface
//=============================================================================

//
// ExecuteTarget
//
static
DECLSPEC_NOINLINE
BOOL
ExecuteTarget()
{
    return TRUE;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestDuplicateHardwareBreakpoints
//
// This test requires manual validation by checking the log file to see that
//  each type of breakpoint is logged correctly.
//
// Failure is indicated by program crash due to unhandled single step exception.
//
VOID
TestDuplicateHardwareBreakpoints()
{
    PVOID pVectoredHandler = NULL;
    DWORD Value = 0;
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

    // Install duplicate execution breakpoints in Dr0 and Dr3.
    printf(
        "Installing execution breakpoints at 0x%IX\n",
        (ULONG_PTR)ExecuteTarget);

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        0,
        (ULONG_PTR)ExecuteTarget,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (execute) failed: %u\n",
            GetLastError());
    }

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        3,
        (ULONG_PTR)ExecuteTarget,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (execute) failed: %u\n",
            GetLastError());
    }

    // Exercise the breakpoints.
    printf("Exercising execution breakpoints...\n");

    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        // Stealth check.
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        // Trigger the breakpoint.
        (VOID)ExecuteTarget();

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
    if (!AreAllHardwareBreakpointsCleared())
    {
        FAIL_TEST("Failed to clear a hardware breakpoint.\n");
    }

    // Install duplicate access breakpoints in Dr1, Dr2, and Dr3.
    printf(
        "Installing access breakpoints at 0x%IX\n",
        (ULONG_PTR)&g_AccessTarget);

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        1,
        (ULONG_PTR)&g_AccessTarget,
        HWBP_TYPE::Access,
        HWBP_SIZE::Dword);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (access) failed: %u\n",
            GetLastError());
    }

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        2,
        (ULONG_PTR)&g_AccessTarget,
        HWBP_TYPE::Access,
        HWBP_SIZE::Dword);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (access) failed: %u\n",
            GetLastError());
    }

    status = DrvSetHardwareBreakpoint(
        GetCurrentProcessId(),
        3,
        (ULONG_PTR)&g_AccessTarget,
        HWBP_TYPE::Access,
        HWBP_SIZE::Dword);
    if (!status)
    {
        FAIL_TEST(
            "DrvSetHardwareBreakpoint (access) failed: %u\n",
            GetLastError());
    }

    // Exercise the breakpoints.
    printf("Exercising access breakpoints...\n");

    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        // Stealth check.
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        // Trigger the breakpoints.
        Value = g_AccessTarget;

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