#include <windows.h>

#include <cstdio>

#include "test_util.h"

#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"
#include "..\VivienneCL\ntdll.h"


//=============================================================================
// Constants
//=============================================================================
#define SHARED_BREAKPOINT_INDEX         1

// NOTE Neither of these breakpoints will be triggered.
// NOTE The breakpoint addresses must be canonical user addresses.
#define THREADLOCAL_BREAKPOINT_ADDRESS  0xF1238ull
#define THREADLOCAL_BREAKPOINT_TYPE     HWBP_TYPE::Write
#define THREADLOCAL_BREAKPOINT_SIZE     HWBP_SIZE::Dword

#define VVMMGLOBAL_BREAKPOINT_ADDRESS   0xEECE0ull
#define VVMMGLOBAL_BREAKPOINT_TYPE      HWBP_TYPE::Access
#define VVMMGLOBAL_BREAKPOINT_SIZE      HWBP_SIZE::Qword

static_assert(
    THREADLOCAL_BREAKPOINT_ADDRESS != VVMMGLOBAL_BREAKPOINT_ADDRESS,
    "Value check");

static_assert(
    THREADLOCAL_BREAKPOINT_TYPE != VVMMGLOBAL_BREAKPOINT_TYPE,
    "Value check");

static_assert(
    THREADLOCAL_BREAKPOINT_SIZE != VVMMGLOBAL_BREAKPOINT_SIZE,
    "Value check");

static_assert(
    IS_ALIGNED(THREADLOCAL_BREAKPOINT_ADDRESS, sizeof(ULONG_PTR)),
    "Alignment check");

static_assert(
    IS_ALIGNED(VVMMGLOBAL_BREAKPOINT_ADDRESS, sizeof(ULONG_PTR)),
    "Alignment check");


//=============================================================================
// Test Interface
//=============================================================================

//
// TestDebugRegisterFacade
//
VOID
TestDebugRegisterFacade()
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

    // Install a thread-local breakpoint then check if the debug registers
    //  contain the expected values.
    status = SetThreadLocalHardwareBreakpoint(
        SHARED_BREAKPOINT_INDEX,
        GetCurrentThread(),
        THREADLOCAL_BREAKPOINT_ADDRESS,
        THREADLOCAL_BREAKPOINT_TYPE,
        THREADLOCAL_BREAKPOINT_SIZE);
    if (!status)
    {
        FAIL_TEST(
            "SetThreadLocalHardwareBreakpoint failed: %u\n",
            GetLastError());
    }

    status = VerifyThreadLocalBreakpointByIndex(
        SHARED_BREAKPOINT_INDEX,
        GetCurrentThread(),
        THREADLOCAL_BREAKPOINT_ADDRESS,
        THREADLOCAL_BREAKPOINT_TYPE,
        THREADLOCAL_BREAKPOINT_SIZE);
    if (!status)
    {
        FAIL_TEST(
            "VerifyThreadLocalBreakpointByIndex failed: %u\n",
            GetLastError());
    }

    // Install a real hardware breakpoint in the same debug address register
    //  with different parameters.
    status = VivienneIoSetHardwareBreakpoint(
        SHARED_BREAKPOINT_INDEX,
        GetCurrentProcessId(),
        VVMMGLOBAL_BREAKPOINT_ADDRESS,
        VVMMGLOBAL_BREAKPOINT_TYPE,
        VVMMGLOBAL_BREAKPOINT_SIZE);
    if (!status)
    {
        FAIL_TEST("VivienneIoSetHardwareBreakpoint failed: %u\n",
            GetLastError());
    }

    status = VerifyThreadLocalBreakpointByIndex(
        SHARED_BREAKPOINT_INDEX,
        GetCurrentThread(),
        THREADLOCAL_BREAKPOINT_ADDRESS,
        THREADLOCAL_BREAKPOINT_TYPE,
        THREADLOCAL_BREAKPOINT_SIZE);
    if (!status)
    {
        FAIL_TEST(
            "VerifyThreadLocalBreakpointByIndex failed: %u\n",
            GetLastError());
    }

    // Clear the thread-local breakpoint.
    status = ClearThreadLocalHardwareBreakpoint(
        SHARED_BREAKPOINT_INDEX,
        GetCurrentThread());
    if (!status)
    {
        FAIL_TEST(
            "ClearThreadLocalHardwareBreakpoint failed: %u\n",
            GetLastError());
    }

    // Verify that our VVMM-managed breakpoint is still hidden.
    status = BreakpointStealthCheck();
    if (!status)
    {
        FAIL_TEST("BreakpointStealthCheck failed.\n");
    }

    // Clear the VVMM-managed breakpoint.
    status = VivienneIoClearHardwareBreakpoint(SHARED_BREAKPOINT_INDEX);
    if (!status)
    {
        FAIL_TEST("VivienneIoClearHardwareBreakpoint failed: %u\n",
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

    PRINT_TEST_FOOTER;
}