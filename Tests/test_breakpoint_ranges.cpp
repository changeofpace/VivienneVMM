#include "tests.h"

#include <intrin.h>

#include <cstdio>

#include "test_util.h"

#include "..\common\debug.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define DEBUG_REGISTER_INDEX    2


//=============================================================================
// Types
//=============================================================================
typedef ULONGLONG ONE_QWORD;
typedef PULONGLONG PONE_QWORD;

static_assert(sizeof(ONE_QWORD) == sizeof(ULONGLONG), "Size check");

#pragma pack(push, 1)
typedef struct _FOUR_WORDS
{
    WORD A;
    WORD B;
    WORD C;
    WORD D;
} FOUR_WORDS, *PFOUR_WORDS;
#pragma pack(pop)

static_assert(sizeof(FOUR_WORDS) == sizeof(ULONGLONG), "Size check");


//=============================================================================
// Module Globals
//=============================================================================
static ONE_QWORD g_OneQword = {};
static FOUR_WORDS g_FourWords = {};


//=============================================================================
// Test Interface
//=============================================================================

//
// TestHardwareBreakpointRanges
//
// These tests ensure that the breakpoint manager correctly handles data
//  breakpoints with an access size not equal to the breakpoint size.
//
VOID
TestHardwareBreakpointRanges()
{
    PVOID pVectoredHandler = NULL;
    PONE_QWORD pOneQword = NULL;
    WORD Word = 0;
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

    //
    // In the graph below, we set an ACCESS, WORD breakpoint at address 4. We
    //  then access the range of bytes using a QWORD pointer. The breakpoint
    //  manager should handle and consume this condition because the breakpoint
    //  bytes are within the accessed bytes.
    //
    //    0 1 2 3 4 5 6 7 8 9 A B C D E F
    //   +-------------------------------+
    //   |x|x|x|x|x|x|x|x|x|x|x|x|x|x|x|x|  Access
    //   +-------------------------------+
    //   | | | | |x|x|x|x| | | | | | | | |  Breakpoint
    //   +-------------------------------+
    //
    status = VivienneIoSetHardwareBreakpoint(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)(&g_FourWords.B),
        HWBP_TYPE::Access,
        HWBP_SIZE::Word);
    if (!status)
    {
        FAIL_TEST(
            "VivienneIoSetHardwareBreakpoint (execute) failed: %u\n",
            GetLastError());
    }

    // Trigger the breakpoint.
    pOneQword = (PONE_QWORD)&g_FourWords;
    *pOneQword = 1;
    *pOneQword = 0xFFFF;
    *pOneQword = 0xFFFFFFFF;
    *pOneQword = 0xFFFFFFFFFFFF;
    *pOneQword = 0xFFFFFFFFFFFFFFFF;
    pOneQword = NULL;

    // Verify that the debug registers are empty.
    status = BreakpointStealthCheck();
    if (!status)
    {
        FAIL_TEST("BreakpointStealthCheck failed.\n");
    }

    // Clear the breakpoint.
    status = VivienneIoClearHardwareBreakpoint(DEBUG_REGISTER_INDEX);
    if (!status)
    {
        FAIL_TEST("VivienneIoClearHardwareBreakpoint failed: %u.\n",
            GetLastError());
    }

    //
    // Perform the inverse of the test above.
    //
    //    0 1 2 3 4 5 6 7 8 9 A B C D E F
    //   +-------------------------------+
    //   | | | | |x|x|x|x| | | | | | | | |  Access
    //   +-------------------------------+
    //   |x|x|x|x|x|x|x|x|x|x|x|x|x|x|x|x|  Breakpoint
    //   +-------------------------------+
    //
    status = VivienneIoSetHardwareBreakpoint(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)&g_FourWords,
        HWBP_TYPE::Access,
        HWBP_SIZE::Qword);
    if (!status)
    {
        FAIL_TEST(
            "VivienneIoSetHardwareBreakpoint (execute) failed: %u\n",
            GetLastError());
    }

    // Trigger the breakpoint.
    Word = g_FourWords.A;
    Word = g_FourWords.B;
    Word = g_FourWords.C;
    Word = g_FourWords.D;

    // Verify that the debug registers are empty.
    status = BreakpointStealthCheck();
    if (!status)
    {
        FAIL_TEST("BreakpointStealthCheck failed.\n");
    }

    // Clear the breakpoint.
    status = VivienneIoClearHardwareBreakpoint(DEBUG_REGISTER_INDEX);
    if (!status)
    {
        FAIL_TEST("VivienneIoClearHardwareBreakpoint failed: %u.\n",
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
