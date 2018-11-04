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
#define WINDBG_PROMPT "Execute the following command if WinDbg is attached:\n"
#define WINDBG_PRE_TEST_COMMAND     "sxd ii; sxd sse; sxd ssec;"
#define WINDBG_POST_TEST_COMMAND    "sxr;"
#define NUMBER_OF_ITERATIONS        1000
#define INSN_SIZE_UD2               2


//=============================================================================
// Module Globals
//=============================================================================
static volatile LONG g_SingleStepCount = 0;


//=============================================================================
// Internal Interface
//=============================================================================

//
// VectoredHandler
//
// We must use a VEH instead of a filter to properly catch both exceptions.
//
static
LONG
CALLBACK
VectoredHandler(
    PEXCEPTION_POINTERS pExceptionInfo
)
{
    DWORD ExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
    PRFLAGS pRflags = (PRFLAGS)&pExceptionInfo->ContextRecord->EFlags;

    if (STATUS_ILLEGAL_INSTRUCTION == ExceptionCode)
    {
        // Set the trap flag which will cause a single-step exception when this
        //  handler returns.
        pRflags->TF = 1;

        // Adjust the IP to skip the ud2 instruction.
        pExceptionInfo->ContextRecord->Rip += INSN_SIZE_UD2;
    }
    else if (STATUS_SINGLE_STEP == ExceptionCode)
    {
        InterlockedIncrement(&g_SingleStepCount);

        // Resume execution.
        pRflags->RF = 1;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestAntiDebugSingleStep
//
// This test invokes a vectored exception handler which then sets the trap flag
//  in the exception context.
//
// NOTE To run this test when WinDbg is attached as a kernel debugger, you
//  must execute the following command to pass illegal-instruction and
//   single-step exceptions exceptions:
//
//      sxd ii; sxd sse; sxd ssec;
//
// The command to revert the changes caused by the above command:
//
//      sxr;
//
VOID
TestAntiDebugSingleStep()
{
    PVOID pVectoredHandler = NULL;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    // Break if WinDbg is attached so we can execute the required command.
    PromptDebuggerExceptionConfiguration(
        WINDBG_PROMPT,
        WINDBG_PRE_TEST_COMMAND);

    printf("Starting anti-debug single-step test...\n");

    // Install the VEH for this test.
    pVectoredHandler = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!pVectoredHandler)
    {
        FAIL_TEST(
            "AddVectoredExceptionHandler failed: %u\n",
            GetLastError());
    }

    // Exercise the VEH.
    for (ULONG i = 0; i < NUMBER_OF_ITERATIONS; ++i)
    {
        __ud2();
    }

    // Verify that our handler caught the expected number of single-step
    //  exceptions.
    if (NUMBER_OF_ITERATIONS != g_SingleStepCount)
    {
        FAIL_TEST(
            "Unexpected number of single-steps: actual = %d, expected = %d\n",
            g_SingleStepCount,
            NUMBER_OF_ITERATIONS);
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
