#include <Windows.h>

#include <cstdio>

#include "tests.h"
#include "test_util.h"

#include "..\common\debug.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"

#include "..\VivienneVMM\config.h"


#define TEST_SUCCESS 0
#define TEST_FAILURE 1

#define TEST_DELAY_DURATION_MS (SECONDS_TO_MILLISECONDS(3))


//
// RunAllTests
//
// We insert a delay between each test to allow the driver log buffer to flush.
//
_Check_return_
static
int
RunAllTests()
{
    printf("Running all tests...\n\n");

    //
    // Convenience break into the debugger.
    //
    DEBUGBREAK;

    //
    // Parser test cases.
    //
    TestTokenParser();
    Sleep(TEST_DELAY_DURATION_MS);

    //
    // BPM test cases.
    //
    TestReadDebugRegister();
    Sleep(TEST_DELAY_DURATION_MS);

    TestSetClearHardwareBreakpoint();
    Sleep(TEST_DELAY_DURATION_MS);

    TestHardwareBreakpointStress();
    Sleep(TEST_DELAY_DURATION_MS);

    TestHardwareBreakpointRanges();
    Sleep(TEST_DELAY_DURATION_MS);

    TestDuplicateHardwareBreakpoints();
    Sleep(TEST_DELAY_DURATION_MS);

    //
    // CECR test cases.
    //
    TestCaptureRegisterValues();
    Sleep(TEST_DELAY_DURATION_MS);

    TestCaptureRegisterValuesEdgeCases();
    Sleep(TEST_DELAY_DURATION_MS);

    //
    // CECM test cases.
    //
    TestCaptureMemoryValues();
    Sleep(TEST_DELAY_DURATION_MS);

    TestCaptureMemoryValuesFpuState();
    Sleep(TEST_DELAY_DURATION_MS);

    TestAntiDebugCecmTrapPage();
    Sleep(TEST_DELAY_DURATION_MS);

    TestAntiDebugCecmSpanningPage();
    Sleep(TEST_DELAY_DURATION_MS);

#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
    //
    // FCD test cases.
    //
    TestDebugRegisterFacade();
    Sleep(TEST_DELAY_DURATION_MS);

    TestDebugRegisterFacadeStress();
    Sleep(TEST_DELAY_DURATION_MS);
#else
    TestProcessUnownedHardwareBreakpoint();
    Sleep(TEST_DELAY_DURATION_MS);
#endif

    //
    // General anti-debug test cases.
    //
    TestAntiDebugSingleStep();
    Sleep(TEST_DELAY_DURATION_MS);

    return TEST_SUCCESS;
}


//
// ProcessTerminationHandler
//
VOID
static
__cdecl
ProcessTerminationHandler()
{
    (VOID)DrvTermination();
}


//
// main
//
int
main(
    _In_ int argc,
    _In_ char* argv[]
)
{
    int mainstatus = TEST_FAILURE;

    if (!DrvInitialization())
    {
        printf("DrvInitialization failed: %u\n", GetLastError());
        goto exit;
    }

    if (!InitializeRngSeed())
    {
        printf("TuInitializeRngSeed failed: %u\n", GetLastError());
        goto exit;
    }

    if (!TiInitialization())
    {
        printf("TiInitialization failed: %u\n", GetLastError());
        goto exit;
    }

    // Register a termination handler for cleanup.
    if (atexit(ProcessTerminationHandler))
    {
        printf("atexit failed.\n");
        goto exit;
    }

    mainstatus = RunAllTests();
    if (TEST_SUCCESS == mainstatus)
    {
        printf("All tests passed.\n");
    }

exit:
    return mainstatus;
}
