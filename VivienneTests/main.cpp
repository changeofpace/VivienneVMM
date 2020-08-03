#include <Windows.h>

#include <intrin.h>
#include <stdio.h>

#include "tests.h"
#include "test_util.h"

#include "..\common\config.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\debug.h"
#include "..\VivienneCL\driver_io.h"
#include "..\VivienneCL\log.h"

#include "..\VivienneCL\ntdll.h"


#define DEBUG_BREAK_DELAY_SECONDS 5

BOOL
DebugBreakForExceptionConfiguration()
{
    BOOL fDebuggerAttached = FALSE;
    BOOL status = TRUE;

    fDebuggerAttached = IsDebuggerPresent();
    if (!fDebuggerAttached)
    {
        status = IsKernelDebuggerAttached(&fDebuggerAttached);
        if (!status)
        {
            goto exit;
        }
    }

    if (fDebuggerAttached)
    {
        INF_PRINT("Debugger detected.");
        INF_PRINT(
            "If WinDbg is attached then execute the following commands so that"
            " single-step exceptions are handled correctly:");
        INF_PRINT("");
        INF_PRINT("    sxi sse; sxi ssec;");
        INF_PRINT("");
        INF_PRINT("Breaking into debugger in %u seconds...",
            DEBUG_BREAK_DELAY_SECONDS);
        
        fflush(stdout);

        Sleep(SECONDS_TO_MILLISECONDS(DEBUG_BREAK_DELAY_SECONDS));

        __debugbreak();
    }

exit:
    return status;
}


#define TEST_DELAY_DURATION_MS (SECONDS_TO_MILLISECONDS(3))


//
// We insert a delay between each test to allow the driver log buffer to flush.
//
_Check_return_
static
int
RunAllTests()
{
    INF_PRINT("Running tests...\n\n");

    //
    // Parser test cases.
    //
    TestTokenParser();
    Sleep(TEST_DELAY_DURATION_MS);

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    //
    // EBM test cases.
    //
    TestEptBreakpointManager();
    Sleep(TEST_DELAY_DURATION_MS);
#endif

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
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

#if defined(CFG_HBM_ENABLE_DEBUG_REGISTER_FACADE)
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
#endif

    //
    // General anti-debug test cases.
    //
    TestAntiDebugSingleStep();
    Sleep(TEST_DELAY_DURATION_MS);

    return EXIT_SUCCESS;
}


VOID
static
__cdecl
ProcessTerminationHandler()
{
    VivienneIoTermination();
}


int
main(
    _In_ int argc,
    _In_ char* argv[]
)
{
    int mainstatus = EXIT_SUCCESS;

    if (!LogInitialization(LOG_CONFIG_STDOUT))
    {
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    if (!VivienneIoInitialization())
    {
        ERR_PRINT("VivienneIoInitialization failed: %u\n", GetLastError());
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    if (!InitializeRngSeed())
    {
        ERR_PRINT("TuInitializeRngSeed failed: %u\n", GetLastError());
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    if (!TiInitialization())
    {
        ERR_PRINT("TiInitialization failed: %u\n", GetLastError());
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    //
    // Register a termination handler for cleanup.
    //
    if (atexit(ProcessTerminationHandler))
    {
        ERR_PRINT("atexit failed.\n");
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    (VOID)DebugBreakForExceptionConfiguration();

    mainstatus = RunAllTests();
    if (EXIT_FAILURE == mainstatus)
    {
        ERR_PRINT("RunAllTests failed.\n");
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    INF_PRINT("All tests passed.\n");

exit:
    return mainstatus;
}
