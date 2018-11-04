#include "tests.h"

#include <cstdio>

#include "arbitrary_code.h"
#include "test_util.h"

#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"


//=============================================================================
// Constants
//=============================================================================
#define DEBUG_REGISTER_INDEX    3
#define CONTEXT_BUFFER_SIZE     (PAGE_SIZE)

// This duration must be long enough so that we can fill a context buffer with
//  unique values.
#define REQUEST_DURATION_MS     (SECONDS_TO_MILLISECONDS(10))
#define WAIT_TIMEOUT_MS         (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Module Globals
//=============================================================================
static BOOLEAN g_Active = FALSE;


//=============================================================================
// Internal Interface
//=============================================================================

//
// MaxResultsCecrRequest
//
static
DWORD
WINAPI
MaxResultsCecrRequest(
    _In_ LPVOID lpParameter
)
{
    ULONG_PTR Value = 0;
    DWORD status = ERROR_SUCCESS;

    while (g_Active)
    {
        Value++;
        AcCaptureRegister(Value);
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestCaptureRegisterValuesEdgeCases
//
// This test executes two CECR requests to test boundary checking.
//
VOID
TestCaptureRegisterValuesEdgeCases()
{
    PCEC_REGISTER_VALUES pValuesCtx = NULL;
    DWORD ThreadId = 0;
    HANDLE hThread = NULL;
    DWORD waitstatus = 0;
    BOOL status = FALSE;

    PRINT_TEST_HEADER;

    // Allocate the captured context buffer.
    // NOTE This memory will leak if this test fails.
    pValuesCtx = (PCEC_REGISTER_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        FAIL_TEST("HeapAlloc failed: %u\n", GetLastError());
    }

    printf("Starting zero results edge case...\n");

    // Edge Case: Zero results because the breakpoint was not triggered.
    status = DrvCaptureRegisterValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        0,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        REGISTER_R12,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        FAIL_TEST(
            "DrvCaptureRegisterValues failed: %u\n",
            GetLastError());
    }

    if (pValuesCtx->NumberOfValues)
    {
        FAIL_TEST(
            "Unexpected number of values: %u\n",
            pValuesCtx->NumberOfValues);
    }

    // Reset the context for the next edge case.
    RtlSecureZeroMemory(pValuesCtx, CONTEXT_BUFFER_SIZE);

    printf("Starting max results edge case...\n");

    // Reset our event flag so that the thread exercises the breakpoint.
    g_Active = TRUE;

    // Create a thread to flood the target register with unique values.
    hThread = CreateThread(
        NULL,
        0,
        MaxResultsCecrRequest,
        NULL,
        0,
        &ThreadId);
    if (!hThread)
    {
        FAIL_TEST("CreateThread failed: %u\n", GetLastError());
    }

    // Edge Case: The values-buffer is full.
    status = DrvCaptureRegisterValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)&g_AcCecrCaptureAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        REGISTER_R12,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        FAIL_TEST(
            "DrvCaptureRegisterValues failed: %u\n",
            GetLastError());
    }

    // Lazily signal that the exercise thread should terminate.
    g_Active = FALSE;

    // Wait for the second thread to terminate.
    waitstatus = WaitForSingleObject(hThread, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForMultipleObjects failed: %u\n", GetLastError());
    }

    // Close thread handle.
    status = CloseHandle(hThread);
    if (!status)
    {
        FAIL_TEST("CloseHandle failed: %u\n", GetLastError());
    }

    // Verify that all debug registers on all processors were cleared.
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        FAIL_TEST("Failed to clear a hardware breakpoint.\n");
    }

    // Check the results.
    if (pValuesCtx->NumberOfValues != pValuesCtx->MaxIndex)
    {
        FAIL_TEST(
            "Captured number of values (%u) not equal to max index (%u).\n",
            pValuesCtx->NumberOfValues,
            pValuesCtx->MaxIndex);
    }

    // Verify that all values are unique.
    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        for (ULONG j = 0; j < pValuesCtx->NumberOfValues; ++j)
        {
            if (i == j)
            {
                continue;
            }

            if (pValuesCtx->Values[i] == pValuesCtx->Values[j])
            {
                FAIL_TEST("Duplicate values at indices %u and %u\n", i, j);
            }
        }
    }

    // Release context.
    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            FAIL_TEST("HeapFree failed: %u\n", GetLastError());
        }
    }

    PRINT_TEST_FOOTER;
}