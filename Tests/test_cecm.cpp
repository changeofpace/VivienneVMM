#include "tests.h"

#include <cstdio>
#include <string>

#include "arbitrary_code.h"
#include "test_util.h"

#include "..\common\driver_io_types.h"
#include "..\common\time_util.h"

#include "..\VivienneCL\driver_io.h"
#include "..\VivienneCL\ntdll.h"
#include "..\VivienneCL\string_util.h"
#include "..\VivienneCL\token_parser.h"


//=============================================================================
// Constants
//=============================================================================
#define INDIRECT_ADDRESS_EXPRESSION     "rcx+rax*8"
#define INVALID_ADDRESS_EXPRESSION      "0x1234"
#define NUMBER_OF_UNIQUE_RANDOM_VALUES  20
#define DEBUG_REGISTER_INDEX            2
#define CONTEXT_BUFFER_SIZE             (PAGE_SIZE * 2)
#define REQUEST_DURATION_MS             (SECONDS_TO_MILLISECONDS(10))
#define WAIT_TIMEOUT_MS                 (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Types
//=============================================================================
typedef struct _ABSOLUTE_ADDRESS_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
    ULONG_PTR ReadTarget;
    ULONG_PTR WriteTarget;
    ULONG_PTR RandomValues[NUMBER_OF_UNIQUE_RANDOM_VALUES];
} ABSOLUTE_ADDRESS_CONTEXT, *PABSOLUTE_ADDRESS_CONTEXT;

typedef struct _INDIRECT_ADDRESS_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
    DOUBLE RandomValues[NUMBER_OF_UNIQUE_RANDOM_VALUES];
} INDIRECT_ADDRESS_CONTEXT, *PINDIRECT_ADDRESS_CONTEXT;

typedef struct _RESULTS_OVERFLOW_CONTEXT
{
    HANDLE BarrierEvent;
    SIZE_T Count;
    BOOLEAN Active;
} RESULTS_OVERFLOW_CONTEXT, *PRESULTS_OVERFLOW_CONTEXT;

typedef struct _INVALID_ADDRESS_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
} INVALID_ADDRESS_CONTEXT, *PINVALID_ADDRESS_CONTEXT;


//=============================================================================
// Absolute Address Test Case
//=============================================================================

#pragma region Absolute Address Test Case

//
// ExerciseCecmAbsoluteAddress
//
_Check_return_
static
DWORD
WINAPI
ExerciseCecmAbsoluteAddress(
    _In_ LPVOID lpParameter
)
{
    PABSOLUTE_ADDRESS_CONTEXT pContext =
        (PABSOLUTE_ADDRESS_CONTEXT)lpParameter;
    SIZE_T Index = 0;
    ULONG_PTR WriteValue = 0;
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    //
    // Wait until all threads have been created.
    //
    waitstatus = WaitForSingleObject(pContext->BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    while (pContext->Active)
    {
        //
        // Stealth check.
        //
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        //
        // Calcluate the current index.
        //
        Index = (Index + 1) % ARRAYSIZE(pContext->RandomValues);

        WriteValue = pContext->RandomValues[Index];

        //
        // Set the value of the read target for this iteration.
        //
        pContext->ReadTarget = WriteValue;

        //
        // Ensure that ReadTarget is updated before we trigger the breakpoint.
        //
        MemoryFence();

        //
        // Trigger the breakpoint associated with this CECM request.
        //
        pContext->WriteTarget = WriteValue;
    }

    return status;
}


//
// InitializeAbsoluteAddressContext
//
_Check_return_
static
BOOL
InitializeAbsoluteAddressContext(
    _Out_ PABSOLUTE_ADDRESS_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pContext, sizeof(*pContext));

    BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!BarrierEvent)
    {
        printf("CreateEvent failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;

    GenerateUniqueRandomValues(
        pContext->RandomValues,
        ARRAYSIZE(pContext->RandomValues));

exit:
    if (!status)
    {
        if (BarrierEvent)
        {
            if (!CloseHandle(BarrierEvent))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// ReleaseAbsoluteAddressContext
//
_Check_return_
static
BOOL
ReleaseAbsoluteAddressContext(
    _In_ PABSOLUTE_ADDRESS_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->BarrierEvent)
    {
        if (!CloseHandle(pContext->BarrierEvent))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}


//
// ExecuteCecmAbsoluteAddress
//
// Whenever Context.WriteTarget is written to, Context.ReadTarget is read by
//  the CECM callback.
//
_Check_return_
static
BOOL
ExecuteCecmAbsoluteAddress()
{
    ABSOLUTE_ADDRESS_CONTEXT Context = {};
    CHAR szReadTarget[STR_ADDRESS_SIZE] = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    PVOID pVectoredHandler = NULL;
    HANDLE hThread = NULL;
    DWORD ThreadId = 0;
    PMEMORY_DATA_VALUE pMemoryDataValue = NULL;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    printf("Executing an absolute address CECM request...\n");

    //
    // Initialize the exercise thread context.
    //
    status = InitializeAbsoluteAddressContext(&Context);
    if (!status)
    {
        printf(
            "InitializeAbsoluteAddressContext failed: %u\n",
            GetLastError());
        goto exit;
    }

    printf("Generated random values:\n");

    for (SIZE_T i = 0; i < ARRAYSIZE(Context.RandomValues); ++i)
    {
        printf(
            "    %5Iu:  0x%018IX  word = 0x%04hX\n",
            i,
            Context.RandomValues[i],
            (WORD)Context.RandomValues[i]);
    }

    status = StrUnsignedLongLongToString(
        TRUE,
        (ULONG_PTR)&Context.ReadTarget,
        szReadTarget,
        sizeof(szReadTarget));
    if (!status)
    {
        printf("StrUnsignedLongLongToString failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Initialize the memory description for the request.
    //
    status = ParseMemoryDescriptionToken(
        szReadTarget,
        MDT_WORD,
        &MemoryDescription);
    if (!status)
    {
        printf("ParseMemoryDescriptionToken failed: %u\n", GetLastError());
        goto exit;
    }

    if (MemoryDescription.IsIndirectAddress)
    {
        printf("Memory description parse error. (not virtual address)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Allocate the values context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Install the stealth check VEH.
    //
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        StealthCheckVectoredHandler);
    if (!pVectoredHandler)
    {
        printf("AddVectoredExceptionHandler failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Create the exercise thread.
    //
    hThread = CreateThread(
        NULL,
        0,
        ExerciseCecmAbsoluteAddress,
        &Context,
        0,
        &ThreadId);
    if (!hThread)
    {
        printf("CreateThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Exercise tid: %u (0x%X)\n", ThreadId, ThreadId);

    //
    // Signal the exercise thread to enter the spinloop.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    printf(
        "Issuing a CECM request for virtual address: 0x%IX\n",
        MemoryDescription.u.VirtualAddress);

    //
    // Issue the synchronous CECM request.
    //
    status = DrvCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)&Context.WriteTarget,
        HWBP_TYPE::Write,
        HWBP_SIZE::Byte,
        &MemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("DrvCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Signal the exercise thread to exit the spinloop.
    //
    Context.Active = FALSE;

    //
    // Wait for the exercise thread to terminate.
    //
    waitstatus = WaitForSingleObject(hThread, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Log the results.
    //
    printf("CECM request returned %u values:\n", pValuesCtx->NumberOfValues);

    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        pMemoryDataValue = (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];

        printf("    %5u:  0x%04hX\n", i, pMemoryDataValue->Word);
    }

    printf("Verifying results...\n");

    //
    // Verify that the returned list of values matches the random values in the
    //  thread context.
    //
    if (ARRAYSIZE(Context.RandomValues) != pValuesCtx->NumberOfValues)
    {
        printf(
            "Unexpected number of captured values: actual = %u, expected = %Iu\n",
            pValuesCtx->NumberOfValues,
            ARRAYSIZE(Context.RandomValues));
        status = FALSE;
        goto exit;
    }

    for (SIZE_T i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        PMEMORY_DATA_VALUE pValuesMdt =
            (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];
        BOOLEAN ValueFound = FALSE;

        for (SIZE_T j = 0; j < ARRAYSIZE(Context.RandomValues); ++j)
        {
            PMEMORY_DATA_VALUE pRandomMdt =
                (PMEMORY_DATA_VALUE)&Context.RandomValues[j];

            if (pRandomMdt->Word == pValuesMdt->Word)
            {
                //
                // Check for multiple matches.
                //
                if (ValueFound)
                {
                    printf("Duplicate value found.\n");
                    status = FALSE;
                    goto exit;
                }

                ValueFound = TRUE;
            }
        }

        //
        // Unmatched value.
        //
        if (!ValueFound)
        {
            printf("Unmatched value: %f.\n", pValuesMdt->Double);
            status = FALSE;
            goto exit;
        }
    }

    //
    // Verify that there were no validation errors.
    //
    if (pValuesCtx->Statistics.ValidationErrors)
    {
        printf(
            "Unexpected number of validation errors: %Iu\n",
            pValuesCtx->Statistics.ValidationErrors);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that all debug registers on all processors were cleared.
    //
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        printf("Failed to clear a hardware breakpoint.\n");
        goto exit;
    }

exit:
    if (hThread)
    {
        if (!CloseHandle(hThread))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (pVectoredHandler)
    {
        if (!RemoveVectoredExceptionHandler(pVectoredHandler))
        {
            printf(
                "RemoveVectoredExceptionHandler failed: %u\n",
                GetLastError());
            status = FALSE;
        }
    }

    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (!ReleaseAbsoluteAddressContext(&Context))
    {
        printf("ReleaseAbsoluteAddressContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}

#pragma endregion Absolute Address Test Case


//=============================================================================
// Indirect Address Test Case
//=============================================================================

#pragma region Indirect Address Test Case

//
// ExerciseCecmIndirectAddress
//
static
DWORD
WINAPI
ExerciseCecmIndirectAddress(
    _In_ LPVOID lpParameter
)
{
    PINDIRECT_ADDRESS_CONTEXT pContext =
        (PINDIRECT_ADDRESS_CONTEXT)lpParameter;
    SIZE_T Index = 0;
    DOUBLE ReturnValue = 0;
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    waitstatus = WaitForSingleObject(pContext->BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    while (pContext->Active)
    {
        //
        // Stealth check.
        //
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        //
        // Calculate the effective index.
        //
        Index = (Index + 1) % ARRAYSIZE(pContext->RandomValues);

        //
        // Trigger the breakpoint.
        //
        ReturnValue = AcCaptureMemoryDouble(
            pContext->RandomValues,
            ARRAYSIZE(pContext->RandomValues),
            Index);
    }

    return status;
}


//
// InitializeIndirectAddressContext
//
_Check_return_
static
BOOL
InitializeIndirectAddressContext(
    _Out_ PINDIRECT_ADDRESS_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pContext, sizeof(*pContext));

    BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!BarrierEvent)
    {
        printf("CreateEvent failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Manually generate double values.
    //
    for (SIZE_T i = 0; i < ARRAYSIZE(pContext->RandomValues); ++i)
    {
        if (0 == i)
        {
            pContext->RandomValues[i] = 18513.382368293f;
            continue;
        }

        pContext->RandomValues[i] = pContext->RandomValues[i - 1] * 3.328;
    }

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;

exit:
    if (!status)
    {
        if (BarrierEvent)
        {
            if (!CloseHandle(BarrierEvent))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// ReleaseIndirectAddressContext
//
_Check_return_
static
BOOL
ReleaseIndirectAddressContext(
    _In_ PINDIRECT_ADDRESS_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->BarrierEvent)
    {
        if (!CloseHandle(pContext->BarrierEvent))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}


//
// ExecuteCecmIndirectAddress
//
// This test captures unique double values from an SSE instruction.
//
_Check_return_
static
BOOL
ExecuteCecmIndirectAddress()
{
    INDIRECT_ADDRESS_CONTEXT Context = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    PVOID pVectoredHandler = NULL;
    HANDLE hThread = NULL;
    DWORD ThreadId = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    printf("Executing an indirect address CECM request...\n");

    //
    // Initialize the exercise thread context.
    //
    status = InitializeIndirectAddressContext(&Context);
    if (!status)
    {
        printf(
            "InitializeIndirectAddressContext failed: %u\n",
            GetLastError());
        goto exit;
    }

    printf("Generated random values:\n");

    for (SIZE_T i = 0; i < ARRAYSIZE(Context.RandomValues); ++i)
    {
        printf("    %5Iu:  %f\n", i, Context.RandomValues[i]);
    }

    //
    // Initialize the memory description for the request.
    //
    status = ParseMemoryDescriptionToken(
        INDIRECT_ADDRESS_EXPRESSION,
        MDT_DOUBLE,
        &MemoryDescription);
    if (!status)
    {
        printf("ParseMemoryDescriptionToken failed: %u\n", GetLastError());
        goto exit;
    }

    if (!MemoryDescription.IsIndirectAddress)
    {
        printf("Memory description parse error. (not indirect address)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Allocate the values context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Install the stealth check VEH.
    //
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        StealthCheckVectoredHandler);
    if (!pVectoredHandler)
    {
        printf("AddVectoredExceptionHandler failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Create the exercise thread.
    //
    hThread = CreateThread(
        NULL,
        0,
        ExerciseCecmIndirectAddress,
        &Context,
        0,
        &ThreadId);
    if (!hThread)
    {
        printf("CreateThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Exercise tid: %u (0x%X)\n", ThreadId, ThreadId);

    //
    // Signal the exercise thread to enter the spinloop.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    printf(
        "Issuing a CECM request for indirect address: %s\n",
        INDIRECT_ADDRESS_EXPRESSION);

    //
    // Issue the synchronous CECM request.
    //
    status = DrvCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)&g_AcCecrDoubleCaptureAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        &MemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("DrvCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Signal the exercise thread to exit the spinloop.
    //
    Context.Active = FALSE;

    //
    // Wait for the exercise thread to terminate.
    //
    waitstatus = WaitForSingleObject(hThread, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Log the results.
    //
    printf("CECM request returned %u values:\n", pValuesCtx->NumberOfValues);

    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        PMEMORY_DATA_VALUE pMemoryDataValue =
            (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];

        printf("    %5u:  %f\n", i, pMemoryDataValue->Double);
    }

    printf("Verifying results...\n");

    //
    // Verify that the returned list of values matches the random values in the
    //  thread context.
    //
    if (ARRAYSIZE(Context.RandomValues) != pValuesCtx->NumberOfValues)
    {
        printf(
            "Unexpected number of captured values: actual = %u, expected = %Iu\n",
            pValuesCtx->NumberOfValues,
            ARRAYSIZE(Context.RandomValues));
        status = FALSE;
        goto exit;
    }

    for (SIZE_T i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        PMEMORY_DATA_VALUE pMemoryDataValue =
            (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];
        BOOLEAN ValueFound = FALSE;

        for (SIZE_T j = 0; j < ARRAYSIZE(Context.RandomValues); ++j)
        {
            if (Context.RandomValues[j] == pMemoryDataValue->Double)
            {
                //
                // Check for multiple matches.
                //
                if (ValueFound)
                {
                    printf("Duplicate value found.\n");
                    status = FALSE;
                    goto exit;
                }

                ValueFound = TRUE;
            }
        }

        //
        // Unmatched value.
        //
        if (!ValueFound)
        {
            printf("Unmatched value: %f.\n", pMemoryDataValue->Double);
            status = FALSE;
            goto exit;
        }
    }

    //
    // Verify that there were no validation errors.
    //
    if (pValuesCtx->Statistics.ValidationErrors)
    {
        printf(
            "Unexpected number of validation errors: %Iu\n",
            pValuesCtx->Statistics.ValidationErrors);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that all debug registers on all processors were cleared.
    //
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        printf("Failed to clear a hardware breakpoint.\n");
        goto exit;
    }

exit:
    if (hThread)
    {
        if (!CloseHandle(hThread))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (pVectoredHandler)
    {
        if (!RemoveVectoredExceptionHandler(pVectoredHandler))
        {
            printf(
                "RemoveVectoredExceptionHandler failed: %u\n",
                GetLastError());
            status = FALSE;
        }
    }

    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (!ReleaseIndirectAddressContext(&Context))
    {
        printf("ReleaseIndirectAddressContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}

#pragma endregion Indirect Address Test Case


//=============================================================================
// Results Overflow Test Case
//=============================================================================

#pragma region Results Overflow Test Case

//
// ResultsOverflowExecutionTargetAddress
//
// NOTE This test will fail if this function is inlined.
//
static
DECLSPEC_NOINLINE
VOID
ResultsOverflowExecutionTargetAddress()
{
    MemoryFence();
}


//
// ExerciseCecmResultsOverflow
//
static
DWORD
WINAPI
ExerciseCecmResultsOverflow(
    _In_ LPVOID lpParameter
)
{
    PRESULTS_OVERFLOW_CONTEXT pContext =
        (PRESULTS_OVERFLOW_CONTEXT)lpParameter;
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    waitstatus = WaitForSingleObject(pContext->BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    //
    // Set the starting count value to 1 so our skip count is consistent.
    //
    pContext->Count = 1;

    while (pContext->Active)
    {
        //
        // Stealth check.
        //
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        //
        // Trigger the breakpoint.
        //
        ResultsOverflowExecutionTargetAddress();

        //
        // Increment the count variable so that it is unique for the next
        //  trigger.
        //
        pContext->Count++;
    }

    return status;
}


//
// InitializeResultsOverflowContext
//
_Check_return_
static
BOOL
InitializeResultsOverflowContext(
    _Out_ PRESULTS_OVERFLOW_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pContext, sizeof(*pContext));

    BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!BarrierEvent)
    {
        printf("CreateEvent failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;

exit:
    if (!status)
    {
        if (BarrierEvent)
        {
            if (!CloseHandle(BarrierEvent))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// ReleaseResultsOverflowContext
//
_Check_return_
static
BOOL
ReleaseResultsOverflowContext(
    _In_ PRESULTS_OVERFLOW_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->BarrierEvent)
    {
        if (!CloseHandle(pContext->BarrierEvent))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}


//
// ExecuteCecmResultsOverflow
//
// This test uses an effective address which yields a number of unique results
//  larger than the provided values buffer can support.
//
_Check_return_
static
BOOL
ExecuteCecmResultsOverflow()
{
    RESULTS_OVERFLOW_CONTEXT Context = {};
    CHAR szReadTarget[STR_ADDRESS_SIZE] = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    PVOID pVectoredHandler = NULL;
    HANDLE hThread = NULL;
    DWORD ThreadId = 0;
    ULONG ExpectedNumberOfResults = 0;
    SIZE_T ExpectedSkipCount = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    printf("Executing an overflowing CECM request...\n");

    //
    // Initialize the exercise thread context.
    //
    status = InitializeResultsOverflowContext(&Context);
    if (!status)
    {
        printf(
            "InitializeResultsOverflowContext failed: %u\n",
            GetLastError());
        goto exit;
    }

    status = StrUnsignedLongLongToString(
        TRUE,
        (ULONG_PTR)&Context.Count,
        szReadTarget,
        sizeof(szReadTarget));
    if (!status)
    {
        printf("StrUnsignedLongLongToString failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Initialize the memory description for the request.
    //
    status = ParseMemoryDescriptionToken(
        szReadTarget,
        MDT_QWORD,
        &MemoryDescription);
    if (!status)
    {
        printf("ParseMemoryDescriptionToken failed: %u\n", GetLastError());
        goto exit;
    }

    if (MemoryDescription.IsIndirectAddress)
    {
        printf("Memory description parse error. (not virtual address)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Allocate the values context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Install the stealth check VEH.
    //
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        StealthCheckVectoredHandler);
    if (!pVectoredHandler)
    {
        printf("AddVectoredExceptionHandler failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Create the exercise thread.
    //
    hThread = CreateThread(
        NULL,
        0,
        ExerciseCecmResultsOverflow,
        &Context,
        0,
        &ThreadId);
    if (!hThread)
    {
        printf("CreateThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Exercise tid: %u (0x%X)\n", ThreadId, ThreadId);

    //
    // Signal the exercise thread to enter the spinloop.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    printf(
        "Issuing a CECM request for virtual address: 0x%IX\n",
        MemoryDescription.u.VirtualAddress);

    //
    // Issue the synchronous CECM request.
    //
    status = DrvCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)ResultsOverflowExecutionTargetAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        &MemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("DrvCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Signal the exercise thread to exit the spinloop.
    //
    Context.Active = FALSE;

    //
    // Wait for the exercise thread to terminate.
    //
    waitstatus = WaitForSingleObject(hThread, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Verify that we filled the values buffer.
    //
    if (pValuesCtx->NumberOfValues != pValuesCtx->MaxIndex)
    {
        printf("Unexpected number of returned values:\n");
        printf("    MaxIndex:       %u\n",
            pValuesCtx->MaxIndex);
        printf("    NumberOfValues: %u\n",
            pValuesCtx->NumberOfValues);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the skip count and returned number of values reflect their
    //  expected values.
    //
    ExpectedNumberOfResults =
        (CONTEXT_BUFFER_SIZE - FIELD_OFFSET(CEC_MEMORY_VALUES, Values))
            / (RTL_FIELD_SIZE(CEC_MEMORY_VALUES, Values));

    if (ExpectedNumberOfResults != pValuesCtx->NumberOfValues)
    {
        printf("Unexpected number of returned values:\n");
        printf("    ExpectedNumberOfResults: %u\n", ExpectedNumberOfResults);
        printf("    NumberOfValues:          %u\n",
            pValuesCtx->NumberOfValues);
        status = FALSE;
        goto exit;
    }

    ExpectedSkipCount =
        pValuesCtx->Statistics.HitCount - pValuesCtx->NumberOfValues;

    if (ExpectedSkipCount != pValuesCtx->Statistics.SkipCount)
    {
        printf("Unexpected skip count:\n");
        printf("    ExpectedSkipCount:  %Iu\n", ExpectedSkipCount);
        printf("    SkipCount:          %Iu\n",
            pValuesCtx->Statistics.SkipCount);
        printf("    HitCount:           %Iu\n",
            pValuesCtx->Statistics.HitCount);
        printf("    NumberOfValues:     %u\n",
            pValuesCtx->NumberOfValues);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that there were no validation errors.
    //
    if (pValuesCtx->Statistics.ValidationErrors)
    {
        printf(
            "Unexpected number of validation errors: %Iu\n",
            pValuesCtx->Statistics.ValidationErrors);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that all debug registers on all processors were cleared.
    //
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        printf("Failed to clear a hardware breakpoint.\n");
        goto exit;
    }

exit:
    if (hThread)
    {
        if (!CloseHandle(hThread))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (pVectoredHandler)
    {
        if (!RemoveVectoredExceptionHandler(pVectoredHandler))
        {
            printf(
                "RemoveVectoredExceptionHandler failed: %u\n",
                GetLastError());
            status = FALSE;
        }
    }

    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (!ReleaseResultsOverflowContext(&Context))
    {
        printf("ReleaseResultsOverflowContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}

#pragma endregion Results Overflow Test Case


//=============================================================================
// Invalid Address Test Case
//=============================================================================

#pragma region Invalid Address Test Case

//
// InvalidAddressExecutionTargetAddress
//
// NOTE This test will fail if this function is inlined.
//
static
DECLSPEC_NOINLINE
VOID
InvalidAddressExecutionTargetAddress()
{
    MemoryFence();
}


//
// ExerciseCecmInvalidAddress
//
static
DWORD
WINAPI
ExerciseCecmInvalidAddress(
    _In_ LPVOID lpParameter
)
{
    PINVALID_ADDRESS_CONTEXT pContext =
        (PINVALID_ADDRESS_CONTEXT)lpParameter;
    DWORD waitstatus = 0;
    DWORD status = ERROR_SUCCESS;

    waitstatus = WaitForSingleObject(pContext->BarrierEvent, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    while (pContext->Active)
    {
        //
        // Stealth check.
        //
        if (!BreakpointStealthCheck())
        {
            FAIL_TEST("BreakpointStealthCheck failed.\n");
        }

        //
        // Trigger the breakpoint.
        //
        InvalidAddressExecutionTargetAddress();
    }

    return status;
}


//
// InitializeInvalidAddressContext
//
_Check_return_
static
BOOL
InitializeInvalidAddressContext(
    _Out_ PINVALID_ADDRESS_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pContext, sizeof(*pContext));

    BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!BarrierEvent)
    {
        printf("CreateEvent failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;

exit:
    if (!status)
    {
        if (BarrierEvent)
        {
            if (!CloseHandle(BarrierEvent))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}


//
// ReleaseInvalidAddressContext
//
_Check_return_
static
BOOL
ReleaseInvalidAddressContext(
    _In_ PINVALID_ADDRESS_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->BarrierEvent)
    {
        if (!CloseHandle(pContext->BarrierEvent))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}


//
// ExecuteCecmInvalidAddress
//
// This test issues a CECM request for an invalid address.
//
_Check_return_
static
BOOL
ExecuteCecmInvalidAddress()
{
    INVALID_ADDRESS_CONTEXT Context = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    PVOID pVectoredHandler = NULL;
    HANDLE hThread = NULL;
    DWORD ThreadId = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    printf("Executing an invalid address CECM request...\n");

    //
    // Initialize the exercise thread context.
    //
    status = InitializeInvalidAddressContext(&Context);
    if (!status)
    {
        printf("InitializeInvalidAddressContext failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Initialize the memory description for the request.
    //
    status = ParseMemoryDescriptionToken(
        INVALID_ADDRESS_EXPRESSION,
        MDT_QWORD,
        &MemoryDescription);
    if (!status)
    {
        printf("ParseMemoryDescriptionToken failed: %u\n", GetLastError());
        goto exit;
    }

    if (MemoryDescription.IsIndirectAddress)
    {
        printf("Memory description parse error. (not virtual address)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Allocate the values context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CONTEXT_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Install the stealth check VEH.
    //
    pVectoredHandler = AddVectoredExceptionHandler(
        1,
        StealthCheckVectoredHandler);
    if (!pVectoredHandler)
    {
        printf("AddVectoredExceptionHandler failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Create the exercise thread.
    //
    hThread = CreateThread(
        NULL,
        0,
        ExerciseCecmInvalidAddress,
        &Context,
        0,
        &ThreadId);
    if (!hThread)
    {
        printf("CreateThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Exercise tid: %u (0x%X)\n", ThreadId, ThreadId);

    //
    // Signal the exercise thread to enter the spinloop.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    printf(
        "Issuing a CECM request for an invalid address: %s\n",
        INVALID_ADDRESS_EXPRESSION);

    //
    // Issue the synchronous CECM request.
    //
    status = DrvCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)InvalidAddressExecutionTargetAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        &MemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("DrvCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Signal the exercise thread to exit the spinloop.
    //
    Context.Active = FALSE;

    //
    // Wait for the exercise thread to terminate.
    //
    waitstatus = WaitForSingleObject(hThread, WAIT_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Verify that we received no results.
    //
    if (pValuesCtx->NumberOfValues)
    {
        printf("Unexpected number of returned values: %u\n",
            pValuesCtx->NumberOfValues);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the number of invalid pte errors equals the hit count.
    //
    if (pValuesCtx->Statistics.InvalidPteErrors !=
        pValuesCtx->Statistics.HitCount)
    {
        printf("Unexpected number of invalid pte errors:\n");
        printf("    InvalidPteErrors:   %Iu\n",
            pValuesCtx->Statistics.InvalidPteErrors);
        printf("    HitCount:           %Iu\n",
            pValuesCtx->Statistics.HitCount);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that there were no validation errors.
    //
    if (pValuesCtx->Statistics.ValidationErrors)
    {
        printf(
            "Unexpected number of validation errors: %Iu\n",
            pValuesCtx->Statistics.ValidationErrors);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that all debug registers on all processors were cleared.
    //
    status = AreAllHardwareBreakpointsCleared();
    if (!status)
    {
        printf("Failed to clear a hardware breakpoint.\n");
        goto exit;
    }

exit:
    if (hThread)
    {
        if (!CloseHandle(hThread))
        {
            printf("CloseHandle failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (pVectoredHandler)
    {
        if (!RemoveVectoredExceptionHandler(pVectoredHandler))
        {
            printf(
                "RemoveVectoredExceptionHandler failed: %u\n",
                GetLastError());
            status = FALSE;
        }
    }

    if (pValuesCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pValuesCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (!ReleaseInvalidAddressContext(&Context))
    {
        printf("ReleaseInvalidAddressContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}

#pragma endregion Invalid Address Test Case


//=============================================================================
// Test Interface
//=============================================================================

//
// TestCaptureMemoryValues
//
VOID
TestCaptureMemoryValues()
{
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = ExecuteCecmAbsoluteAddress();
    if (!status)
    {
        FAIL_TEST("ExecuteCecmAbsoluteAddress failed.\n");
    }

    status = ExecuteCecmIndirectAddress();
    if (!status)
    {
        FAIL_TEST("ExecuteCecmIndirectAddress failed.\n");
    }

    status = ExecuteCecmResultsOverflow();
    if (!status)
    {
        FAIL_TEST("ExecuteCecmResultsOverflow failed.\n");
    }

    status = ExecuteCecmInvalidAddress();
    if (!status)
    {
        FAIL_TEST("ExecuteCecmInvalidAddress failed.\n");
    }

    PRINT_TEST_FOOTER;
}
