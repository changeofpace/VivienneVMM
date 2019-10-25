#include "tests.h"

#include <Psapi.h>

#include <cstdio>

#include "arbitrary_code.h"
#include "memory.h"
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
#define ADDRESS_EXPRESSION              "rcx+rax*8"
#define NUMBER_OF_THREADS               4
#define DEBUG_REGISTER_INDEX            0
#define CONTEXT_BUFFER_SIZE             (PAGE_SIZE)
#define REQUEST_DURATION_MS             (SECONDS_TO_MILLISECONDS(10))
#define WAIT_TIMEOUT_MS                 (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Types
//=============================================================================
typedef struct _TRAP_PAGE_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
    PVOID TrapPage;
} TRAP_PAGE_CONTEXT, *PTRAP_PAGE_CONTEXT;


//=============================================================================
// Trap Page Test Case
//=============================================================================

//
// ExecutionTargetAddress
//
// NOTE This test will fail if this function is inlined.
//
static
DECLSPEC_NOINLINE
VOID
ExecutionTargetAddress()
{
    MemoryFence();
}


//
// ExerciseTrapPageBreakpoint
//
_Check_return_
static
DWORD
WINAPI
ExerciseTrapPageBreakpoint(
    _In_ LPVOID lpParameter
)
{
    PTRAP_PAGE_CONTEXT pContext = (PTRAP_PAGE_CONTEXT)lpParameter;
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
        // Trigger the breakpoint.
        //
        ExecutionTargetAddress();
    }

    return status;
}


//
// InitializeTrapPageContext
//
_Check_return_
static
BOOL
InitializeTrapPageContext(
    _Out_ PTRAP_PAGE_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    PVOID pTrapPage = NULL;
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
    // Allocate a page which is not backed by physical pages until first
    //  access.
    //
    pTrapPage = VirtualAlloc(
        NULL,
        PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pTrapPage)
    {
        printf("VirtualAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Allocated the trap page: 0x%IX\n", (ULONG_PTR)pTrapPage);

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;
    pContext->TrapPage = pTrapPage;

exit:
    if (!status)
    {
        if (pTrapPage)
        {
            if (!VirtualFree(pTrapPage, 0, MEM_RELEASE))
            {
                printf("VirtualFree failed: %u\n", GetLastError());
            }
        }

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
// ReleaseTrapPageContext
//
_Check_return_
static
BOOL
ReleaseTrapPageContext(
    _In_ PTRAP_PAGE_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->TrapPage)
    {
        if (!VirtualFree(pContext->TrapPage, 0, MEM_RELEASE))
        {
            printf("VirtualFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

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
// ExecuteCecmRequestForTrapPage
//
// This test issues a CECM request for an effective address which has been
//  reserved and committed but not accessed.
//
// This test verifies that our CECM implementation is not vulnerable to
//  detection via a QueryWorkingSetEx anti-debug technique.
//
_Check_return_
static
BOOL
ExecuteCecmRequestForTrapPage()
{
    TRAP_PAGE_CONTEXT Context = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    CHAR szTrapPageAddress[STR_ADDRESS_SIZE] = {};
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    BOOL ValidAddress = FALSE;
    ULONG ReadValue = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    printf("Executing a CECM request targeting a trap page...\n");

    //
    // Initialize the exercise thread context.
    //
    status = InitializeTrapPageContext(&Context);
    if (!status)
    {
        printf(
            "InitializeTrapPageContext failed: %u\n",
            GetLastError());
        goto exit;
    }

    status = StrUnsignedLongLongToString(
        TRUE,
        (ULONG_PTR)Context.TrapPage,
        szTrapPageAddress,
        sizeof(szTrapPageAddress));
    if (!status)
    {
        printf("StrUnsignedLongLongToString failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Initialize the memory description for the request.
    //
    status = ParseMemoryDescriptionToken(
        szTrapPageAddress,
        MDT_BYTE,
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
    // Create the exercise threads.
    //
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        hThreads[i] = CreateThread(
            NULL,
            0,
            ExerciseTrapPageBreakpoint,
            &Context,
            0,
            &ThreadIds[i]);
        if (!hThreads[i])
        {
            printf("CreateThread failed: %u\n", GetLastError());
            status = FALSE;
            goto exit;
        }

        printf("    tid: %u (0x%X)\n", ThreadIds[i], ThreadIds[i]);
    }

    //
    // Verify that the trap page has not been accessed.
    //
    status = IsVirtualAddressValid(Context.TrapPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (ValidAddress)
    {
        printf("Trap page accessed by third party.\n");
        status = FALSE;
        goto exit;
    }

    //
    // Signal the exercise threads to enter the spinloop.
    //
    status = SetEvent(Context.BarrierEvent);
    if (!status)
    {
        printf("SetEvent failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Issue the synchronous CECM request.
    //
    status = VivienneIoCaptureMemoryValues(
        GetCurrentProcessId(),
        DEBUG_REGISTER_INDEX,
        (ULONG_PTR)ExecutionTargetAddress,
        HWBP_TYPE::Execute,
        HWBP_SIZE::Byte,
        &MemoryDescription,
        REQUEST_DURATION_MS,
        pValuesCtx,
        CONTEXT_BUFFER_SIZE);
    if (!status)
    {
        printf("VivienneIoCaptureMemoryValues failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Verify that the trap page is still invalid.
    //
    status = IsVirtualAddressValid(Context.TrapPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (ValidAddress)
    {
        printf("Trap page accessed by third party.\n");
        status = FALSE;
        goto exit;
    }

    //
    // Lazily signal that all threads should terminate.
    //
    Context.Active = FALSE;

    //
    // Wait for all threads to terminate.
    //
    waitstatus = WaitForMultipleObjects(
        ARRAYSIZE(hThreads),
        hThreads,
        TRUE,
        WAIT_TIMEOUT_MS);
    if (waitstatus < WAIT_OBJECT_0 || waitstatus >= ARRAYSIZE(hThreads))
    {
        printf("WaitForMultipleObjects failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the request yielded zero results.
    //
    if (pValuesCtx->NumberOfValues)
    {
        printf(
            "Unexpected number of returned values: %u\n",
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
    // Verify that accessing an address in the trap page causes that page to
    //  become valid.
    //
    ReadValue = *(PULONG)Context.TrapPage;

    status = IsVirtualAddressValid(Context.TrapPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (!ValidAddress)
    {
        printf("Trap page is invalid after post-test access.\n");
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
    for (ULONG i = 0; i < ARRAYSIZE(hThreads); ++i)
    {
        if (hThreads[i])
        {
#pragma warning(suppress : 6001) // Using uninitialized memory.
            if (!CloseHandle(hThreads[i]))
            {
                printf("CloseHandle failed: %u\n", GetLastError());
                status = FALSE;
            }
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

    if (!ReleaseTrapPageContext(&Context))
    {
        printf("ReleaseTrapPageContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestAntiDebugCecmTrapPage
//
// See: ExecuteCecmRequestForTrapPage
//
VOID
TestAntiDebugCecmTrapPage()
{
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = ExecuteCecmRequestForTrapPage();
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForTrapPage failed.\n");
    }

    PRINT_TEST_FOOTER;
}
