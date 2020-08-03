#include "tests.h"

#include <Psapi.h>

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
#define SPANNING_BUFFER_SIZE            (PAGE_SIZE * 2)
#define NUMBER_OF_THREADS               4
#define DEBUG_REGISTER_INDEX            0
#define CONTEXT_BUFFER_SIZE             (PAGE_SIZE)
#define REQUEST_DURATION_MS             (SECONDS_TO_MILLISECONDS(10))
#define WAIT_TIMEOUT_MS                 (SECONDS_TO_MILLISECONDS(10))


//=============================================================================
// Types
//=============================================================================
typedef struct _SPANNING_PAGE_CONTEXT
{
    HANDLE BarrierEvent;
    BOOLEAN Active;
    PVOID Buffer;
    PVOID FirstPage;
    PVOID SecondPage;

    //
    // An address which touches FirstPage and SecondPage when treated as a data
    //  type of size greater than one byte.
    //
    ULONG_PTR SpanningAddress;

} SPANNING_PAGE_CONTEXT, *PSPANNING_PAGE_CONTEXT;


//=============================================================================
// Spanning Page Test Case
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
// ExerciseSpanningPageBreakpoint
//
_Check_return_
static
DWORD
WINAPI
ExerciseSpanningPageBreakpoint(
    _In_ LPVOID lpParameter
)
{
    PSPANNING_PAGE_CONTEXT pContext = (PSPANNING_PAGE_CONTEXT)lpParameter;
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
// InitializeSpanningPageContext
//
_Check_return_
static
BOOL
InitializeSpanningPageContext(
    _Out_ PSPANNING_PAGE_CONTEXT pContext
)
{
    HANDLE BarrierEvent = NULL;
    PVOID pBuffer = NULL;
    SIZE_T cbBuffer = SPANNING_BUFFER_SIZE;
    ULONG_PTR SpanningAddress = 0;
    PVOID pFirstPage = NULL;
    PVOID pSecondPage = NULL;
    ULONG Value = 0;
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
    // Allocate at least two pages of memory.
    //
    pBuffer = VirtualAlloc(
        NULL,
        cbBuffer,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pBuffer)
    {
        printf("VirtualAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    printf("Allocated the spanning buffer: 0x%IX\n", (ULONG_PTR)pBuffer);

    //
    // Calculate an address inside the buffer which spans two pages when
    //  treated as a data type of size greater than one byte.
    //
    SpanningAddress = (ULONG_PTR)pBuffer + PAGE_SIZE - 1;

    if (SpanningAddress < (ULONG_PTR)pBuffer ||
        SpanningAddress >= (ULONG_PTR)pBuffer + cbBuffer)
    {
        printf("Unexpected spanning address:\n");
        printf("    pBuffer:         0x%IX\n", (ULONG_PTR)pBuffer);
        printf("    cbBuffer:        0x%IX\n", cbBuffer);
        printf("    SpanningAddress: 0x%IX\n", SpanningAddress);
        status = FALSE;
        goto exit;
    }

    printf("Spanning address: 0x%IX\n", SpanningAddress);

    //
    // Calculate the spanned pages.
    //
    pFirstPage = PAGE_ALIGN(SpanningAddress);
    pSecondPage = (PVOID)((ULONG_PTR)pFirstPage + PAGE_SIZE);

    if (pFirstPage < pBuffer ||
        (ULONG_PTR)pFirstPage >= (ULONG_PTR)pBuffer + cbBuffer)
    {
        printf("Unexpected first page spanned:\n");
        printf("    pBuffer:    0x%IX\n", (ULONG_PTR)pBuffer);
        printf("    cbBuffer:   0x%IX\n", cbBuffer);
        printf("    pFirstPage: 0x%IX\n", (ULONG_PTR)pFirstPage);
        status = FALSE;
        goto exit;
    }

    if (pSecondPage < pBuffer ||
        (ULONG_PTR)pSecondPage >= (ULONG_PTR)pBuffer + cbBuffer)
    {
        printf("Unexpected second page spanned:\n");
        printf("    pBuffer:        0x%IX\n", (ULONG_PTR)pBuffer);
        printf("    cbBuffer:       0x%IX\n", cbBuffer);
        printf("    pSecondPage:    0x%IX\n", (ULONG_PTR)pSecondPage);
        status = FALSE;
        goto exit;
    }

    if (pFirstPage == pSecondPage)
    {
        printf("Unexpected spanned pages:\n");
        printf("    pFirstPage:     0x%IX\n", (ULONG_PTR)pFirstPage);
        printf("    pSecondPage:    0x%IX\n", (ULONG_PTR)pSecondPage);
        status = FALSE;
        goto exit;
    }

    //
    // Access the first spanned page so that it is paged in for the request.
    //
    Value = *(PULONG)pFirstPage;

    // Set out parameters.
    pContext->BarrierEvent = BarrierEvent;
    pContext->Active = TRUE;
    pContext->Buffer = pBuffer;
    pContext->FirstPage = pFirstPage;
    pContext->SecondPage = pSecondPage;
    pContext->SpanningAddress = SpanningAddress;

exit:
    if (!status)
    {
        if (pBuffer)
        {
            if (!VirtualFree(pBuffer, 0, MEM_RELEASE))
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
// ReleaseSpanningPageContext
//
_Check_return_
static
BOOL
ReleaseSpanningPageContext(
    _In_ PSPANNING_PAGE_CONTEXT pContext
)
{
    BOOL status = TRUE;

    if (pContext->Buffer)
    {
        if (!VirtualFree(pContext->Buffer, 0, MEM_RELEASE))
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
// ExecuteCecmRequestForSpanningPage
//
// This test issues a CECM request which attempts to read an effective address
//  that spans two pages. The effective address is near a page boundary, and
//  the size of the memory data type causes the effective read to touch two
//  pages.
//
_Check_return_
static
BOOL
ExecuteCecmRequestForSpanningPage(
    _In_ MEMORY_DATA_TYPE MemoryDataType
)
{
    ULONG cbMemoryDataType = 0;
    SPANNING_PAGE_CONTEXT Context = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    BOOL ValidAddress = FALSE;
    CHAR szSpanningAddress[STR_ADDRESS_SIZE] = {};
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    DWORD ThreadIds[NUMBER_OF_THREADS] = {};
    HANDLE hThreads[NUMBER_OF_THREADS] = {};
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    cbMemoryDataType = GetMemoryDataTypeSize(MemoryDataType);
    if (!cbMemoryDataType)
    {
        printf("Invalid memory data type.\n");
        status = FALSE;
        goto exit;
    }

    printf(
        "Executing a CECM request for a page spanning address (%u)...\n",
        cbMemoryDataType);

    //
    // Initialize the exercise thread context.
    //
    status = InitializeSpanningPageContext(&Context);
    if (!status)
    {
        printf(
            "InitializeSpanningPageContext failed: %u\n",
            GetLastError());
        goto exit;
    }

    status = StrUnsignedLongLongToString(
        TRUE,
        (ULONG_PTR)Context.SpanningAddress,
        szSpanningAddress,
        sizeof(szSpanningAddress));
    if (!status)
    {
        printf("StrUnsignedLongLongToString failed: %u\n", GetLastError());
        goto exit;
    }

    //
    // Initialize the memory description for the request.
    //
    // NOTE The memory data type size used must be larger than a byte.
    //
    status = ParseMemoryDescriptionToken(
        szSpanningAddress,
        MemoryDataType,
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

    if (MDT_BYTE == MemoryDescription.DataType)
    {
        printf("Memory description parse error. (byte type)\n");
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
            ExerciseSpanningPageBreakpoint,
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
    // Verify that the first spanned page is valid.
    //
    status = IsVirtualAddressValid(Context.FirstPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (!ValidAddress)
    {
        printf("First spanned page is invalid. (pre-request)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the second spanned page is invalid.
    //
    status = IsVirtualAddressValid(Context.SecondPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (ValidAddress)
    {
        printf("Second spanned page is valid. (pre-request)\n");
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
    // Verify that the first spanned page is still valid.
    //
    status = IsVirtualAddressValid(Context.FirstPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (!ValidAddress)
    {
        printf("First spanned page is invalid. (post-request)\n");
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the second spanned page is still invalid.
    //
    status = IsVirtualAddressValid(Context.SecondPage, &ValidAddress);
    if (!status)
    {
        printf("IsVirtualAddressValid failed: %u.\n", GetLastError());
        goto exit;
    }

    if (ValidAddress)
    {
        printf("Second spanned page is valid. (post-request)\n");
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
    // Verify that the number of spanning address errors equals the hit count.
    //
    if (pValuesCtx->Statistics.SpanningAddressErrors !=
        pValuesCtx->Statistics.HitCount)
    {
        //
        // TODO For an unknown reason, this test may yield untouched page
        //  errors instead of spanning address errors.
        //
        SIZE_T CombinedErrorCount =
            pValuesCtx->Statistics.UntouchedPageErrors +
            pValuesCtx->Statistics.SpanningAddressErrors;

        if (CombinedErrorCount != pValuesCtx->Statistics.HitCount)
        {
            printf("Unexpected number of spanning address errors:\n");
            printf("    UntouchedPageErrors:    %Iu\n",
                pValuesCtx->Statistics.UntouchedPageErrors);
            printf("    SpanningAddressErrors:  %Iu\n",
                pValuesCtx->Statistics.SpanningAddressErrors);
            printf("    HitCount:               %Iu\n",
                pValuesCtx->Statistics.HitCount);
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

    if (!ReleaseSpanningPageContext(&Context))
    {
        printf("ReleaseSpanningPageContext failed: %u\n", GetLastError());
        status = FALSE;
    }

    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestAntiDebugCecmSpanningPage
//
// See: ExecuteCecmRequestForSpanningPage
//
VOID
TestAntiDebugCecmSpanningPage()
{
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = ExecuteCecmRequestForSpanningPage(MDT_WORD);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForSpanningPage failed. (word)\n");
    }

    status = ExecuteCecmRequestForSpanningPage(MDT_DWORD);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForSpanningPage failed. (dword)\n");
    }

    status = ExecuteCecmRequestForSpanningPage(MDT_QWORD);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForSpanningPage failed. (qword)\n");
    }

    status = ExecuteCecmRequestForSpanningPage(MDT_FLOAT);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForSpanningPage failed. (float)\n");
    }

    status = ExecuteCecmRequestForSpanningPage(MDT_DOUBLE);
    if (!status)
    {
        FAIL_TEST("ExecuteCecmRequestForSpanningPage failed. (double)\n");
    }

    PRINT_TEST_FOOTER;
}
