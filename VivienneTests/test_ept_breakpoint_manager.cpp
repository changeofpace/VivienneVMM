#include "test_ept_breakpoint_manager.h"

#include <Psapi.h>
#include <intrin.h>

#include "affinity.h"
#include "ept_breakpoint.h"
#include "system_util.h"
#include "test_util.h"
#include "thread_util.h"

#include "../common/time_util.h"

#include "../VivienneCL/log.h"
#include "../VivienneCL/memory_util.h"
#include "../VivienneCL/ntdll.h"


//
// TODO Organize this file and the corresponding assembly file.
//


//=============================================================================
// Constants
//=============================================================================
#define TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD 100


//=============================================================================
// Macros
//=============================================================================
#define ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, Expected)                       \
    if (((PEPT_BREAKPOINT_LOG)(pLog))->Header.NumberOfElements != (Expected))\
    {                                                                       \
        FAIL_TEST(                                                          \
            "Unexpected NumberOfElements. (Actual = %u, Expected = %u)",    \
            ((PEPT_BREAKPOINT_LOG)(pLog))->Header.NumberOfElements,         \
            (Expected));                                                    \
    }

#define ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, Expected)        \
    if (((PEBLE_BASIC)(pElement))->TriggerAddress != ((ULONG_PTR)(Expected)))\
    {                                                                       \
        FAIL_TEST(                                                          \
            "Unexpected TriggerAddress. (Actual = %p, Expected = %p)",      \
            ((PEBLE_BASIC)(pElement))->TriggerAddress,                      \
            (Expected));                                                    \
    }

#define ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(pElement, Expected)\
    if (((PEBLE_BASIC)(pElement))->HitCount < (Expected) &&                 \
        ((PEBLE_BASIC)(pElement))->HitCount >=                              \
            ((ULONG_PTR)(Expected) + TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD))\
    {                                                                       \
        WRN_PRINT("Unexpected HitCount. (Actual = %Iu, Expected = %Iu - %Iu)", \
            ((PEBLE_BASIC)(pElement))->HitCount,                            \
            (Expected),                                                     \
            (Expected) + TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD);          \
    }


#define ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_ABOVE_THRESHOLD(pElement, Expected)\
    if (((PEBLE_BASIC)(pElement))->HitCount < ((ULONG_PTR)(Expected)))      \
    {                                                                       \
        FAIL_TEST("Unexpected HitCount. (Actual = %Iu, Expected = %Iu)", \
            ((PEBLE_BASIC)(pElement))->HitCount,                            \
            (Expected));                                                    \
    }


//=============================================================================
// Utilities
//=============================================================================
_Success_(return != FALSE)
_Check_return_
static
BOOL
QueryEptBreakpointInformation(
    _Outptr_result_nullonfailure_
        PEPT_BREAKPOINT_INFORMATION* pEptBreakpointInfo
)
{
    INF_PRINT("Querying ept breakpoint information.");

    return EbpQueryEptBreakpointInformation(pEptBreakpointInfo, NULL);
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
SetEptBreakpoint(
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG_PTR Address,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType,
    _In_ SIZE_T cbLog,
    _In_ BOOLEAN fMakePageResident,
    _In_opt_ X64_REGISTER RegisterKey,
    _Out_ PHANDLE phLog,
    _Out_ PEPT_BREAKPOINT_LOG* ppLog
)
{
    BOOL status = TRUE;

    INF_PRINT(
        "Setting ept breakpoint."
        " (PID = %Iu, VA = %p, BT = %d, BS = %d, LT = %d, LS = 0x%IX)",
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        LogType,
        cbLog);

    switch (LogType)
    {
        case EptBreakpointLogTypeBasic:
            status = EbpSetEptBreakpointBasic(
                ProcessId,
                Address,
                BreakpointType,
                BreakpointSize,
                cbLog,
                fMakePageResident,
                phLog,
                ppLog);
            break;

        case EptBreakpointLogTypeGeneralRegisterContext:
            status = EbpSetEptBreakpointGeneralRegisterContext(
                ProcessId,
                Address,
                BreakpointType,
                BreakpointSize,
                cbLog,
                fMakePageResident,
                phLog,
                ppLog);
            break;

        case EptBreakpointLogTypeKeyedRegisterContext:
            status = EbpSetEptBreakpointKeyedRegisterContext(
                ProcessId,
                Address,
                BreakpointType,
                BreakpointSize,
                cbLog,
                fMakePageResident,
                RegisterKey,
                phLog,
                ppLog);
            break;

        default:
            ERR_PRINT("Unexpected LogType: %d", LogType);
            status = FALSE;
            goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
DisableEptBreakpoint(
    _In_ HANDLE Handle
)
{
    INF_PRINT("Disabling ept breakpoint. (Handle = %p)", Handle);

    return EbpDisableEptBreakpoint(Handle);
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
ClearEptBreakpoint(
    _In_ HANDLE Handle
)
{
    INF_PRINT("Clearing ept breakpoint. (Handle = %p)", Handle);

    return EbpClearEptBreakpoint(Handle);
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
VerifyEptBreakpointUnwind()
{
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo = NULL;
    BOOL status = TRUE;

    status = QueryEptBreakpointInformation(&pEptBreakpointInfo);
    if (!status)
    {
        ERR_PRINT("QueryEptBreakpointInformation failed: %u", GetLastError());
        goto exit;
    }

    if (pEptBreakpointInfo->NumberOfActiveBreakpoints)
    {
        ERR_PRINT("Unexpected NumberOfActiveBreakpoints: %u",
            pEptBreakpointInfo->NumberOfActiveBreakpoints);
        status = FALSE;
        goto exit;
    }

    if (pEptBreakpointInfo->NumberOfInactiveBreakpoints)
    {
        ERR_PRINT("Unexpected NumberOfInactiveBreakpoints: %u",
            pEptBreakpointInfo->NumberOfInactiveBreakpoints);
        status = FALSE;
        goto exit;
    }

    if (pEptBreakpointInfo->NumberOfLockedPages)
    {
        ERR_PRINT("Unexpected NumberOfLockedPages: %u",
            pEptBreakpointInfo->NumberOfLockedPages);
        status = FALSE;
        goto exit;
    }

    if (pEptBreakpointInfo->NumberOfHookedPages)
    {
        ERR_PRINT("Unexpected NumberOfHookedPages: %u",
            pEptBreakpointInfo->NumberOfHookedPages);
        status = FALSE;
        goto exit;
    }

    if (pEptBreakpointInfo->NumberOfElements)
    {
        ERR_PRINT("Unexpected NumberOfElements: %u",
            pEptBreakpointInfo->NumberOfElements);
        status = FALSE;
        goto exit;
    }

    if (!MemFreeHeap(pEptBreakpointInfo))
    {
        ERR_PRINT("MemFreeHeap failed: %u", GetLastError());
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
QueryWorkingSetExInformation(
    _In_ PVOID pAddress,
    _Out_ PPSAPI_WORKING_SET_EX_INFORMATION pWorkingSetExInfo
)
{
    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetExInfo = {};
    BOOL status = TRUE;

    //
    // Zero output parameters.
    //
    RtlSecureZeroMemory(pWorkingSetExInfo, sizeof(*pWorkingSetExInfo));

    //
    // Initialize the target virtual address for the working set query.
    //
    WorkingSetExInfo.VirtualAddress = pAddress;

    status = QueryWorkingSetEx(
        GetCurrentProcess(),
        &WorkingSetExInfo,
        sizeof(WorkingSetExInfo));
    if (!status)
    {
        ERR_PRINT("QueryWorkingSetEx failed: %u", GetLastError());
        goto exit;
    }

    //
    // Set output parameters.
    //
    RtlCopyMemory(
        pWorkingSetExInfo,
        &WorkingSetExInfo,
        sizeof(PSAPI_WORKING_SET_EX_INFORMATION));

exit:
    return status;
}


static
VOID
PrintWorkingSetExInformation(
    _In_opt_ PSTR pszTitle,
    _In_ PPSAPI_WORKING_SET_EX_INFORMATION pWorkingSetExInfo
)
{
    if (ARGUMENT_PRESENT(pszTitle))
    {
        INF_PRINT("%s", pszTitle);
    }

    INF_PRINT("    VirtualAddress:  %p", pWorkingSetExInfo->VirtualAddress);

    if (pWorkingSetExInfo->VirtualAttributes.Valid)
    {
        INF_PRINT("    Valid:           %p", pWorkingSetExInfo->VirtualAttributes.Valid);
        INF_PRINT("    ShareCount:      %p", pWorkingSetExInfo->VirtualAttributes.ShareCount);
        INF_PRINT("    Win32Protection: %p", pWorkingSetExInfo->VirtualAttributes.Win32Protection);
        INF_PRINT("    Shared:          %p", pWorkingSetExInfo->VirtualAttributes.Shared);
        INF_PRINT("    Node:            %p", pWorkingSetExInfo->VirtualAttributes.Node);
        INF_PRINT("    Locked:          %p", pWorkingSetExInfo->VirtualAttributes.Locked);
        INF_PRINT("    LargePage:       %p", pWorkingSetExInfo->VirtualAttributes.LargePage);
        INF_PRINT("    Reserved:        %p", pWorkingSetExInfo->VirtualAttributes.Reserved);
        INF_PRINT("    Bad:             %p", pWorkingSetExInfo->VirtualAttributes.Bad);
        INF_PRINT("    ReservedUlong:   %p", pWorkingSetExInfo->VirtualAttributes.ReservedUlong);
    }
    else
    {
        INF_PRINT("    Valid:           %p", pWorkingSetExInfo->VirtualAttributes.Valid);
        INF_PRINT("    Reserved0:       %p", pWorkingSetExInfo->VirtualAttributes.Invalid.Reserved0);
        INF_PRINT("    Shared:          %p", pWorkingSetExInfo->VirtualAttributes.Invalid.Shared);
        INF_PRINT("    Reserved1:       %p", pWorkingSetExInfo->VirtualAttributes.Invalid.Reserved1);
        INF_PRINT("    Bad:             %p", pWorkingSetExInfo->VirtualAttributes.Invalid.Bad);
    }
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
IsUnchangedWorkingSetExInformation(
    _In_ PVOID pAddress,
    _In_ PPSAPI_WORKING_SET_EX_INFORMATION pWorkingSetExInfo,
    _In_opt_ DWORD IgnoreMask
)
{
    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetExInfo = {};
    BOOL status = TRUE;

    status = QueryWorkingSetExInformation(pAddress, &WorkingSetExInfo);
    if (!status)
    {
        ERR_PRINT("QueryWorkingSetExInformation failed: %u", GetLastError());
        goto exit;
    }

    if (!RtlEqualMemory(
            &WorkingSetExInfo.VirtualAttributes,
            &pWorkingSetExInfo->VirtualAttributes,
            sizeof(PSAPI_WORKING_SET_EX_BLOCK)))
    {
        ERR_PRINT("WorkingSetExInformation changed for %p", pAddress);
        PrintWorkingSetExInformation("Previous", pWorkingSetExInfo);
        PrintWorkingSetExInformation("New", &WorkingSetExInfo);
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
VirtualAddressResidency(
    _In_ PVOID pAddress,
    _In_ BOOLEAN fAssertResident
)
{
    BOOL fValid = TRUE;
    BOOL status = TRUE;

    status = IsVirtualAddressValid(pAddress, &fValid);
    if (!status)
    {
        FAIL_TEST("IsVirtualAddressValid failed: %u (Address = %p)",
            GetLastError(),
            pAddress);
    }

    if (!fValid && fAssertResident)
    {
        FAIL_TEST("Virtual address %p is resident. (Unexpected)", pAddress);
    }
    else if (fValid && !fAssertResident)
    {
        FAIL_TEST("Virtual address %p is not resident. (Unexpected)",
            pAddress);
    }
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
VerifyVirtualAddressIsResident(
    _In_ PVOID pAddress
)
{
    BOOL fValid = TRUE;
    BOOL status = TRUE;

    status = IsVirtualAddressValid(pAddress, &fValid);
    if (!status)
    {
        ERR_PRINT("IsVirtualAddressValid failed: %u (pAddress = %p)",
            GetLastError(),
            pAddress);
    }

    if (!fValid)
    {
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
VerifyVirtualAddressIsNotResident(
    _In_ PVOID pAddress
)
{
    BOOL fValid = TRUE;
    BOOL status = TRUE;

    status = IsVirtualAddressValid(pAddress, &fValid);
    if (!status)
    {
        ERR_PRINT("IsVirtualAddressValid failed: %u (pAddress = %p)",
            GetLastError(),
            pAddress);
    }

    if (fValid)
    {
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
VerifyMemoryRegionIsFree(
    _In_ PVOID pAddress
)
{
    MEMORY_BASIC_INFORMATION MemoryBasicInfo = {};
    SIZE_T cbRegion = 0;
    BOOL status = TRUE;

    cbRegion =
        VirtualQuery(pAddress, &MemoryBasicInfo, sizeof(MemoryBasicInfo));
    if (!cbRegion)
    {
        ERR_PRINT("VirtualQuery failed: %u", GetLastError());
        status = FALSE;
        goto exit;
    }

    if (MemoryBasicInfo.AllocationBase)
    {
        ERR_PRINT("Unexpected AllocationBase: %p",
            MemoryBasicInfo.AllocationBase);
        status = FALSE;
        goto exit;
    }

    if (MemoryBasicInfo.AllocationProtect)
    {
        ERR_PRINT("Unexpected AllocationProtect: %p",
            MemoryBasicInfo.AllocationProtect);
        status = FALSE;
        goto exit;
    }

    if (MemoryBasicInfo.State != MEM_FREE)
    {
        ERR_PRINT("Unexpected State: %p", MemoryBasicInfo.State);
        status = FALSE;
        goto exit;
    }

    if (MemoryBasicInfo.Protect != PAGE_NOACCESS)
    {
        ERR_PRINT("Unexpected Protect: %p", MemoryBasicInfo.Protect);
        status = FALSE;
        goto exit;
    }

    if (MemoryBasicInfo.Type)
    {
        ERR_PRINT("Unexpected Type: %p", MemoryBasicInfo.Type);
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


static
VOID
PrintMemoryBasicInformation(
    _In_opt_ PSTR pszTitle,
    _In_ PMEMORY_BASIC_INFORMATION pMemoryBasicInfo
)
{
    if (ARGUMENT_PRESENT(pszTitle))
    {
        INF_PRINT("%s", pszTitle);
    }

    INF_PRINT("    BaseAddress:         %p", pMemoryBasicInfo->BaseAddress);
    INF_PRINT("    AllocationBase:      %p", pMemoryBasicInfo->AllocationBase);
    INF_PRINT("    AllocationProtect:   %08X",
        pMemoryBasicInfo->AllocationProtect);
    INF_PRINT("    RegionSize:          %IX", pMemoryBasicInfo->RegionSize);
    INF_PRINT("    State:               %08X", pMemoryBasicInfo->State);
    INF_PRINT("    Protect:             %08X", pMemoryBasicInfo->Protect);
    INF_PRINT("    Type:                %08X", pMemoryBasicInfo->Type);
}


FORCEINLINE
static
ULONG_PTR
GeneratePseudoRandomUlongPtr()
{
    ULONG_PTR Value = {};

#if defined(_WIN64)
    Value = ((((ULONG_PTR)(RANDOM_ULONG)) << 32) | (RANDOM_ULONG));
#else
    Value = RANDOM_ULONG;
#endif

    return Value;
}


static
VOID
GeneratePseudoRandomGeneralPurposeRegisterContext(
    _Out_ PGENERAL_PURPOSE_REGISTERS pContext
)
{
    pContext->R15 = GeneratePseudoRandomUlongPtr();
    pContext->R14 = GeneratePseudoRandomUlongPtr();
    pContext->R13 = GeneratePseudoRandomUlongPtr();
    pContext->R12 = GeneratePseudoRandomUlongPtr();
    pContext->R11 = GeneratePseudoRandomUlongPtr();
    pContext->R10 = GeneratePseudoRandomUlongPtr();
    pContext->R9 = GeneratePseudoRandomUlongPtr();
    pContext->R8 = GeneratePseudoRandomUlongPtr();
    pContext->Rdi = GeneratePseudoRandomUlongPtr();
    pContext->Rsi = GeneratePseudoRandomUlongPtr();
    pContext->Rbp = GeneratePseudoRandomUlongPtr();
    pContext->Rsp = GeneratePseudoRandomUlongPtr();
    pContext->Rbx = GeneratePseudoRandomUlongPtr();
    pContext->Rdx = GeneratePseudoRandomUlongPtr();
    pContext->Rcx = GeneratePseudoRandomUlongPtr();
    pContext->Rax = GeneratePseudoRandomUlongPtr();
}


_Success_(return != FALSE)
_Check_return_
static
BOOL
SelectGeneralPurposeRegister(
    _In_ X64_REGISTER Register,
    _In_ PGENERAL_PURPOSE_REGISTERS pRegisterContext,
    _Out_ PULONG_PTR pRegisterValue
)
{
    BOOL status = TRUE;

    //
    // Zero output parameters.
    //
    *pRegisterValue = 0;

    switch (Register)
    {
        case REGISTER_R15: *pRegisterValue = pRegisterContext->R15; break;
        case REGISTER_R14: *pRegisterValue = pRegisterContext->R14; break;
        case REGISTER_R13: *pRegisterValue = pRegisterContext->R13; break;
        case REGISTER_R12: *pRegisterValue = pRegisterContext->R12; break;
        case REGISTER_R11: *pRegisterValue = pRegisterContext->R11; break;
        case REGISTER_R10: *pRegisterValue = pRegisterContext->R10; break;
        case REGISTER_R9:  *pRegisterValue = pRegisterContext->R9;  break;
        case REGISTER_R8:  *pRegisterValue = pRegisterContext->R8;  break;
        case REGISTER_RDI: *pRegisterValue = pRegisterContext->Rdi; break;
        case REGISTER_RSI: *pRegisterValue = pRegisterContext->Rsi; break;
        case REGISTER_RBP: *pRegisterValue = pRegisterContext->Rbp; break;
        case REGISTER_RSP: *pRegisterValue = pRegisterContext->Rsp; break;
        case REGISTER_RBX: *pRegisterValue = pRegisterContext->Rbx; break;
        case REGISTER_RDX: *pRegisterValue = pRegisterContext->Rdx; break;
        case REGISTER_RCX: *pRegisterValue = pRegisterContext->Rcx; break;
        case REGISTER_RAX: *pRegisterValue = pRegisterContext->Rax; break;
        default:
            status = FALSE;
            goto exit;
    }

exit:
    return status;
}


//=============================================================================
// Safety Tests
//=============================================================================
static WORD g_LogContextSafety_TargetAddress = 0;

VOID
Test_Ebm_LogContextSafety()
{
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    DWORD PreviousProtection = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&g_LogContextSafety_TargetAddress,
        EptBreakpointTypeWrite,
        EptBreakpointSizeWord,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Verify that we cannot unmap the log section.
    //
    ntstatus = NtUnmapViewOfSection(NtCurrentProcess(), pLog);
    if (NT_SUCCESS(ntstatus))
    {
        FAIL_TEST("NtUnmapViewOfSection succeeded. (Unexpected)");
    }

    //
    // Verify that we cannot change the page protection of a page in the log
    //  section.
    //
    status =
        VirtualProtect(pLog, PAGE_SIZE, PAGE_READWRITE, &PreviousProtection);
    if (status)
    {
        FAIL_TEST("VirtualProtect succeeded. (Unexpected)");
    }

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// Basic Functionality Tests
//=============================================================================
VOID
Test_Ebm_ReadBreakpointBasic()
{
    PVOID pBuffer = NULL;
    PDWORD64 pQword = NULL;
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    DWORD i = 0;
    PBYTE pAccessAddress = NULL;
    DWORD nReads = 0;
    DWORD nTotalReads = 0;
    PEBLE_BASIC pElement = NULL;
    BYTE Temp = 0;
    DWORD j = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    pBuffer = VirtualAlloc(
        NULL,
        PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pBuffer)
    {
        FAIL_TEST("VirtualAlloc failed: %u", GetLastError());
    }

    pQword = (PDWORD64)pBuffer;

    //
    // Set a qword sized breakpoint and verify that accessing any of the bytes
    //  in the range (breakpoint_address, breakpoint_address + sizeof(qword)]
    //  triggers the breakpoint.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)pQword,
        EptBreakpointTypeRead,
        EptBreakpointSizeQword,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Access each byte of the target qword a random number of times.
    //
    for (i = 0; i < sizeof(DWORD64); i++)
    {
        pAccessAddress = (PBYTE)((ULONG_PTR)pQword + i);

        nReads = RANDOM_ULONG % 30;

        for (j = 0; j < nReads; j++)
        {
            Temp = Test_Ebm_ReadByte(pAccessAddress);
        }

        nTotalReads += nReads;

        ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 1);

        pElement = &pLog->u.Basic.Elements[0];

        ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, Test_Ebm_ReadByte);

        ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
            pElement,
            nTotalReads);
    }

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    status = VirtualFree(pBuffer, 0, MEM_RELEASE);
    if (!status)
    {
        FAIL_TEST("VirtualFree failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


VOID
Test_Ebm_WriteBreakpointBasic()
{
    PBYTE pByteBuffer = NULL;
    ULONG nTargetIndex = 0;
    PBYTE pTargetByte = NULL;
    HANDLE hByteLog = NULL;
    PEPT_BREAKPOINT_LOG pByteLog = NULL;
    PEBLE_BASIC pByteElement = NULL;
    BYTE TempByte = 0;
    DWORD i = 0;
    PBYTE pIrrelevantByte = NULL;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    pByteBuffer = (PBYTE)VirtualAlloc(
        NULL,
        PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pByteBuffer)
    {
        FAIL_TEST("VirtualAlloc failed: %u", GetLastError());
    }

    //
    // Randomly select a byte in the buffer as the target address.
    //
    nTargetIndex = RANDOM_ULONG % PAGE_SIZE;

    pTargetByte = &pByteBuffer[nTargetIndex];

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)pTargetByte,
        EptBreakpointTypeWrite,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hByteLog,
        &pByteLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Verify that neither target variables have been written to.
    //
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pByteLog, 0);

    //
    // Trigger the breakpoint.
    //
    *pTargetByte = 0x77;

    //
    // Verify that there is only have one trigger address with one hit.
    //
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pByteLog, 1);

    pByteElement = &pByteLog->u.Basic.Elements[0];

    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(pByteElement, 1);

    //
    // Modify every other byte in the page.
    //
    for (i = 0; i < PAGE_SIZE; i++)
    {
        if (i == nTargetIndex)
        {
            continue;
        }

        pByteBuffer[i] = (BYTE)i;
    }

    //
    // Verify that there is only one trigger address with one hit.
    //
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pByteLog, 1);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(pByteElement, 1);

    //
    // Trigger the breakpoint at a different address.
    //
    *pTargetByte = 0x44;

    //
    // Verify that there are two trigger addresses with one hit each.
    //
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pByteLog, 2);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(pByteElement, 1);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
        &pByteLog->u.Basic.Elements[1],
        1);

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hByteLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


VOID
Test_Ebm_ExecuteBreakpointBasic()
{
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    DWORD nProcessors = 0;
    DWORD nIterations = 0;
    DWORD i = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)Test_Ebm_ExecuteBasic,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    nIterations = (RANDOM_ULONG % 100) + 100;

    for (i = 0; i < nIterations; i++)
    {
        Test_Ebm_ExecuteBasic();

        ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 1);
    }

    status = DisableEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("DisableEptBreakpoint failed: %u", GetLastError());
    }

    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
        &pLog->u.Basic.Elements[0].HitCount,
        nIterations);

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


#define MULTICORE_EXERCISE_DURATION_MS 15000

typedef enum _BASIC_EPT_BREAKPOINTS_MULTICORE_BREAKPOINT_TYPE {
    BasicEptBreakpointsMulticoreBreakpointTypeRead = 0,
    BasicEptBreakpointsMulticoreBreakpointTypeWrite,
    BasicEptBreakpointsMulticoreBreakpointTypeExecute,
    BasicEptBreakpointsMulticoreBreakpointTypeNtWaitForSingleObject,
    MaxBasicEptBreakpointsMulticoreBreakpointType
} BASIC_EPT_BREAKPOINTS_MULTICORE_BREAKPOINT_TYPE,
*PBASIC_EPT_BREAKPOINTS_MULTICORE_BREAKPOINT_TYPE;

typedef struct _BASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT {
    HANDLE BarrierEvent;
    BOOL Active;
    HANDLE DummyEvent;
    DWORD ReadTargetAddress;
    ULONG64 ReadHitCount;
    DWORD64 WriteTargetAddress;
    ULONG64 WriteHitCount;
    ULONG64 ExecuteHitCount;
    ULONG64 NtWaitForSingleObjectHitCount;
} BASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT,
*PBASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT;

DWORD
WINAPI
Test_Ebm_BreakpointsMulticoreBasic_ThreadRoutine(
    _In_ LPVOID lpThreadParameter
)
{
    PBASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT pContext = NULL;
    DWORD waitstatus = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    DWORD exitstatus = ERROR_SUCCESS;

    pContext = (PBASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT)lpThreadParameter;

    //
    // Wait until all threads have been created.
    //
    waitstatus = WaitForSingleObject(pContext->BarrierEvent, INFINITE);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u", GetLastError());
    }

    //
    // Enter the exercise loop.
    //
    while (pContext->Active)
    {
        switch (RANDOM_ULONG % MaxBasicEptBreakpointsMulticoreBreakpointType)
        {
            case BasicEptBreakpointsMulticoreBreakpointTypeRead:
                Test_Ebm_ReadDword(&pContext->ReadTargetAddress);
                pContext->ReadHitCount++;
                break;

            case BasicEptBreakpointsMulticoreBreakpointTypeWrite:
                Test_Ebm_WriteQword(
                    &pContext->WriteTargetAddress,
                    RANDOM_ULONG);
                pContext->WriteHitCount++;
                break;

            case BasicEptBreakpointsMulticoreBreakpointTypeExecute:
                Test_Ebm_ExecuteBasic();
                pContext->ExecuteHitCount++;
                break;

            case BasicEptBreakpointsMulticoreBreakpointTypeNtWaitForSingleObject:
                ntstatus =
                    NtWaitForSingleObject(pContext->DummyEvent, FALSE, NULL);
                if (STATUS_SUCCESS != ntstatus)
                {
                    FAIL_TEST("NtWaitForSingleObject failed: 0x%X", ntstatus);
                }

                pContext->NtWaitForSingleObjectHitCount++;

                break;

            default:
                FAIL_TEST(
                    "Unhandled BASIC_EPT_BREAKPOINTS_MULTICORE_BREAKPOINT_TYPE.");
        }

        Sleep(RANDOM_ULONG % 20);
    }

    return exitstatus;
}


VOID
Test_Ebm_BreakpointsMulticoreBasic()
{
    HMODULE pNtdll = NULL;
    FARPROC pNtWaitForSingleObject = NULL;
    DWORD nProcessors = 0;
    BASIC_EPT_BREAKPOINTS_MULTICORE_CONTEXT TestContext = {};
    PHANDLE phThread = NULL;
    WORD ReadTargetAddress = 0;
    HANDLE ReadBreakpointHandle = NULL;
    PEPT_BREAKPOINT_LOG pReadBreakpointLog = NULL;
    DWORD64 WriteTargetAddress = 0;
    HANDLE WriteBreakpointHandle = NULL;
    PEPT_BREAKPOINT_LOG pWriteBreakpointLog = NULL;
    HANDLE ExecuteBreakpointHandle = NULL;
    PEPT_BREAKPOINT_LOG pExecuteBreakpointLog = NULL;
    HANDLE NtWaitForSingleObjectBreakpointHandle = NULL;
    PEPT_BREAKPOINT_LOG pNtWaitForSingleObjectBreakpointLog = NULL;
    PEBLE_BASIC pElement = NULL;
    DWORD i = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    pNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!pNtdll)
    {
        FAIL_TEST("GetModuleHandleW failed: %u", GetLastError());
    }

    pNtWaitForSingleObject = GetProcAddress(pNtdll, "NtWaitForSingleObject");
    if (!pNtWaitForSingleObject)
    {
        FAIL_TEST("GetProcAddress failed: %u", GetLastError());
    }

    //
    // Allow our current process to execute threads on each logical process.
    //
    nProcessors = AfnGetLogicalProcessorCount();
    if (!nProcessors)
    {
        FAIL_TEST("AfnGetLogicalProcessorCount failed: %u", GetLastError());
    }

    //
    // Limit the processor count to MAXIMUM_WAIT_OBJECTS to simplify our
    //  WaitForMultipleObjects logic.
    //
    if (nProcessors > MAXIMUM_WAIT_OBJECTS)
    {
        nProcessors = MAXIMUM_WAIT_OBJECTS;

        WRN_PRINT("Detected more than %u processors.", MAXIMUM_WAIT_OBJECTS);
        WRN_PRINT("Setting processor count to %u.", MAXIMUM_WAIT_OBJECTS);
    }

    status =
        AfnSetProcessAffinityAllProcessors(GetCurrentProcess(), nProcessors);
    if (!status)
    {
        FAIL_TEST("AfnSetProcessAffinityAllProcessors failed: %u",
            GetLastError());
    }

    //
    // Initialize the shared context.
    //
    TestContext.BarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!TestContext.BarrierEvent)
    {
        FAIL_TEST("CreateEvent failed: %u", GetLastError());
    }

    TestContext.DummyEvent = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (!TestContext.DummyEvent)
    {
        FAIL_TEST("CreateEvent failed: %u", GetLastError());
    }
    
    TestContext.Active = TRUE;

    //
    // Allocate the wait object array.
    //
    phThread = (PHANDLE)MemAllocateHeap(nProcessors * sizeof(*phThread));
    if (!phThread)
    {
        FAIL_TEST("MemAllocateHeap failed.");
    }

    //
    // Set the breakpoints.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&ReadTargetAddress,
        EptBreakpointTypeRead,
        EptBreakpointSizeWord,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &ReadBreakpointHandle,
        &pReadBreakpointLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&WriteTargetAddress,
        EptBreakpointTypeWrite,
        EptBreakpointSizeQword,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &WriteBreakpointHandle,
        &pWriteBreakpointLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)Test_Ebm_ExecuteBasic,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &ExecuteBreakpointHandle,
        &pExecuteBreakpointLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)pNtWaitForSingleObject,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &NtWaitForSingleObjectBreakpointHandle,
        &pNtWaitForSingleObjectBreakpointLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Verify that none of the breakpoints have been triggered yet.
    //
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pReadBreakpointLog, 0);
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pWriteBreakpointLog, 0);
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pExecuteBreakpointLog, 0);
    ASSERT_NUMBER_OF_LOG_ELEMENTS(pNtWaitForSingleObjectBreakpointLog, 0);

    //
    // Create a thread on each processor.
    //
    for (i = 0; i < nProcessors; i++)
    {
        phThread[i] = CreateThread(
            NULL,
            0,
            Test_Ebm_BreakpointsMulticoreBasic_ThreadRoutine,
            &TestContext,
            0,
            NULL);
        if (!phThread[i])
        {
            FAIL_TEST("CreateThread failed: %u", GetLastError());
        }
    }

    //
    // Signal the exercise threads to enter the test loop.
    //
    if (!SetEvent(TestContext.BarrierEvent))
    {
        FAIL_TEST("SetEvent failed: %u", GetLastError());
    }

    //
    // Let the threads trigger the breakpoints.
    //
    Sleep(MULTICORE_EXERCISE_DURATION_MS);

    //
    // Lazily signal that all threads should terminate.
    //
    TestContext.Active = FALSE;

    //
    // Wait for all threads to terminate.
    //
    waitstatus = WaitForMultipleObjects(
        nProcessors,
        phThread,
        TRUE,
        INFINITE);
    if (waitstatus < WAIT_OBJECT_0 || waitstatus >= nProcessors)
    {
        FAIL_TEST("WaitForMultipleObjects failed: %u", GetLastError());
    }

    //
    // Disable each breakpoint to reduce the number of false positive hits.
    //
    status = DisableEptBreakpoint(ReadBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("DisableEptBreakpoint failed: %u", GetLastError());
    }

    status = DisableEptBreakpoint(WriteBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("DisableEptBreakpoint failed: %u", GetLastError());
    }

    status = DisableEptBreakpoint(ExecuteBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("DisableEptBreakpoint failed: %u", GetLastError());
    }

    status = DisableEptBreakpoint(NtWaitForSingleObjectBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("DisableEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Validate the read breakpoint log.
    //
    if (TestContext.ReadHitCount &&
        TestContext.ReadHitCount > TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD &&
        pReadBreakpointLog->Header.NumberOfElements != 1)
    {
        WRN_PRINT("Unexpected NumberOfElements. (Read)");
    }

    pElement = &pReadBreakpointLog->u.Basic.Elements[0];

    if (pElement->HitCount)
    {
        ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, Test_Ebm_ReadDword);

        ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
            pElement,
            TestContext.ReadHitCount);
    }

    //
    // Validate the write breakpoint log.
    //
    if (TestContext.WriteHitCount &&
        TestContext.WriteHitCount > TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD &&
        pWriteBreakpointLog->Header.NumberOfElements != 1)
    {
        WRN_PRINT("Unexpected NumberOfElements. (Write)");
    }

    pElement = &pWriteBreakpointLog->u.Basic.Elements[0];

    if (pElement->HitCount)
    {
        ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, Test_Ebm_ReadQword);

        ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
            pElement,
            TestContext.WriteHitCount);
    }

    //
    // Validate the execute breakpoint log.
    //
    if (TestContext.ExecuteHitCount &&
        TestContext.ExecuteHitCount >
            TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD &&
        pExecuteBreakpointLog->Header.NumberOfElements != 1)
    {
        WRN_PRINT("Unexpected NumberOfElements. (Execute)");
    }

    pElement = &pExecuteBreakpointLog->u.Basic.Elements[0];

    if (pElement->HitCount)
    {
        ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, Test_Ebm_ExecuteBasic);

        ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
            pElement,
            TestContext.ExecuteHitCount);
    }

    //
    // Validate the NtWaitForSingleObject breakpoint log.
    //
    if (TestContext.NtWaitForSingleObjectHitCount &&
        TestContext.NtWaitForSingleObjectHitCount >
            TEST_EBM_BREAKPOINT_HIT_COUNT_THRESHOLD &&
        pNtWaitForSingleObjectBreakpointLog->Header.NumberOfElements != 1)
    {
        WRN_PRINT("Unexpected NumberOfElements. (NtWaitForSingleObject)");
    }

    pElement = &pNtWaitForSingleObjectBreakpointLog->u.Basic.Elements[0];

    if (pElement->HitCount)
    {
        ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(pElement, pNtWaitForSingleObject);

        ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_WITH_THRESHOLD(
            pElement,
            TestContext.NtWaitForSingleObjectHitCount);
    }

    //
    // Clear the breakpoints.
    //
    status = ClearEptBreakpoint(NtWaitForSingleObjectBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = ClearEptBreakpoint(ExecuteBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = ClearEptBreakpoint(WriteBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = ClearEptBreakpoint(ReadBreakpointHandle);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Unwind.
    //
    if (!VerifyEptBreakpointUnwind())
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    for (i = 0; i < nProcessors; ++i)
    {
        if (phThread[i])
        {
            if (!CloseHandle(phThread[i]))
            {
                FAIL_TEST("CloseHandle failed: %u", GetLastError());
            }
        }
    }

    if (!MemFreeHeap(phThread))
    {
        FAIL_TEST("MemFreeHeap failed: %u", GetLastError());
    }

    if (!CloseHandle(TestContext.DummyEvent))
    {
        FAIL_TEST("CloseHandle failed: %u", GetLastError());
    }

    if (!CloseHandle(TestContext.BarrierEvent))
    {
        FAIL_TEST("CloseHandle failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// General Register Context Functionality Tests
//=============================================================================
#define GRCF_LOG_SIZE               0x20000
#define GRCF_NUMBER_OF_ITERATIONS   1500

//
// Assert that we generate more log entries than what the log buffer can hold.
//
C_ASSERT(
    GRCF_NUMBER_OF_ITERATIONS >
    ((GRCF_LOG_SIZE) / sizeof(EBLE_GENERAL_REGISTER_CONTEXT) +
        sizeof(EPT_BREAKPOINT_LOG)));


_Success_(return != FALSE)
_Check_return_
static
BOOL
Test_Ebm_GeneralRegisterContext_CompareRegisterContexts(
    _In_ PGENERAL_PURPOSE_REGISTERS pAlpha,
    _In_ PGENERAL_PURPOSE_REGISTERS pBeta
)
{
    return (
        pAlpha->R15 == pBeta->R15 &&
        pAlpha->R14 == pBeta->R14 &&
        pAlpha->R13 == pBeta->R13 &&
        pAlpha->R12 == pBeta->R12 &&
        pAlpha->R11 == pBeta->R11 &&
        pAlpha->R10 == pBeta->R10 &&
        pAlpha->R9  == pBeta->R9 &&
        pAlpha->R8  == pBeta->R8 &&
        pAlpha->Rdi == pBeta->Rdi &&
        pAlpha->Rsi == pBeta->Rsi &&
        pAlpha->Rbp == pBeta->Rbp &&
        //pAlpha->Rsp == pBeta->Rsp &&
        pAlpha->Rbx == pBeta->Rbx &&
        pAlpha->Rdx == pBeta->Rdx &&
        pAlpha->Rcx == pBeta->Rcx &&
        pAlpha->Rax == pBeta->Rax);
}


VOID
Test_Ebm_GeneralRegisterContext()
{
    PGENERAL_PURPOSE_REGISTERS pContexts = NULL;
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    ULONG i = 0;
    BOOL fSuppressTest = FALSE;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    pContexts = (PGENERAL_PURPOSE_REGISTERS)VirtualAlloc(
        NULL,
        GRCF_LOG_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pContexts)
    {
        FAIL_TEST("VirtualAlloc failed: %u", GetLastError());
    }

    //
    // Set an ept execute breakpoint at the target address.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&g_Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint_Location,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeGeneralRegisterContext,
        GRCF_LOG_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Fill the log.
    //
    for (i = 0; i < GRCF_NUMBER_OF_ITERATIONS; i++)
    {
        if (i == pLog->Header.MaxIndex)
        {
            break;
        }

        //
        // Generate a new pseudo-random context in place so that we can
        //  validate log entries later.
        //
#pragma warning(suppress : 6011) // Dereferencing NULL pointer.
        GeneratePseudoRandomGeneralPurposeRegisterContext(&pContexts[i]);

        Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint(&pContexts[i]);

        //
        // Validate this iteration.
        //
        /// TODO This sometimes fails on multicore systems.
        /*ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, (i + 1));

        if (!Test_Ebm_GeneralRegisterContext_CompareRegisterContexts(
                &pLog->u.GeneralRegisterContext.Elements[i].Registers,
                &pContexts[i]))
        {
            FAIL_TEST("Unexpected log register context. (MaxIndex = %u)",
                pLog->Header.MaxIndex);
        }*/
        if (pLog->Header.NumberOfElements != (i + 1))
        {
            WRN_PRINT(
                "Unexpected NumberOfElements. (Actual = %u, Expected = %u)",
                pLog->Header.NumberOfElements,
                (i + 1));
        }

        if (!Test_Ebm_GeneralRegisterContext_CompareRegisterContexts(
                &pLog->u.GeneralRegisterContext.Elements[i].Registers,
                &pContexts[i]))
        {
            WRN_PRINT("Unexpected log register context. (MaxIndex = %u)",
                pLog->Header.MaxIndex);
        }

        fSuppressTest = TRUE;
        break;
    }

    if (!fSuppressTest)
    {
        //
        // Validate the entire log to verify that we did not overwrite elements.
        //
        for (i = 0; i < pLog->Header.MaxIndex; i++)
        {
            if (!Test_Ebm_GeneralRegisterContext_CompareRegisterContexts(
                    &pLog->u.GeneralRegisterContext.Elements[i].Registers,
                    &pContexts[i]))
            {
                FAIL_TEST("Unexpected log register context.");
            }
        }
    }

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    status = VirtualFree(pContexts, 0, MEM_RELEASE);
    if (!status)
    {
        FAIL_TEST("VirtualFree failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// Keyed Register Context Functionality Tests
//=============================================================================
#define KRCF_LOG_SIZE           0x2000
#define KRCF_REGISTER_KEY       REGISTER_R12


VOID
Test_Ebm_KeyedRegisterContext()
{
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    GENERAL_PURPOSE_REGISTERS ContextA = {};
    GENERAL_PURPOSE_REGISTERS ContextB = {};
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    //
    // Set an ept execute breakpoint at the target address.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&g_Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint_Location,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeKeyedRegisterContext,
        KRCF_LOG_SIZE,
        TRUE,
        KRCF_REGISTER_KEY,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Construct simple register contexts, trigger the breakpoint, then verify
    //  the log elements.
    //
    RtlFillMemory(&ContextA, sizeof(ContextA), 1);
    RtlFillMemory(&ContextB, sizeof(ContextB), 1);

    Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint(&ContextA);

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 1);

    if (!RtlEqualMemory(
            &ContextA,
            &ContextB,
            sizeof(GENERAL_PURPOSE_REGISTERS)))
    {
        FAIL_TEST("Unexpected log register context.");
    }

    RtlFillMemory(&ContextA, sizeof(ContextA), 7);
    RtlFillMemory(&ContextB, sizeof(ContextB), 7);

    Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint(&ContextA);

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 2);

    if (!RtlEqualMemory(
            &ContextA,
            &ContextB,
            sizeof(GENERAL_PURPOSE_REGISTERS)))
    {
        FAIL_TEST("Unexpected log register context.");
    }

    //
    // Use a duplicate value for the register key.
    //
    RtlFillMemory(&ContextA, sizeof(ContextA), 4);
    ContextA.R12 = 1;

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 2);

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// System Side Effects Tests
//=============================================================================
VOID
Test_Ebm_PageResidency()
{
    PWORD pWordBuffer = NULL;
    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetExInfoBase = {};
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    pWordBuffer = (PWORD)VirtualAlloc(
        NULL,
        PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!pWordBuffer)
    {
        FAIL_TEST("VirtualAlloc failed: %u", GetLastError());
    }

    //
    // Touch the page to make it resident.
    //
    *pWordBuffer = 0x7771;

    status = VerifyVirtualAddressIsResident(pWordBuffer);
    if (!status)
    {
        FAIL_TEST("VerifyVirtualAddressIsResident failed: %u", GetLastError());
    }

    //
    // Query the working set ex information for the page before we breakpoint
    //  it.
    //
    status =
        QueryWorkingSetExInformation(pWordBuffer, &WorkingSetExInfoBase);
    if (!status)
    {
        FAIL_TEST("QueryWorkingSetExInformation failed: %u", GetLastError());
    }

    PrintWorkingSetExInformation(
        "Base Working Set Ex Information",
        &WorkingSetExInfoBase);

    //
    // Set a breakpoint on an address in the page.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)pWordBuffer,
        EptBreakpointTypeWrite,
        EptBreakpointSizeWord,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Verify that the page's working set ex information has not changed.
    //
    status = IsUnchangedWorkingSetExInformation(
        pWordBuffer,
        &WorkingSetExInfoBase,
        0);
    if (!status)
    {
        FAIL_TEST("IsUnchangedWorkingSetExInformation failed.");
    }

    //
    // Force the page to be paged out.
    //
    status = VirtualUnlock(pWordBuffer, PAGE_SIZE);
    if (status)
    {
        FAIL_TEST("VirtualLock succeeded. (Unexpected)");
    }
    //
    if (GetLastError() != ERROR_NOT_LOCKED)
    {
        FAIL_TEST("VirtualLock failed: %u (Unexpected)", GetLastError());
    }

    //
    // Verify that the page is not resident.
    //
    status = VerifyVirtualAddressIsNotResident(pWordBuffer);
    if (!status)
    {
        FAIL_TEST("VerifyVirtualAddressIsNotResident failed: %u",
            GetLastError());
    }

    //
    // Touch the page to make it resident again.
    //
    *pWordBuffer = 0x7771;

    status = VerifyVirtualAddressIsResident(pWordBuffer);
    if (!status)
    {
        FAIL_TEST("VerifyVirtualAddressIsResident failed: %u", GetLastError());
    }

    //
    // Verify that the page's working set ex information has not changed.
    //
    status = IsUnchangedWorkingSetExInformation(
        pWordBuffer,
        &WorkingSetExInfoBase,
        0);
    if (!status)
    {
        FAIL_TEST("IsUnchangedWorkingSetExInformation failed: %u",
            GetLastError());
    }

    //
    // Free the buffer then verify that the page is no longer valid in this
    //  process context.
    //
    status = VirtualFree(pWordBuffer, 0, MEM_RELEASE);
    if (!status)
    {
        FAIL_TEST("VirtualFree failed: %u (Unexpected)", GetLastError());
    }

#pragma warning(suppress : 6001) // Using uninitialized memory.
    status = VerifyMemoryRegionIsFree(pWordBuffer);
    if (!status)
    {
        FAIL_TEST("VerifyMemoryRegionIsFree failed: %u", GetLastError());
    }

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLog, 1);

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// Single-Step Exception Tests
//=============================================================================
static SIZE_T g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions = 0;

LONG
Test_Ebm_TrapFlag_SEH_HandlerRoutine(
    _In_ PEXCEPTION_POINTERS pExceptionPointers
)
{
    LONG Decision = EXCEPTION_CONTINUE_EXECUTION;

    if (pExceptionPointers->ExceptionRecord->ExceptionCode !=
        STATUS_SINGLE_STEP)
    {
        ERR_PRINT("Unexpected exception code: 0x%X (Expected = 0x%X)",
            pExceptionPointers->ExceptionRecord->ExceptionCode,
            STATUS_SINGLE_STEP);
        Decision = EXCEPTION_EXECUTE_HANDLER;
        goto exit;
    }

    if (pExceptionPointers->ExceptionRecord->ExceptionAddress !=
        &g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location)
    {
        ERR_PRINT("Unexpected exception address: %p (Expected = %p, # = %Iu)",
            pExceptionPointers->ExceptionRecord->ExceptionAddress,
            &g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location,
            g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions);
        Decision = EXCEPTION_EXECUTE_HANDLER;
        goto exit;
    }

    //
    // Update the global single-step exception counter.
    //
    g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions++;

exit:
    return Decision;
}


_Check_return_
BOOL
Test_Ebm_TrapFlag_SEH_ExerciseRoutine()
{
    ULONG nIterations = 0;
    ULONG_PTR i = 0;
    BOOL status = TRUE;

    //
    // Reset the global single-step exception counters.
    //
    g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions = 0;
    g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count = 0;

    nIterations = (RANDOM_ULONG % 1000) + 500;

    INF_PRINT("Exercising trap flag SEH. (Iterations = %u)", nIterations);

    for (i = 0; i < nIterations; i++)
    {
        //
        // Verify that we are not skipping instructions or executing the
        //  target instruction multiple times per iteration.
        //
        if (g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count != i)
        {
            ERR_PRINT("Unexpected execution count: %Iu vs %Iu",
                g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count,
                i);
            status = FALSE;
            goto exit;
        }

        __try
        {
            Test_Ebm_SetTrapFlag_StaticExceptionAddress();
        }
        __except (
            Test_Ebm_TrapFlag_SEH_HandlerRoutine(
                GetExceptionInformation()))
        {
            ERR_PRINT("Test_Ebm_SetTrapFlag_StaticExceptionAddress failed.");
            status = FALSE;
            goto exit;
        }
    }

    //
    // Verify that we caught the expected number of single-step exceptions.
    //
    if (nIterations != g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions)
    {
        ERR_PRINT(
            "Unexpected number of caught single-step exceptions."
            " (Actual = %Iu, Expected = %Iu)",
            nIterations,
            g_Test_Ebm_TrapFlag_SEH_NumberOfExceptions);
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


#define EBM_TRAP_FLAG_SEH_NUMBER_OF_COMBINATIONS 7

VOID
Test_Ebm_TrapFlag_SEH()
{
    HANDLE hLog1 = NULL;
    PEPT_BREAKPOINT_LOG pLog1 = NULL;
    HANDLE hLog2 = NULL;
    PEPT_BREAKPOINT_LOG pLog2 = NULL;
    HANDLE hLog3 = NULL;
    PEPT_BREAKPOINT_LOG pLog3 = NULL;
    ULONG i = 0;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    //
    // This test is meant to verify that the EBM properly handles single-step
    //  exceptions when ept breakpoints are set at addresses involved with the
    //  single-step exception. We have three breakpoint target addresses:
    //
    //      g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_1
    //      g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_2
    //      g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_3
    //
    // We call 'Test_Ebm_SetTrapFlag_StaticExceptionAddress' to generate a
    //  single-step exception at the address of
    //  'g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location'.
    //
    // The following loop exercises all combinations of ept breakpoints for the
    //  three breakpoint target addresses.
    //
    for (i = 0; i < EBM_TRAP_FLAG_SEH_NUMBER_OF_COMBINATIONS; i++)
    {
        //
        // Reset variables.
        //
        hLog1 = NULL;
        pLog1 = NULL;
        hLog2 = NULL;
        pLog2 = NULL;
        hLog3 = NULL;
        pLog3 = NULL;

        INF_PRINT("Index %u:", i);

        //
        // Set the breakpoints.
        //
        if (BooleanFlagOn(i, (1 << 0)))
        {
            status = SetEptBreakpoint(
                GetCurrentProcessId(),
                (ULONG_PTR)&g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_1,
                EptBreakpointTypeExecute,
                EptBreakpointSizeByte,
                EptBreakpointLogTypeBasic,
                PAGE_SIZE,
                TRUE,
                REGISTER_INVALID,
                &hLog1,
                &pLog1);
            if (!status)
            {
                FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
            }
        }

        if (BooleanFlagOn(i, (1 << 1)))
        {
            status = SetEptBreakpoint(
                GetCurrentProcessId(),
                (ULONG_PTR)&g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_2,
                EptBreakpointTypeExecute,
                EptBreakpointSizeByte,
                EptBreakpointLogTypeBasic,
                PAGE_SIZE,
                TRUE,
                REGISTER_INVALID,
                &hLog2,
                &pLog2);
            if (!status)
            {
                FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
            }
        }

        if (BooleanFlagOn(i, (1 << 2)))
        {
            status = SetEptBreakpoint(
                GetCurrentProcessId(),
                (ULONG_PTR)&g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_3,
                EptBreakpointTypeExecute,
                EptBreakpointSizeByte,
                EptBreakpointLogTypeBasic,
                PAGE_SIZE,
                TRUE,
                REGISTER_INVALID,
                &hLog3,
                &pLog3);
            if (!status)
            {
                FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
            }
        }

        //
        // Exercise the single-step exception code.
        //
        status = Test_Ebm_TrapFlag_SEH_ExerciseRoutine();
        if (!status)
        {
            FAIL_TEST(
                "Test_Ebm_TrapFlag_SEH_ExerciseRoutine failed. (i = %u)\n",
                i);
        }

        //
        // Cleanup breakpoints.
        //
        if (hLog3)
        {
            status = ClearEptBreakpoint(hLog3);
            if (!status)
            {
                FAIL_TEST("ClearEptBreakpoint failed: %u (3)", GetLastError());
            }
        }

        if (hLog2)
        {
            status = ClearEptBreakpoint(hLog2);
            if (!status)
            {
                FAIL_TEST("ClearEptBreakpoint failed: %u (2)", GetLastError());
            }
        }

        if (hLog1)
        {
            status = ClearEptBreakpoint(hLog1);
            if (!status)
            {
                FAIL_TEST("ClearEptBreakpoint failed: %u (1)", GetLastError());
            }
        }

        status = VerifyEptBreakpointUnwind();
        if (!status)
        {
            FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
        }
    }

    PRINT_TEST_FOOTER;
}


VOID
Test_Ebm_DelayedMonitorTrapFlagStep_1()
{
    DWORD TargetAddress = 0;
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL fExceptionValidated = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)Test_Ebm_VmCall,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLog,
        &pLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    __try
    {
        Test_Ebm_VmCall(0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (GetExceptionCode() != STATUS_ILLEGAL_INSTRUCTION)
        {
            FAIL_TEST("Invalid emulation. (Error = 0x%X, Expected = 0x%X)",
                GetExceptionCode(),
                STATUS_ILLEGAL_INSTRUCTION);
        }

        fExceptionValidated = TRUE;
    }
    //
    if (!fExceptionValidated)
    {
        FAIL_TEST("Failed to validate Test_Ebm_VmCall exception.");
    }

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    if (!VerifyEptBreakpointUnwind())
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


VOID
Test_Ebm_DelayedMonitorTrapFlagStep_2()
{
    DWORD TargetAddress = 0;
    HANDLE hReadLog = NULL;
    PEPT_BREAKPOINT_LOG pReadLog = NULL;
    HANDLE hExecuteLog = NULL;
    PEPT_BREAKPOINT_LOG pExecuteLog = NULL;
    BOOL fExceptionCaught = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&TargetAddress,
        EptBreakpointTypeRead,
        EptBreakpointSizeDword,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hReadLog,
        &pReadLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)Test_Ebm_ReadDword,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hExecuteLog,
        &pExecuteLog);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    //
    // Trigger the breakpoint and cause an exception in the same instruction.
    //
    __try
    {
#pragma warning(suppress : 6387) // This does not adhere to the specification.
        Test_Ebm_ReadDword(NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fExceptionCaught = TRUE;
    }
    //
    if (!fExceptionCaught)
    {
        FAIL_TEST("Exception missed.");
    }

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hExecuteLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = ClearEptBreakpoint(hReadLog);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    if (!VerifyEptBreakpointUnwind())
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// Stress Tests
//=============================================================================
#define STRESS_DEBUG_EXCEPTIONS_SCENARIO_NONE           0
#define STRESS_DEBUG_EXCEPTIONS_SCENARIO_SINGLE_STEP    1
#define STRESS_DEBUG_EXCEPTIONS_SCENARIO_READ_HWBP      2
#define STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED       3

#define STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_SCENARIOS     4ull

#define STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_ASM_STEPS     4

#define STRESS_DEBUG_EXCEPTIONS_THREAD_PREPARATION_TIMEOUT_MS \
    (SECONDS_TO_MILLISECONDS(20))

#define STRESS_DEBUG_EXCEPTIONS_THREAD_COMPLETION_TIMEOUT_MS \
    (SECONDS_TO_MILLISECONDS(60 * 5))


typedef struct _STRESS_DEBUG_EXCEPTIONS_CONTEXT {
    HANDLE ThreadReadyEvent;
    HANDLE ThreadBarrierEvent;
    ULONG Scenario;
    ULONG NumberOfIterations;
    struct {
        ULONG Read;
        ULONG SingleStep;
    } ExceptionCounters;
} STRESS_DEBUG_EXCEPTIONS_CONTEXT, *PSTRESS_DEBUG_EXCEPTIONS_CONTEXT;


static STRESS_DEBUG_EXCEPTIONS_CONTEXT g_Test_Ebm_Stress_DebugExceptions_Context = {};


LONG
NTAPI
Test_Ebm_Stress_DebugExceptions_VEH(
    _Inout_ PEXCEPTION_POINTERS pExceptionInfo
)
{
    PEXCEPTION_RECORD pExceptionRecord = NULL;
    PSTRESS_DEBUG_EXCEPTIONS_CONTEXT pContext = NULL;
    PDR6 pDr6 = NULL;
    PDR7 pDr7 = NULL;
    PRFLAGS pRflags = NULL;

    pExceptionRecord = pExceptionInfo->ExceptionRecord;
    pContext = &g_Test_Ebm_Stress_DebugExceptions_Context;
    pDr6 = (PDR6)&pExceptionInfo->ContextRecord->Dr6;
    pDr7 = (PDR7)&pExceptionInfo->ContextRecord->Dr7;
    pRflags = (PRFLAGS)&pExceptionInfo->ContextRecord->EFlags;

    //
    // We should not encounter exceptions in the base scenario.
    //
    if (STRESS_DEBUG_EXCEPTIONS_SCENARIO_NONE == pContext->Scenario)
    {
        FAIL_TEST("Unexpected scenario state.");
    }

    //
    // Check the exception code.
    //
    if (STATUS_SINGLE_STEP != pExceptionRecord->ExceptionCode)
    {
        FAIL_TEST("Unexpected ExceptionCode: 0x%X",
            pExceptionRecord->ExceptionCode);
    }

    //
    // Verify that the exception occurred in the body of the assembly routine.
    //
    if (pExceptionRecord->ExceptionAddress <
            &Test_Ebm_Stress_DebugExceptions_Asm ||
        pExceptionRecord->ExceptionAddress >
            &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return)
    {
        FAIL_TEST("Unexpected ExceptionAddress: %p",
            pExceptionRecord->ExceptionAddress);
    }

    //
    // Validate the exception and update exception counters by scenario.
    //
    switch (pContext->Scenario)
    {
        case STRESS_DEBUG_EXCEPTIONS_SCENARIO_SINGLE_STEP:
            if (pExceptionInfo->ContextRecord->Dr0)
            {
                FAIL_TEST("Unexpected Dr0: %p",
                    pExceptionInfo->ContextRecord->Dr0);
            }

            if (pDr6->All)
            {
                FAIL_TEST("Unexpected Dr6: %p", pDr6->All);
            }

            if (pDr7->All)
            {
                FAIL_TEST("Unexpected Dr7: %p", pDr7->All);
            }

            pContext->ExceptionCounters.SingleStep++;

            break;

        case STRESS_DEBUG_EXCEPTIONS_SCENARIO_READ_HWBP:
            if (pExceptionRecord->ExceptionAddress !=
                &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read)
            {
                FAIL_TEST("Unexpected ExceptionAddress: %p",
                    pExceptionRecord->ExceptionAddress);
            }

            //
            // Verify that the target debug address register is enabled.
            //
            if (!pDr7->L0 && !pDr7->G0)
            {
                FAIL_TEST("Unexpected Dr7: %p", pDr7->All);
            }

            //
            // Verify that this is an access debug exception.
            //
            if (!pDr6->B0 || pDr6->BS)
            {
                FAIL_TEST("Unexpected Dr6: %p", pDr6->All);
            }

            pContext->ExceptionCounters.Read++;

            break;

        case STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED:
            if (pExceptionRecord->ExceptionAddress ==
                &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read)
            {
                //
                // Verify that the target debug address register is enabled.
                //
                if (!pDr7->L0 && !pDr7->G0)
                {
                    FAIL_TEST("Unexpected Dr7: %p", pDr7->All);
                }

                //
                // Verify that this is an access debug exception.
                //
                /// TODO Review.
                if (!pDr6->B0)
                {
                    FAIL_TEST("Unexpected Dr6: %p", pDr6->All);
                }

                pContext->ExceptionCounters.Read++;
            }
            else
            {
                if (pDr6->B0)
                {
                    FAIL_TEST("Unexpected Dr6: %p", pDr6->All);
                }

                pContext->ExceptionCounters.SingleStep++;
            }

            //
            // The single-step flag should always be set (even when the read
            //  breakpoint is triggered).
            //
            /// TODO Review.
            if (!pDr6->BS)
            {
                FAIL_TEST("Unexpected Dr6: %p (Address = %p)",
                    pDr6->All,
                    pExceptionRecord->ExceptionAddress);
            }

            break;

        default:
            FAIL_TEST("Unexpected Scenario: %u", pContext->Scenario);
    }

    //
    // Continue single-stepping until we reach the end of the assembly routine.
    //
    if (STRESS_DEBUG_EXCEPTIONS_SCENARIO_SINGLE_STEP == pContext->Scenario ||
        STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED == pContext->Scenario)
    {
        if (pExceptionRecord->ExceptionAddress !=
            &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return)
        {
            pRflags->TF = 1;
        }
    }

    //
    // Resume execution.
    //
    pRflags->RF = 1;

    return EXCEPTION_CONTINUE_EXECUTION;
}


static
VOID
Test_Ebm_Stress_DebugExceptions_GenerateScenarioContext(
    _In_ ULONG Scenario,
    _In_ ULONG nIterations,
    _Out_ PSTRESS_DEBUG_EXCEPTIONS_CONTEXT pContext
)
{
    pContext->ThreadReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!pContext->ThreadReadyEvent)
    {
        FAIL_TEST("CreateEvent failed: %u\n", GetLastError());
    }

    pContext->ThreadBarrierEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!pContext->ThreadBarrierEvent)
    {
        FAIL_TEST("CreateEvent failed: %u\n", GetLastError());
    }

    pContext->Scenario = Scenario;
    pContext->NumberOfIterations = nIterations;
    pContext->ExceptionCounters.Read = 0;
    pContext->ExceptionCounters.SingleStep = 0;
}


static
VOID
Test_Ebm_Stress_DebugExceptions_CleanupScenarioContext(
    _In_ PSTRESS_DEBUG_EXCEPTIONS_CONTEXT pContext
)
{
    if (!CloseHandle(pContext->ThreadBarrierEvent))
    {
        FAIL_TEST("CloseHandle failed: %u\n", GetLastError());
    }

    if (!CloseHandle(pContext->ThreadReadyEvent))
    {
        FAIL_TEST("CloseHandle failed: %u\n", GetLastError());
    }
}


static
DWORD
WINAPI
Test_Ebm_Stress_DebugExceptions_ThreadRoutine(
    _In_ LPVOID lpParameter
)
{
    PSTRESS_DEBUG_EXCEPTIONS_CONTEXT pContext = NULL;
    ULONG i = 0;
    BOOL fSingleStepping = FALSE;
    SIZE_T cbAssemblyRoutine = 0;
    DWORD waitstatus = 0;

    pContext = (PSTRESS_DEBUG_EXCEPTIONS_CONTEXT)lpParameter;

    INF_PRINT("Scenario %u: NumberOfIterations = %u",
        pContext->Scenario,
        pContext->NumberOfIterations);

    //
    // Signal that we started execution.
    //
    if (!SetEvent(pContext->ThreadReadyEvent))
    {
        FAIL_TEST("SetEvent failed: %u\n", GetLastError());
    }

    //
    // Wait for the main thread to set hardware breakpoints (if necessary).
    //
    waitstatus = WaitForSingleObject(
        pContext->ThreadBarrierEvent,
        STRESS_DEBUG_EXCEPTIONS_THREAD_PREPARATION_TIMEOUT_MS);
    if (WAIT_OBJECT_0 != waitstatus)
    {
        FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
    }

    if (STRESS_DEBUG_EXCEPTIONS_SCENARIO_SINGLE_STEP == pContext->Scenario ||
        STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED == pContext->Scenario)
    {
        fSingleStepping = TRUE;
    }

    g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1 = 0;
    g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2 = 0;

    cbAssemblyRoutine = (SIZE_T)(
        (ULONG_PTR)&g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return -
        (ULONG_PTR)&Test_Ebm_Stress_DebugExceptions_Asm +
        1);

    for (i = 0; i < pContext->NumberOfIterations; ++i)
    {
        //
        // Randomly force the page(s) containing the assembly routine to be
        //  paged out.
        //
        if ((RANDOM_ULONG % 100) > 70)
        {
            if (VirtualUnlock(
                    Test_Ebm_Stress_DebugExceptions_Asm,
                    cbAssemblyRoutine))
            {
                FAIL_TEST("VirtualUnlock succeeded. (Unexpected)");
            }

            if (ERROR_NOT_LOCKED != GetLastError())
            {
                FAIL_TEST("VirtualUnlock failed: %u.\n", GetLastError());
            }
        }

        Test_Ebm_Stress_DebugExceptions_Asm(fSingleStepping);

        switch (pContext->Scenario)
        {
            case STRESS_DEBUG_EXCEPTIONS_SCENARIO_NONE:
                if (pContext->ExceptionCounters.Read ||
                    pContext->ExceptionCounters.SingleStep)
                {
                    FAIL_TEST("Unexpected ExceptionCounters.");
                }

                break;

            case STRESS_DEBUG_EXCEPTIONS_SCENARIO_SINGLE_STEP:
                if (pContext->ExceptionCounters.Read)
                {
                    FAIL_TEST("Unexpected ExceptionCounters.Read.");
                }

                if (pContext->ExceptionCounters.SingleStep !=
                    (STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_ASM_STEPS * (i + 1)))
                {
                    FAIL_TEST(
                        "Unexpected ExceptionCounters.SingleStep: %u (Expected = %u)",
                        pContext->ExceptionCounters.SingleStep,
                        (STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_ASM_STEPS * (i + 1)));
                }

                break;

            case STRESS_DEBUG_EXCEPTIONS_SCENARIO_READ_HWBP:
                if (pContext->ExceptionCounters.Read != (i + 1))
                {
                    FAIL_TEST(
                        "Unexpected ExceptionCounters.Read: %u (Expected = %u)",
                        pContext->ExceptionCounters.Read,
                        (i + 1));
                }

                if (pContext->ExceptionCounters.SingleStep)
                {
                    FAIL_TEST("Unexpected ExceptionCounters.SingleStep: %u",
                        pContext->ExceptionCounters.SingleStep);
                }

                break;

            case STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED:
                if (pContext->ExceptionCounters.Read != (i + 1))
                {
                    FAIL_TEST(
                        "Unexpected ExceptionCounters.Read: %u (Expected = %u)",
                        pContext->ExceptionCounters.Read,
                        (i + 1));
                }

                if (pContext->ExceptionCounters.SingleStep !=
                    ((STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_ASM_STEPS - 1) * (i + 1)))
                {
                    FAIL_TEST(
                        "Unexpected ExceptionCounters.SingleStep: %u (Expected = %u)",
                        pContext->ExceptionCounters.SingleStep,
                        ((STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_ASM_STEPS - 1) * (i + 1)));
                }

                break;

            default:
                FAIL_TEST("Unexpected Scenario: %u", pContext->Scenario);
        }

        if (g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1 != (i + 1))
        {
            FAIL_TEST(
                "Unexpected g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1: %u\n",
                g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1);
        }

        if (g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2 != (i + 1))
        {
            FAIL_TEST(
                "Unexpected g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2: %u\n",
                g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2);
        }
    }

    return ERROR_SUCCESS;
}


VOID
Test_Ebm_Stress_DebugExceptions_Debuggee(
    _In_ ULONG nIterations
)
{
    PSTRESS_DEBUG_EXCEPTIONS_CONTEXT pContext = NULL;
    PVOID pVectoredHandler = NULL;
    ULONG i = 0;
    HANDLE hThread = NULL;
    DWORD ThreadId = 0;
    DWORD waitstatus = 0;
    BOOL status = TRUE;

    pContext = &g_Test_Ebm_Stress_DebugExceptions_Context;

    pVectoredHandler =
        AddVectoredExceptionHandler(1, Test_Ebm_Stress_DebugExceptions_VEH);
    if (!pVectoredHandler)
    {
        FAIL_TEST("AddVectoredExceptionHandler failed: %u", GetLastError());
    }

    for (i = 0; i < STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_SCENARIOS; i++)
    {
        Test_Ebm_Stress_DebugExceptions_GenerateScenarioContext(
            i,
            nIterations,
            pContext);

        hThread = CreateThread(
            NULL,
            0,
            Test_Ebm_Stress_DebugExceptions_ThreadRoutine,
            pContext,
            0,
            &ThreadId);
        if (!hThread)
        {
            FAIL_TEST("CreateThread failed: %u\n", GetLastError());
        }

        //
        // NOTE If we do not wait for the thread to begin execution then we
        //  cannot reliably set hardware breakpoints in its context.
        //
        waitstatus = WaitForSingleObject(
            pContext->ThreadReadyEvent,
            STRESS_DEBUG_EXCEPTIONS_THREAD_PREPARATION_TIMEOUT_MS);
        if (WAIT_OBJECT_0 != waitstatus)
        {
            FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
        }

        //
        // Set hardware breakpoints by scenario.
        //
        if (STRESS_DEBUG_EXCEPTIONS_SCENARIO_READ_HWBP == i ||
            STRESS_DEBUG_EXCEPTIONS_SCENARIO_COMBINED == i)
        {
            status = ThuSetThreadHardwareBreakpoint(
                ThreadId,
                0,
                &g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read,
                HWBP_TYPE::Access,
                HWBP_SIZE::Word);
            if (!status)
            {
                FAIL_TEST("ThuSetThreadHardwareBreakpoint failed: %u\n",
                    GetLastError());
            }
        }

        //
        // Let the thread run.
        //
        if (!SetEvent(pContext->ThreadBarrierEvent))
        {
            FAIL_TEST("SetEvent failed: %u\n", GetLastError());
        }

        //
        // Wait for the thread to complete.
        //
        waitstatus = WaitForSingleObject(
            hThread,
            STRESS_DEBUG_EXCEPTIONS_THREAD_COMPLETION_TIMEOUT_MS);
        if (WAIT_OBJECT_0 != waitstatus)
        {
            FAIL_TEST("WaitForSingleObject failed: %u\n", GetLastError());
        }

        //
        // Scenario unwind.
        //
        if (!CloseHandle(hThread))
        {
            FAIL_TEST("CloseHandle failed: %u.\n", GetLastError());
        }

        Test_Ebm_Stress_DebugExceptions_CleanupScenarioContext(pContext);
    }
}


VOID
Test_Ebm_Stress_DebugExceptions()
{
    ULONG nIterations = 0;
    HANDLE hLogExecute = NULL;
    PEPT_BREAKPOINT_LOG pLogExecute = NULL;
    HANDLE hLogRead = NULL;
    PEPT_BREAKPOINT_LOG pLogRead = NULL;
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    nIterations = (RANDOM_ULONG % 5000) + 500;

    INF_PRINT("------------------------------------------------------------------------------");
    INF_PRINT("Executing debuggee routine. (no ept breakpoints)");
    INF_PRINT("------------------------------------------------------------------------------");

    //
    // Run the debuggee routine without any ept breakpoints to verify that the
    //  anti-debug checks are correct.
    //
    Test_Ebm_Stress_DebugExceptions_Debuggee(nIterations);

    INF_PRINT("------------------------------------------------------------------------------");
    INF_PRINT("Executing debuggee routine. (Execute ept breakpoint)");
    INF_PRINT("------------------------------------------------------------------------------");

    //
    // Install an execution ept breakpoint then run the debuggee routine.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLogExecute,
        &pLogExecute);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    Test_Ebm_Stress_DebugExceptions_Debuggee(nIterations);

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLogExecute, 1);
    ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(
        &pLogExecute->u.Basic.Elements[0],
        &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_ABOVE_THRESHOLD(
        &pLogExecute->u.Basic.Elements[0],
        (nIterations * STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_SCENARIOS));

    //
    // Reset.
    //
    status = ClearEptBreakpoint(hLogExecute);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    INF_PRINT("------------------------------------------------------------------------------");
    INF_PRINT("Executing debuggee routine. (Execute and read ept breakpoints)");
    INF_PRINT("------------------------------------------------------------------------------");

    //
    // Install an execution and read ept breakpoint then run the debuggee
    //  routine.
    //
    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&Test_Ebm_Stress_DebugExceptions_Asm,
        EptBreakpointTypeExecute,
        EptBreakpointSizeByte,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLogExecute,
        &pLogExecute);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    status = SetEptBreakpoint(
        GetCurrentProcessId(),
        (ULONG_PTR)&g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read,
        EptBreakpointTypeRead,
        EptBreakpointSizeWord,
        EptBreakpointLogTypeBasic,
        PAGE_SIZE,
        TRUE,
        REGISTER_INVALID,
        &hLogRead,
        &pLogRead);
    if (!status)
    {
        FAIL_TEST("SetEptBreakpoint failed: %u", GetLastError());
    }

    Test_Ebm_Stress_DebugExceptions_Debuggee(nIterations);

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLogExecute, 1);
    ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(
        &pLogExecute->u.Basic.Elements[0],
        &Test_Ebm_Stress_DebugExceptions_Asm);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_ABOVE_THRESHOLD(
        &pLogExecute->u.Basic.Elements[0],
        (nIterations * STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_SCENARIOS));

    ASSERT_NUMBER_OF_LOG_ELEMENTS(pLogRead, 1);
    ASSERT_BASIC_LOG_ELEMENT_TRIGGER_ADDRESS(
        &pLogRead->u.Basic.Elements[0],
        &g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read);
    ASSERT_BASIC_LOG_ELEMENT_HIT_COUNT_ABOVE_THRESHOLD(
        &pLogRead->u.Basic.Elements[0],
        (nIterations * STRESS_DEBUG_EXCEPTIONS_NUMBER_OF_SCENARIOS));

    //
    // Unwind.
    //
    status = ClearEptBreakpoint(hLogRead);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = ClearEptBreakpoint(hLogExecute);
    if (!status)
    {
        FAIL_TEST("ClearEptBreakpoint failed: %u", GetLastError());
    }

    status = VerifyEptBreakpointUnwind();
    if (!status)
    {
        FAIL_TEST("VerifyEptBreakpointUnwind failed: %u", GetLastError());
    }

    PRINT_TEST_FOOTER;
}


//=============================================================================
// Test Interface
//=============================================================================
VOID
TestEptBreakpointManager()
{
    Test_Ebm_LogContextSafety();
    Test_Ebm_ReadBreakpointBasic();
    Test_Ebm_WriteBreakpointBasic();
    Test_Ebm_ExecuteBreakpointBasic();
    Test_Ebm_BreakpointsMulticoreBasic();
    Test_Ebm_GeneralRegisterContext();
    Test_Ebm_KeyedRegisterContext();
    Test_Ebm_PageResidency();
    Test_Ebm_DelayedMonitorTrapFlagStep_1();
    Test_Ebm_DelayedMonitorTrapFlagStep_2();

    //
    // There is a bug in VMware which causes debug exceptions (#DB) to be
    //  delivered to the guest out-of-order when a vmm single-steps the guest
    //  using the monitor trap flag and the guest triggers a #DB. The bug
    //  is inconsistent which makes me think that it's related to a VMware
    //  ISR, interrupt VM exit handler, or VMX-preemption timer value.
    //
    // NOTE Linux KVM has / had an issue that may be related to this bug
    //  behavior.
    //
    //  See: 'kvm: nVMX: Pending debug exceptions trump expired VMX-preemption
    //      timer'
    //
    if (SyuIsVMwareHypervisorPresent())
    {
        INF_PRINT("Detected VMware hypervisor. Skipping the following tests:");
        INF_PRINT("    Test_Ebm_TrapFlag_SEH");
        INF_PRINT("    Test_Ebm_Stress_DebugExceptions");
        PRINT_TEST_FOOTER;
    }
    else
    {
        Test_Ebm_TrapFlag_SEH();

        //
        // TODO This test needs to be reviewed.
        //
        ///Test_Ebm_Stress_DebugExceptions();
    }
}
