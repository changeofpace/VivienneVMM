/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "ept_breakpoint.h"

#include <intsafe.h>

#include "debug.h"
#include "driver_io.h"
#include "log.h"
#include "memory_util.h"
#include "ntdll.h"


/*++

Description:

    Queries ept breakpoint information for all active and inactive ept
    breakpoints.

Parameters:

    ppEptBreakpointInfo - Returns a pointer to an allocated buffer that
        contains ept breakpoint information.

    pcbEptBreakpointInfo - The size of the buffer returned in
        'ppEptBreakpointInfo'.

Requirements:

    On success, the caller must free the returned ept breakpoint information
    buffer by calling 'MemFreeHeap'.

--*/
_Use_decl_annotations_
BOOL
EbpQueryEptBreakpointInformation(
    PEPT_BREAKPOINT_INFORMATION* ppEptBreakpointInfo,
    PULONG pcbEptBreakpointInfo
)
{
    ULONG cbEptBreakpointInfo = 0;
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo = NULL;
    BOOL status = TRUE;

    //
    // Zero output parameters.
    //
    *ppEptBreakpointInfo = NULL;
    if (ARGUMENT_PRESENT(pcbEptBreakpointInfo))
    {
        *pcbEptBreakpointInfo = 0;
    }

    for (;;)
    {
        status =
            VivienneIoQueryEptBreakpointInformationSize(&cbEptBreakpointInfo);
        if (!status)
        {
            ERR_PRINT(
                "VivienneIoQueryEptBreakpointInformationSize failed: %u (0x%X)",
                GetLastError(),
                RtlGetLastNtStatus());
            goto exit;
        }

        if (pEptBreakpointInfo)
        {
            VERIFY(MemFreeHeap(pEptBreakpointInfo));
        }

        pEptBreakpointInfo =
            (PEPT_BREAKPOINT_INFORMATION)MemAllocateHeap(cbEptBreakpointInfo);
        if (!pEptBreakpointInfo)
        {
            ERR_PRINT("Out of memory. (0x%X bytes)", cbEptBreakpointInfo);
            status = FALSE;
            goto exit;
        }

        status = VivienneIoQueryEptBreakpointInformation(
            pEptBreakpointInfo,
            cbEptBreakpointInfo);
        if (status)
        {
            break;
        }
        else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            ERR_PRINT(
                "VivienneIoQueryEptBreakpointInformation failed: %u (0x%X)",
                GetLastError(),
                RtlGetLastNtStatus());
            goto exit;
        }
    }

    //
    // Set output parameters.
    //
    *ppEptBreakpointInfo = pEptBreakpointInfo;
    if (ARGUMENT_PRESENT(pcbEptBreakpointInfo))
    {
        *pcbEptBreakpointInfo = cbEptBreakpointInfo;
    }

exit:
    if (!status)
    {
        if (pEptBreakpointInfo)
        {
            VERIFY(MemFreeHeap(pEptBreakpointInfo));
        }
    }

    return status;
}


/*++

Description:

    The common set-ept-breakpoint routine for all ept breakpoint log types.

Parameters:

    ProcessId - The target process of the ept breakpoint.

    Address - The target virtual address of the ept breakpoint.

    BreakpointType - The breakpoint type of the ept breakpoint.

    BreakpointSize - The breakpoint size of the ept breakpoint.

    LogType - The log type of the ept breakpoint.

    cbLog - The size in bytes of the ept breakpoint log.

    fMakePageResident - If TRUE then the page containing the target virtual
        address is made resident (if it is currently paged out) then locked in
        memory. If FALSE then this routine fails if the target page is not
        resident in memory.

    RegisterKey - If 'LogType' is 'EptBreakpointLogTypeKeyedRegisterContext'
        then this parameter specifies which register is used to determine the
        uniqueness of a guest context when the corresponding ept breakpoint is
        triggered.

    phLog - Returns the unique identifier for the installed ept breakpoint.

    ppLog - Returns a pointer to the ept breakpoint log.

Requirements:

    On success, the caller must clear the ept breakpoint by calling
    'EbpClearEptBreakpoint'.

--*/
_Success_(return != FALSE)
_Check_return_
static
BOOL
EbppSetEptBreakpoint(
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
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    //
    // Zero output parameters.
    //
    *phLog = NULL;
    *ppLog = NULL;

    //
    // Validate input parameters.
    //
    if (!MI_RESERVED_BITS_CANONICAL((PVOID)Address))
    {
        ERR_PRINT("Non-canonical address. (Address = %p)", Address);
        status = FALSE;
        goto exit;
    }

    if (!IS_ALIGNED(Address, BreakpointSize))
    {
        ERR_PRINT(
            "Invalid breakpoint alignment. (Address = %p, BreakpointSize = %d)",
            Address,
            BreakpointSize);
        status = FALSE;
        goto exit;
    }

    if (1 != ADDRESS_AND_SIZE_TO_SPAN_PAGES(Address, BreakpointSize))
    {
        ERR_PRINT(
            "Ept breakpoint crosses page boundary. (Address = %p, BreakpointSize = %d)",
            Address,
            BreakpointSize);
        status = FALSE;
        goto exit;
    }

    if (EptBreakpointTypeRead != BreakpointType &&
        EptBreakpointTypeWrite != BreakpointType &&
        EptBreakpointTypeExecute != BreakpointType)
    {
        ERR_PRINT("Invalid BreakpointType: %d", BreakpointType);
        status = FALSE;
        goto exit;
    }

    if (EptBreakpointSizeByte != BreakpointSize &&
        EptBreakpointSizeWord != BreakpointSize &&
        EptBreakpointSizeDword != BreakpointSize &&
        EptBreakpointSizeQword != BreakpointSize)
    {
        ERR_PRINT("Invalid BreakpointSize: %d", BreakpointSize);
        status = FALSE;
        goto exit;
    }

    if (EptBreakpointTypeExecute == BreakpointType &&
        EptBreakpointSizeByte != BreakpointSize)
    {
        ERR_PRINT("Invalid execution BreakpointSize: %d", BreakpointSize);
        status = FALSE;
        goto exit;
    }

    if (EptBreakpointLogTypeBasic != LogType &&
        EptBreakpointLogTypeGeneralRegisterContext != LogType &&
        EptBreakpointLogTypeKeyedRegisterContext != LogType)
    {
        ERR_PRINT("Invalid LogType: %d", LogType);
        status = FALSE;
        goto exit;
    }

    if (EptBreakpointLogTypeKeyedRegisterContext == LogType)
    {
        switch (RegisterKey)
        {
            case REGISTER_RIP:
            case REGISTER_R15:
            case REGISTER_R14:
            case REGISTER_R13:
            case REGISTER_R12:
            case REGISTER_R11:
            case REGISTER_R10:
            case REGISTER_R9:
            case REGISTER_R8:
            case REGISTER_RDI:
            case REGISTER_RSI:
            case REGISTER_RBP:
            case REGISTER_RSP:
            case REGISTER_RBX:
            case REGISTER_RDX:
            case REGISTER_RCX:
            case REGISTER_RAX:
                break;
            default:
                ERR_PRINT("Invalid RegisterKey: %d", RegisterKey);
                status = FALSE;
                goto exit;
        }
    }

    status = VivienneIoSetEptBreakpoint(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        LogType,
        cbLog,
        fMakePageResident,
        RegisterKey,
        &hLog,
        &pLog);
    if (!status)
    {
        ERR_PRINT("VivienneIoSetEptBreakpoint failed: %u (0x%X)",
            GetLastError(),
            RtlGetLastNtStatus());
        goto exit;
    }

    //
    // Set output parameters.
    //
    *phLog = hLog;
    *ppLog = pLog;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
EbpSetEptBreakpointBasic(
    ULONG_PTR ProcessId,
    ULONG_PTR Address,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    SIZE_T cbLog,
    BOOLEAN fMakePageResident,
    PHANDLE phLog,
    PEPT_BREAKPOINT_LOG* ppLog
)
{
    return EbppSetEptBreakpoint(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        EptBreakpointLogTypeBasic,
        cbLog,
        fMakePageResident,
        (X64_REGISTER)0,
        phLog,
        ppLog);
}


_Use_decl_annotations_
BOOL
EbpSetEptBreakpointGeneralRegisterContext(
    ULONG_PTR ProcessId,
    ULONG_PTR Address,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    SIZE_T cbLog,
    BOOLEAN fMakePageResident,
    PHANDLE phLog,
    PEPT_BREAKPOINT_LOG* ppLog
)
{
    return EbppSetEptBreakpoint(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        EptBreakpointLogTypeGeneralRegisterContext,
        cbLog,
        fMakePageResident,
        (X64_REGISTER)0,
        phLog,
        ppLog);
}


_Use_decl_annotations_
BOOL
EbpSetEptBreakpointKeyedRegisterContext(
    ULONG_PTR ProcessId,
    ULONG_PTR Address,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    SIZE_T cbLog,
    BOOLEAN fMakePageResident,
    X64_REGISTER RegisterKey,
    PHANDLE phLog,
    PEPT_BREAKPOINT_LOG* ppLog
)
{
    return EbppSetEptBreakpoint(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        EptBreakpointLogTypeKeyedRegisterContext,
        cbLog,
        fMakePageResident,
        RegisterKey,
        phLog,
        ppLog);
}


/*++

Description:

    Disable an active ept breakpoint.

Parameters:

    hLog - The handle for the ept breakpoint to be disabled.

Requirements:

    Disabled breakpoints are uninstalled from all processors. The breakpoint
    log for a disabled ept breakpoint remains valid (readable) until the
    breakpoint is cleared.

--*/
_Use_decl_annotations_
BOOL
EbpDisableEptBreakpoint(
    HANDLE hLog
)
{
    BOOL status = TRUE;

    status = VivienneIoDisableEptBreakpoint(hLog);
    if (!status)
    {
        ERR_PRINT("VivienneIoDisableEptBreakpoint failed: %u (0x%X)",
            GetLastError(),
            RtlGetLastNtStatus());
        goto exit;
    }

exit:
    return status;
}


/*++

Description:

    Uninstall the target ept breakpoint from all processors and unmap the
    corresponding breakpoint log.

Parameters:

    hLog - The handle for the ept breakpoint to be cleared.

--*/
_Use_decl_annotations_
BOOL
EbpClearEptBreakpoint(
    HANDLE hLog
)
{
    BOOL status = TRUE;

    status = VivienneIoClearEptBreakpoint(hLog);
    if (!status)
    {
        ERR_PRINT("VivienneIoClearEptBreakpoint failed: %u (0x%X)",
            GetLastError(),
            RtlGetLastNtStatus());
        goto exit;
    }

exit:
    return status;
}


#define EBP_UNHANDLED_CONVERSION_CHARACTER '?'

CHAR
EbppEptBreakpointTypeToCharacter(
    _In_ EPT_BREAKPOINT_TYPE BreakpointType
)
{
    CHAR Character = NULL;

    switch (BreakpointType)
    {
        case EptBreakpointTypeRead:
            Character = 'R';
            break;

        case EptBreakpointTypeWrite:
            Character = 'W';
            break;

        case EptBreakpointTypeExecute:
            Character = 'X';
            break;

        default:
            ERR_PRINT("Unhandled BreakpointType: %d", BreakpointType);
            Character = EBP_UNHANDLED_CONVERSION_CHARACTER;
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return Character;
}


CHAR
EbppEptBreakpointSizeToCharacter(
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize
)
{
    CHAR Character = NULL;

    switch (BreakpointSize)
    {
        case EptBreakpointSizeByte:
            Character = '1';
            break;

        case EptBreakpointSizeWord:
            Character = '2';
            break;

        case EptBreakpointSizeDword:
            Character = '4';
            break;

        case EptBreakpointSizeQword:
            Character = '8';
            break;

        default:
            ERR_PRINT("Unhandled BreakpointSize: %d", BreakpointSize);
            Character = EBP_UNHANDLED_CONVERSION_CHARACTER;
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return Character;
}


#define EBP_UNHANDLED_STRING_CONVERSION_NAME "(ERROR)"

PSTR
EbppEptBreakpointStatusToString(
    _In_ EPT_BREAKPOINT_STATUS BreakpointStatus
)
{
    PSTR pszString = NULL;

    switch (BreakpointStatus)
    {
        case EptBreakpointStatusActive:
            pszString = "Active";
            break;

        case EptBreakpointStatusInactive:
            pszString = "Inactive";
            break;

        case EptBreakpointStatusInstalling:
            pszString = "Installing";
            break;

        default:
            ERR_PRINT("Unhandled BreakpointStatus: %d", BreakpointStatus);
            pszString = EBP_UNHANDLED_STRING_CONVERSION_NAME;
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return pszString;
}


PSTR
EbppEptBreakpointLogTypeToString(
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType
)
{
    PSTR pszString = NULL;

    switch (LogType)
    {
        case EptBreakpointLogTypeBasic:
            pszString = "Basic";
            break;

        case EptBreakpointLogTypeGeneralRegisterContext:
            pszString = "GeneralRegisterContext";
            break;

        case EptBreakpointLogTypeKeyedRegisterContext:
            pszString = "KeyedRegisterContext";
            break;

        default:
            ERR_PRINT("Unhandled LogType: %d", LogType);
            pszString = EBP_UNHANDLED_STRING_CONVERSION_NAME;
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return pszString;
}


PSTR
EbppRegisterToString(
    _In_ X64_REGISTER Register
)
{
    PSTR pszString = NULL;

    switch (Register)
    {
        case REGISTER_RIP: pszString = "RIP"; break;
        case REGISTER_R15: pszString = "R15"; break;
        case REGISTER_R14: pszString = "R14"; break;
        case REGISTER_R13: pszString = "R13"; break;
        case REGISTER_R12: pszString = "R12"; break;
        case REGISTER_R11: pszString = "R11"; break;
        case REGISTER_R10: pszString = "R10"; break;
        case REGISTER_R9:  pszString = "R9";  break;
        case REGISTER_R8:  pszString = "R8";  break;
        case REGISTER_RDI: pszString = "RDI"; break;
        case REGISTER_RSI: pszString = "RSI"; break;
        case REGISTER_RBP: pszString = "RBP"; break;
        case REGISTER_RSP: pszString = "RSP"; break;
        case REGISTER_RBX: pszString = "RBX"; break;
        case REGISTER_RDX: pszString = "RDX"; break;
        case REGISTER_RCX: pszString = "RCX"; break;
        case REGISTER_RAX: pszString = "RAX"; break;
        default:
            ERR_PRINT("Unhandled Register: %d", Register);
            pszString = EBP_UNHANDLED_STRING_CONVERSION_NAME;
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return pszString;
}


_Use_decl_annotations_
VOID
EbpPrintEptBreakpointLogHeader(
    HANDLE hLog,
    PEPT_BREAKPOINT_LOG_HEADER pHeader
)
{
    CHAR BreakpointTypeSize[3] = {};
    BOOL fLogTypeKeyedRegisterContext = FALSE;

    BreakpointTypeSize[0] =
        EbppEptBreakpointTypeToCharacter(pHeader->BreakpointType);

    if (EptBreakpointTypeRead == pHeader->BreakpointType ||
        EptBreakpointTypeWrite == pHeader->BreakpointType)
    {
        BreakpointTypeSize[1] =
            EbppEptBreakpointSizeToCharacter(pHeader->BreakpointSize);
    }
    else
    {
        BreakpointTypeSize[1] = ' ';
    }

    fLogTypeKeyedRegisterContext =
        EptBreakpointLogTypeKeyedRegisterContext == pHeader->LogType;

    INF_PRINT(
        "EPTBP Log #%Iu | PID: %Iu, Address: %p, BP: %s, Status: %s, %s%s%s",
        hLog,
        pHeader->ProcessId,
        pHeader->Address,
        BreakpointTypeSize,
        EbppEptBreakpointStatusToString(pHeader->BreakpointStatus),
        EbppEptBreakpointLogTypeToString(pHeader->LogType),
        (fLogTypeKeyedRegisterContext ? " " : ""),
        (fLogTypeKeyedRegisterContext ?
            EbppRegisterToString(pHeader->RegisterKey) :
            ""));

    INF_PRINT("    NumberOfElements: %u, MaxIndex: %u",
        pHeader->NumberOfElements,
        pHeader->MaxIndex);
}


_Use_decl_annotations_
VOID
EbpPrintEptBreakpointInformation(
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo
)
{
    ULONG i = 0;
    PEPT_BREAKPOINT_INFORMATION_ELEMENT pElement = NULL;
    PEPT_BREAKPOINT_LOG_HEADER pHeader = NULL;
    CHAR BreakpointTypeSize[3] = {};

    INF_PRINT("Ept Breakpoint Information");
    INF_PRINT("    %u active breakpoints.",
        pEptBreakpointInfo->NumberOfActiveBreakpoints);
    INF_PRINT("    %u inactive breakpoints.",
        pEptBreakpointInfo->NumberOfInactiveBreakpoints);
    INF_PRINT("    %u locked pages.",
        pEptBreakpointInfo->NumberOfLockedPages);
    INF_PRINT("    %u hooked pages.",
        pEptBreakpointInfo->NumberOfHookedPages);

    if (!pEptBreakpointInfo->NumberOfElements)
    {
        goto exit;
    }

    INF_PRINT("    Breakpoints:");
    INF_PRINT("        Handle   PID          Address BP     Status                LogType #Elements MaxIndex");
    INF_PRINT("        -------------------------------------------------------------------------------------");

    for (i = 0; i < pEptBreakpointInfo->NumberOfElements; i++)
    {
        pElement = &pEptBreakpointInfo->Elements[i];
        pHeader = &pElement->Header;

        BreakpointTypeSize[0] =
            EbppEptBreakpointTypeToCharacter(pHeader->BreakpointType);

        if (EptBreakpointTypeRead == pHeader->BreakpointType ||
            EptBreakpointTypeWrite == pHeader->BreakpointType)
        {
            BreakpointTypeSize[1] =
                EbppEptBreakpointSizeToCharacter(pHeader->BreakpointSize);
        }
        else
        {
            BreakpointTypeSize[1] = ' ';
        }

        INF_PRINT("        %6u %5u %p %s %10s %22s %9u %8u",
            pElement->Handle,
            pHeader->ProcessId,
            pHeader->Address,
            BreakpointTypeSize,
            EbppEptBreakpointStatusToString(pHeader->BreakpointStatus),
            EbppEptBreakpointLogTypeToString(pHeader->LogType),
            pHeader->NumberOfElements,
            pHeader->MaxIndex);
    }

exit:
    return;
}


VOID
EbppPrintLogElementsBasic(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG pLog,
    _In_ ULONG StartIndex,
    _In_ ULONG EndIndex
)
{
    ULONG i = 0;
    PEBLE_BASIC pElement = NULL;

    EbpPrintEptBreakpointLogHeader(hLog, &pLog->Header);

    if (!pLog->Header.NumberOfElements)
    {
        goto exit;
    }

    INF_PRINT("    Elements:");
    INF_PRINT("        Index    TriggerAddress    HitCount");
    INF_PRINT("        -----------------------------------");

    for (i = StartIndex; i < EndIndex; i++)
    {
        pElement = &pLog->u.Basic.Elements[i];

        INF_PRINT("        %5u  %p  %10u",
            i,
            pElement->TriggerAddress,
            pElement->HitCount);
    }

exit:
    return;
}


VOID
EbppPrintLogElementsGeneralRegisterContext(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG pLog,
    _In_ ULONG StartIndex,
    _In_ ULONG EndIndex
)
{
    ULONG i = 0;
    PEBLE_GENERAL_REGISTER_CONTEXT pElement = NULL;

    EbpPrintEptBreakpointLogHeader(hLog, &pLog->Header);

    if (!pLog->Header.NumberOfElements)
    {
        goto exit;
    }

    INF_PRINT("    Elements:");

    for (i = StartIndex; i < EndIndex; i++)
    {
        pElement = &pLog->u.GeneralRegisterContext.Elements[i];

        INF_PRINT_RAW(
            "    %5u   rip: %p flg: %p\r\n"
            "            rax: %p rbx: %p rbp: %p rsp: %p\r\n"
            "            rcx: %p rdx: %p r8:  %p r9:  %p\r\n"
            "            rdi: %p rsi: %p r10: %p r11: %p\r\n"
            "            r12: %p r13: %p r14: %p r15: %p\r\n\r\n",
            i, pElement->TriggerAddress, pElement->Flags,
            pElement->Registers.Rax, pElement->Registers.Rbx,
            pElement->Registers.Rbp, pElement->Registers.Rsp,
            pElement->Registers.Rcx, pElement->Registers.Rdx,
            pElement->Registers.R8, pElement->Registers.R9,
            pElement->Registers.Rdi, pElement->Registers.Rsi,
            pElement->Registers.R10, pElement->Registers.R11,
            pElement->Registers.R12, pElement->Registers.R13,
            pElement->Registers.R14, pElement->Registers.R15);
    }

exit:
    return;
}


VOID
EbppPrintLogElementsKeyedRegisterContext(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG pLog,
    _In_ ULONG StartIndex,
    _In_ ULONG EndIndex
)
{
    ULONG i = 0;
    PEBLE_KEYED_REGISTER_CONTEXT pElement = NULL;

    EbpPrintEptBreakpointLogHeader(hLog, &pLog->Header);

    if (!pLog->Header.NumberOfElements)
    {
        goto exit;
    }

    INF_PRINT("    Elements:");

    for (i = StartIndex; i < EndIndex; i++)
    {
        pElement = &pLog->u.KeyedRegisterContext.Elements[i];

        INF_PRINT_RAW(
            "    %5u   rip: %p flg: %p\r\n"
            "            rax: %p rbx: %p rbp: %p rsp: %p\r\n"
            "            rcx: %p rdx: %p r8:  %p r9:  %p\r\n"
            "            rdi: %p rsi: %p r10: %p r11: %p\r\n"
            "            r12: %p r13: %p r14: %p r15: %p\r\n\r\n",
            i, pElement->TriggerAddress, pElement->Flags,
            pElement->Registers.Rax, pElement->Registers.Rbx,
            pElement->Registers.Rbp, pElement->Registers.Rsp,
            pElement->Registers.Rcx, pElement->Registers.Rdx,
            pElement->Registers.R8, pElement->Registers.R9,
            pElement->Registers.Rdi, pElement->Registers.Rsi,
            pElement->Registers.R10, pElement->Registers.R11,
            pElement->Registers.R12, pElement->Registers.R13,
            pElement->Registers.R14, pElement->Registers.R15);
    }

exit:
    return;
}


/*++

Description:

    Print a range of elements from the specified ept breakpoint log.

Parameters:

    hLog - Log handle for 'pLog'.

    pLog - The log to print elements from.

    StartIndex - The index of the first element to be printed.

    nPrint - The number of elements to print. If this parameter is zero then
        all of the elements from 'StartIndex' to the last element are printed.

Remarks:

    The output format depends on the log type.

--*/
_Use_decl_annotations_
BOOL
EbpPrintEptBreakpointElements(
    HANDLE hLog,
    PEPT_BREAKPOINT_LOG pLog,
    ULONG StartIndex,
    ULONG nPrint
)
{
    ULONG EndIndex = 0;
    HRESULT hresult = S_OK;
    BOOL status = TRUE;

    //
    // Validate input parameters.
    //
    if (!pLog->Header.NumberOfElements)
    {
        //
        // If the log has no elements then print the header and return success.
        //
        EbpPrintEptBreakpointLogHeader(hLog, &pLog->Header);
        goto exit;
    }

    if (StartIndex >= pLog->Header.NumberOfElements)
    {
        ERR_PRINT("StartIndex out of range: %u (NumberOfElements = %u)",
            StartIndex,
            pLog->Header.NumberOfElements);
        status = FALSE;
        goto exit;
    }

    if (nPrint)
    {
        hresult = ULongAdd(StartIndex, nPrint, &EndIndex);
        if (FAILED(hresult))
        {
            ERR_PRINT("ULongAdd failed: 0x%X", hresult);
            status = FALSE;
            goto exit;
        }

        //
        // Clamp the print range to the last element in the log.
        //
        if (EndIndex > pLog->Header.NumberOfElements)
        {
            EndIndex = pLog->Header.NumberOfElements;
        }
    }
    else
    {
        EndIndex = pLog->Header.NumberOfElements;
    }

    _ASSERT(StartIndex < EndIndex);

    switch (pLog->Header.LogType)
    {
        case EptBreakpointLogTypeBasic:
            EbppPrintLogElementsBasic(hLog, pLog, StartIndex, EndIndex);
            break;

        case EptBreakpointLogTypeGeneralRegisterContext:
            EbppPrintLogElementsGeneralRegisterContext(
                hLog,
                pLog,
                StartIndex,
                EndIndex);
            break;

        case EptBreakpointLogTypeKeyedRegisterContext:
            EbppPrintLogElementsKeyedRegisterContext(
                hLog,
                pLog,
                StartIndex,
                EndIndex);
            break;

        default:
            ERR_PRINT("Unexpected LogType: %d", pLog->Header.LogType);
            status = FALSE;
            goto exit;
    }

exit:
    return status;
}
