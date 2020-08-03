#include "test_ept_breakpoint.h"

/*

 - set multiple breakpoint types at same address

*/

#include <Psapi.h>

#include <cstdio>

#include "memory.h"

#include "../VivienneCL/log.h"
#include "../VivienneCL/ntdll.h"
#include "..\VivienneCL\driver_io.h"


#define FILLER_BUFFER_SIZE (PAGE_SIZE * 5)

//ULONG_PTR g_VarA = 0;
//UCHAR g_FillerBuffer[FILLER_BUFFER_SIZE] = {};
//ULONG_PTR g_VarB = 0;

UCHAR g_VarA[PAGE_SIZE] = {};
UCHAR g_FillerBuffer[FILLER_BUFFER_SIZE] = {};
UCHAR g_VarB[PAGE_SIZE] = {};
HANDLE g_hProcess = NULL;



typedef struct _WSI_VIRTUAL_ATTRIBUTES_TEST {
    PSAPI_WORKING_SET_EX_BLOCK Initial;
    PSAPI_WORKING_SET_EX_BLOCK AfterVirtualLock;
    PSAPI_WORKING_SET_EX_BLOCK AfterVirtualUnlock;
    PSAPI_WORKING_SET_EX_BLOCK AfterForcedOutPage;
    PSAPI_WORKING_SET_EX_BLOCK AfterFree;
} WSI_VIRTUAL_ATTRIBUTES_TEST, *PWSI_VIRTUAL_ATTRIBUTES_TEST;



//_Check_return_
//BOOL
//PrintWorkingSetInfoByAddress(
//    _In_ ULONG_PTR Address
//)
//{
//    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetInfo = {};
//    BOOL status = TRUE;
//
//    //
//    // Initialize the target virtual address for the working set query.
//    //
//    WorkingSetInfo.VirtualAddress = (PVOID)Address;
//
//    status = QueryWorkingSetEx(
//        GetCurrentProcess(),
//        &WorkingSetInfo,
//        sizeof(WorkingSetInfo));
//    if (!status)
//    {
//        ERR_PRINT("QueryWorkingSetEx failed: %u\n", GetLastError());
//        goto exit;
//    }
//
//    INF_PRINT("WSI: %p", Address);
//    INF_PRINT("    Flags: %p", WorkingSetInfo.VirtualAttributes.Flags);
//    if (WorkingSetInfo.VirtualAttributes.Valid)
//    {
//        INF_PRINT("    Valid:           %p", WorkingSetInfo.VirtualAttributes.Valid);
//        INF_PRINT("    ShareCount:      %p", WorkingSetInfo.VirtualAttributes.ShareCount);
//        INF_PRINT("    Win32Protection: %p", WorkingSetInfo.VirtualAttributes.Win32Protection);
//        INF_PRINT("    Shared:          %p", WorkingSetInfo.VirtualAttributes.Shared);
//        INF_PRINT("    Node:            %p", WorkingSetInfo.VirtualAttributes.Node);
//        INF_PRINT("    Locked:          %p", WorkingSetInfo.VirtualAttributes.Locked);
//        INF_PRINT("    LargePage:       %p", WorkingSetInfo.VirtualAttributes.LargePage);
//        INF_PRINT("    Reserved:        %p", WorkingSetInfo.VirtualAttributes.Reserved);
//        INF_PRINT("    Bad:             %p", WorkingSetInfo.VirtualAttributes.Bad);
//        INF_PRINT("    ReservedUlong:   %p", WorkingSetInfo.VirtualAttributes.ReservedUlong);
//    }
//    else
//    {
//        INF_PRINT("    Valid:           %p", WorkingSetInfo.VirtualAttributes.Valid);
//        INF_PRINT("    Reserved0:       %p", WorkingSetInfo.VirtualAttributes.Invalid.Reserved0);
//        INF_PRINT("    Shared:          %p", WorkingSetInfo.VirtualAttributes.Invalid.Shared);
//        INF_PRINT("    Reserved1:       %p", WorkingSetInfo.VirtualAttributes.Invalid.Reserved1);
//        INF_PRINT("    Bad:             %p", WorkingSetInfo.VirtualAttributes.Invalid.Bad);
//    }
//
//exit:
//    return status;
//}


VOID
PrintWorkingSetInfo(
    _In_ ULONG_PTR Address,
    _In_ PPSAPI_WORKING_SET_EX_BLOCK pAttributes
)
{
    INF_PRINT("  WSI: %p", Address);
    INF_PRINT("    Flags: %p", pAttributes->Flags);
    if (pAttributes->Valid)
    {
        INF_PRINT("    Valid:           %p", pAttributes->Valid);
        INF_PRINT("    ShareCount:      %p", pAttributes->ShareCount);
        INF_PRINT("    Win32Protection: %p", pAttributes->Win32Protection);
        INF_PRINT("    Shared:          %p", pAttributes->Shared);
        INF_PRINT("    Node:            %p", pAttributes->Node);
        INF_PRINT("    Locked:          %p", pAttributes->Locked);
        INF_PRINT("    LargePage:       %p", pAttributes->LargePage);
        INF_PRINT("    Reserved:        %p", pAttributes->Reserved);
        INF_PRINT("    Bad:             %p", pAttributes->Bad);
        INF_PRINT("    ReservedUlong:   %p", pAttributes->ReservedUlong);
    }
    else
    {
        INF_PRINT("    Valid:           %p", pAttributes->Valid);
        INF_PRINT("    Reserved0:       %p", pAttributes->Invalid.Reserved0);
        INF_PRINT("    Shared:          %p", pAttributes->Invalid.Shared);
        INF_PRINT("    Reserved1:       %p", pAttributes->Invalid.Reserved1);
        INF_PRINT("    Bad:             %p", pAttributes->Invalid.Bad);
    }
}


VOID
PrintWorkingSetInfoShort(
    _In_ PSTR pszPrefix,
    _In_ PPSAPI_WORKING_SET_EX_BLOCK pAttributes
)
{
    INF_PRINT("%p  %s", pAttributes->Flags, pszPrefix);
}


VOID
PrintWsiTest(
    _In_ ULONG_PTR Address,
    _In_ PWSI_VIRTUAL_ATTRIBUTES_TEST pWsiTest
)
{
    PrintWorkingSetInfoShort("Initial", &pWsiTest->Initial);
    PrintWorkingSetInfoShort("AfterVirtualLock", &pWsiTest->AfterVirtualLock);
    PrintWorkingSetInfoShort("AfterVirtualUnlock", &pWsiTest->AfterVirtualUnlock);
    PrintWorkingSetInfoShort("AfterForcedOutPage", &pWsiTest->AfterForcedOutPage);
    PrintWorkingSetInfoShort("AfterFree", &pWsiTest->AfterFree);
    //INF_PRINT("Initial");
    //PrintWorkingSetInfo(Address, &pWsiTest->Initial);
    //INF_PRINT("AfterVirtualLock");
    //PrintWorkingSetInfo(Address, &pWsiTest->AfterVirtualLock);
    //INF_PRINT("AfterVirtualUnlock");
    //PrintWorkingSetInfo(Address, &pWsiTest->AfterVirtualUnlock);
    //INF_PRINT("AfterForcedOutPage");
    //PrintWorkingSetInfo(Address, &pWsiTest->AfterForcedOutPage);
    //INF_PRINT("AfterFree");
    //PrintWorkingSetInfo(Address, &pWsiTest->AfterFree);
}


_Check_return_
BOOL
GetWorkingSetInfo(
    _In_ ULONG_PTR Address,
    _Out_ PPSAPI_WORKING_SET_EX_BLOCK pAttributes
)
{
    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetInfo = {};
    BOOL status = TRUE;
    
    *pAttributes = {};

    //
    // Initialize the target virtual address for the working set query.
    //
    WorkingSetInfo.VirtualAddress = (PVOID)Address;

    status = QueryWorkingSetEx(
        GetCurrentProcess(),
        &WorkingSetInfo,
        sizeof(WorkingSetInfo));
    if (!status)
    {
        ERR_PRINT("QueryWorkingSetEx failed: %u\n", GetLastError());
        goto exit;
    }

    *pAttributes = WorkingSetInfo.VirtualAttributes;

exit:
    return status;
}



VOID
TestEptBreakpoint()
{
    WSI_VIRTUAL_ATTRIBUTES_TEST WsiTest = {};
    PVOID pAddress = NULL;
    BOOL fValid = FALSE;
    HANDLE LogHandle = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    INF_PRINT("Executing: %s", __FUNCTION__);

    pAddress = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAddress)
    {
        ERR_PRINT("VirtualAlloc failed: %u", GetLastError());
        goto exit;
    }

    if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.Initial))
    {
        ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
        goto exit;
    }

    INF_PRINT("    pAddress:    %p", pAddress);

    //*(PULONG_PTR)pAddress = 1;

    status = IsVirtualAddressValid(pAddress, &fValid);
    if (!status)
    {
        ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
        goto exit;
    }
    //
    if (fValid)
    {
        INF_PRINT("Target address is valid.");
    }
    else
    {
        INF_PRINT("Target address is invalid. Paging it in...");

        status = VivienneIoSetEptBreakpoint(
            GetCurrentProcessId(),
            //TARGET_PID,
            (ULONG_PTR)pAddress,
            //TARGET_ADDRESS,
            EptBreakpointTypeWrite,
            EptBreakpointSizeByte,
            EptBreakpointLogTypeSimple,
            100,
            &LogHandle,
            &pLog);
        if (!status)
        {
            ERR_PRINT("VivienneIoSetEptBreakpoint failed: %u", GetLastError());
            goto exit;
        }

        if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterVirtualLock))
        {
            ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
            goto exit;
        }

        status = IsVirtualAddressValid(pAddress, &fValid);
        if (!status)
        {
            ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
            goto exit;
        }
        //
        if (!fValid)
        {
            INF_PRINT("Target address is invalid. Paging it in...");

            *(PULONG_PTR)pAddress = 0;

            status = IsVirtualAddressValid(&pAddress, &fValid);
            if (!status)
            {
                ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
                goto exit;
            }

            if (!fValid)
            {
                ERR_PRINT("Target address is still invalid.");
                goto exit;
            }

            if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterVirtualUnlock))
            {
                ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
                goto exit;
            }

            INF_PRINT("good");
        }
    }

    PrintWsiTest((ULONG_PTR)pAddress, &WsiTest);

    getchar();






    //INF_PRINT("locking page VirtualLock");

    status = VirtualLock(pAddress, 8);
    if (!status)
    {
        ERR_PRINT("VirtualLock failed: %u", GetLastError());
        goto exit;
    }

    if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterVirtualLock))
    {
        ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
        goto exit;
    }

    //INF_PRINT("Setting ept breakpoint.");

//#define TARGET_PID      1256
//#define TARGET_ADDRESS  0x140007380
//
    //status = VivienneIoSetEptBreakpoint(
    //    GetCurrentProcessId(),
    //    //TARGET_PID,
    //    (ULONG_PTR)pAddress,
    //    //TARGET_ADDRESS,
    //    EptBreakpointTypeWrite,
    //    EptBreakpointSizeByte,
    //    EptBreakpointLogTypeSimple,
    //    100,
    //    &LogHandle,
    //    &pLog);
    //if (!status)
    //{
    //    ERR_PRINT("VivienneIoSetEptBreakpoint failed: %u", GetLastError());
    //    goto exit;
    //}

    status = VirtualUnlock(pAddress, 8);
    if (!status)
    {
        ERR_PRINT("VirtualUnlock failed: %u", GetLastError());
        goto exit;
    }

    if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterVirtualUnlock))
    {
        ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
        goto exit;
    }

    status = VirtualUnlock(pAddress, 8);
    //
    //Sleep(5000);
    //
    if (status)
    {
        ERR_PRINT("VirtualUnlock succeeded.\n");
        goto exit;
    }
    //
    if (GetLastError() != ERROR_NOT_LOCKED)
    {
        ERR_PRINT("VirtualUnlock failed: %u", GetLastError());
        goto exit;
    }

    if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterForcedOutPage))
    {
        ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
        goto exit;
    }

    status = VirtualFree(pAddress, 0, MEM_RELEASE);
    if (!status)
    {
        ERR_PRINT("VirtualFree failed: %u", GetLastError());
        goto exit;
    }

    if (!GetWorkingSetInfo((ULONG_PTR)pAddress, &WsiTest.AfterFree))
    {
        ERR_PRINT("GetWorkingSetInfo failed: %u", GetLastError());
        goto exit;
    }

    PrintWsiTest((ULONG_PTR)pAddress, &WsiTest);

    getchar();

exit:
    return;
}





//VOID
//TestEptBreakpoint()
//{
//    HANDLE LogHandle = NULL;
//    PEPT_BREAKPOINT_LOG pLog = NULL;
//    PUCHAR pTarget = NULL;
//    BOOL fValid = FALSE;
//    BOOL status = TRUE;
//
//    INF_PRINT("Executing: %s", __FUNCTION__);
//
//    pTarget = g_VarA;
//
//    g_VarA[16] = 0x11;
//    g_VarA[17] = 0x22;
//    g_VarA[18] = 0x11;
//    g_VarA[19] = 0x22;
//    g_VarA[20] = 0x11;
//    g_VarA[21] = 0x22;
//    g_VarA[22] = 0x11;
//    g_VarA[23] = 0x22;
//
//    //INF_PRINT("    g_VarA:     %p", &g_VarA);
//    ////printf("    g_FillerBuffer: %p", &g_FillerBuffer);
//    //INF_PRINT("    g_VarB:     %p", &g_VarB);
//    //INF_PRINT("    Delta:      %p", (ULONG_PTR)&g_VarB - (ULONG_PTR)&g_VarA);
//    INF_PRINT("    pTarget:    %p", pTarget);
//
//    //EbmSimpleReadAccess();
//
//
//
//    status = IsVirtualAddressValid(pTarget, &fValid);
//    if (!status)
//    {
//        ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
//        goto exit;
//    }
//
//    if (fValid)
//    {
//        INF_PRINT("Target address is valid.");
//    }
//    else
//    {
//        INF_PRINT("Target address is invalid. Paging it in...");
//
//        *pTarget = 0;
//
//        status = IsVirtualAddressValid(&g_VarA, &fValid);
//        if (!status)
//        {
//            ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
//            goto exit;
//        }
//
//        if (!fValid)
//        {
//            ERR_PRINT("Target address is still invalid.");
//            goto exit;
//        }
//    }
//
//    if (!PrintWorkingSetInfo((ULONG_PTR)pTarget))
//    {
//        ERR_PRINT("PrintWorkingSetInfo failed: %u", GetLastError());
//        goto exit;
//    }
//
//    INF_PRINT("locking page");
//
//    status = VirtualLock(pTarget, 8);
//    if (!status)
//    {
//        ERR_PRINT("VirtualLock failed: %u", GetLastError());
//        goto exit;
//    }
//
//    if (!PrintWorkingSetInfo((ULONG_PTR)pTarget))
//    {
//        ERR_PRINT("PrintWorkingSetInfo failed: %u", GetLastError());
//        goto exit;
//    }
//
//    return;
//
//    fflush(stdout);
//    Sleep(1000);
//    fflush(stdout);
//
//
//    INF_PRINT("Setting ept breakpoint.");
//
//#define TARGET_PID      1256
//#define TARGET_ADDRESS  0x140007380
//
//    status = VivienneIoSetEptBreakpoint(
//        GetCurrentProcessId(),
//        //TARGET_PID,
//        (ULONG_PTR)pTarget,
//        //TARGET_ADDRESS,
//        EptBreakpointTypeWrite,
//        EptBreakpointSizeByte,
//        EptBreakpointLogTypeSimple,
//        100,
//        &LogHandle,
//        &pLog);
//    if (!status)
//    {
//        ERR_PRINT("VivienneIoSetEptBreakpoint failed: %u", GetLastError());
//        goto exit;
//    }
//
//    fflush(stdout);
//    Sleep(1000);
//    fflush(stdout);
//
//
//    if (!PrintWorkingSetInfo((ULONG_PTR)pTarget))
//    {
//        ERR_PRINT("PrintWorkingSetInfo failed: %u", GetLastError());
//        goto exit;
//    }
//
//    fflush(stdout);
//    Sleep(1000);
//    fflush(stdout);
//
//    getchar();
//
//    return;
//
//
//
//    //g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TARGET_PID);
//    //if (!g_hProcess)
//    //{
//    //    ERR_PRINT("OpenProcess failed: %u", GetLastError());
//    //    goto exit;
//    //}
//
//    //status = ReadProcessMemory(g_hProcess, (PVOID)TARGET_ADDRESS, &g_VarB, 16, NULL);
//    //if (!status)
//    //{
//    //    ERR_PRINT("ReadProcessMemory failed: %u", GetLastError());
//    //    goto exit;
//    //}
//
//
//
//    INF_PRINT("Handle: %p", LogHandle);
//    INF_PRINT("Log: %p", pLog);
//    INF_PRINT("    ProcessId:          %Iu", pLog->ProcessId);
//    INF_PRINT("    Address:            %p", pLog->Address);
//    INF_PRINT("    BreakpointStatus:   %d", pLog->BreakpointStatus);
//    INF_PRINT("    BreakpointType:     %d", pLog->BreakpointType);
//    INF_PRINT("    BreakpointSize:     %d", pLog->BreakpointSize);
//    INF_PRINT("    MaxIndex:           %u", pLog->MaxIndex);
//    INF_PRINT("    NumberOfElements:   %u", pLog->NumberOfElements);
//
//
//
//    INF_PRINT("Triggering ept breakpoint...");
//    fflush(stdout);
//    Sleep(10000);
//    fflush(stdout);
//
//
//    *pTarget = 0x99;
//    g_VarA[30] = 0x77;
//
//    Sleep(5000);
//
//
//    status = VirtualUnlock((PVOID)pTarget, 0x2000);
//    //
//    Sleep(5000);
//    //
//    if (status)
//    {
//        ERR_PRINT("VirtualUnlock succeeded.\n");
//        goto exit;
//    }
//    //
//    if (GetLastError() != ERROR_NOT_LOCKED)
//    {
//        ERR_PRINT("VirtualUnlock failed: %u", GetLastError());
//        goto exit;
//    }
//
//    Sleep(5000);
//
//    status = IsVirtualAddressValid(pTarget, &fValid);
//    if (!status)
//    {
//        ERR_PRINT("IsVirtualAddressValid failed: %u", GetLastError());
//        goto exit;
//    }
//    //
//    if (fValid)
//    {
//        __debugbreak();
//        ERR_PRINT("target address is resident.\n");
//        goto exit;
//    }
//
//
//
//    INF_PRINT("done. sleeping...");
//    Sleep(5000);
//    
//    __debugbreak();
//
//
//
//exit:
//    return;
//}
