#include "thread_util.h"

#include "../VivienneCL/debug.h"
#include "../VivienneCL/log.h"
#include "../VivienneCL/ntdll.h"


_Use_decl_annotations_
BOOL
ThuSetThreadHardwareBreakpoint(
    DWORD ThreadId,
    ULONG DebugRegisterIndex,
    PVOID pAddress,
    HWBP_TYPE Type,
    HWBP_SIZE Size
)
{
    HANDLE hThread = NULL;
    BOOL fSuspended = FALSE;
    CONTEXT Context = {};
    DR7 NewDr7 = {};
    BOOL status = TRUE;

    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
    if (!hThread)
    {
        ERR_PRINT("OpenThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    if (GetCurrentThreadId() != ThreadId)
    {
        if ((DWORD)(-1) == SuspendThread(hThread))
        {
            ERR_PRINT("SuspendThread failed: %u\n", GetLastError());
            status = FALSE;
            goto exit;
        }

        fSuspended = TRUE;
    }

    Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;

    status = GetThreadContext(hThread, &Context);
    if (!status)
    {
        ERR_PRINT("GetThreadContext failed: %u\n", GetLastError());
        goto exit;
    }

    NewDr7.All = Context.Dr7;

    switch (DebugRegisterIndex)
    {
        case 0:
            Context.Dr0 = (DWORD64)pAddress;
            NewDr7.L0 = TRUE;
            NewDr7.G0 = TRUE;
            NewDr7.RW0 = (UCHAR)Type;
            NewDr7.Len0 = (UCHAR)Size;
            break;

        case 1:
            Context.Dr1 = (DWORD64)pAddress;
            NewDr7.L1 = TRUE;
            NewDr7.G1 = TRUE;
            NewDr7.RW1 = (UCHAR)Type;
            NewDr7.Len1 = (UCHAR)Size;
            break;

        case 2:
            Context.Dr2 = (DWORD64)pAddress;
            NewDr7.L2 = TRUE;
            NewDr7.G2 = TRUE;
            NewDr7.RW2 = (UCHAR)Type;
            NewDr7.Len2 = (UCHAR)Size;
            break;

        case 3:
            Context.Dr3 = (DWORD64)pAddress;
            NewDr7.L3 = TRUE;
            NewDr7.G3 = TRUE;
            NewDr7.RW3 = (UCHAR)Type;
            NewDr7.Len3 = (UCHAR)Size;
            break;

        default:
            ERR_PRINT("Invalid DebugRegisterIndex: %u\n", DebugRegisterIndex);
            status = FALSE;
            goto exit;
    }

    Context.Dr7 = NewDr7.All;
    Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;

    status = SetThreadContext(hThread, &Context);
    if (!status)
    {
        ERR_PRINT("SetThreadContext failed.");
        goto exit;
    }

exit:
    if (fSuspended)
    {
        if ((DWORD)(-1) == ResumeThread(hThread))
        {
            ERR_PRINT("ResumeThread failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (hThread)
    {
        VERIFY(CloseHandle(hThread));
    }

    return status;
}


_Use_decl_annotations_
BOOL ThuClearThreadHardwareBreakpoint(
    DWORD ThreadId,
    ULONG DebugRegisterIndex
)
{
    HANDLE hThread = NULL;
    BOOL fSuspended = FALSE;
    CONTEXT Context = {};
    PDR7 pDr7 = NULL;
    BOOL status = TRUE;

    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
    if (!hThread)
    {
        ERR_PRINT("OpenThread failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    if (GetCurrentThreadId() != ThreadId)
    {
        if ((DWORD)(-1) == SuspendThread(hThread))
        {
            ERR_PRINT("SuspendThread failed: %u\n", GetLastError());
            status = FALSE;
            goto exit;
        }

        fSuspended = TRUE;
    }

    Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;

    status = GetThreadContext(hThread, &Context);
    if (!status)
    {
        ERR_PRINT("GetThreadContext failed: %u\n", GetLastError());
        goto exit;
    }

    switch (DebugRegisterIndex)
    {
        case 0:
            Context.Dr0 = 0;
            break;

        case 1:
            Context.Dr1 = 0;
            break;

        case 2:
            Context.Dr2 = 0;
            break;

        case 3:
            Context.Dr3 = 0;
            break;

        default:
            ERR_PRINT("Invalid DebugRegisterIndex: %u", DebugRegisterIndex);
            status = FALSE;
            goto exit;
    }

    status = SetThreadContext(hThread, &Context);
    if (!status)
    {
        ERR_PRINT("SetThreadContext failed.");
        goto exit;
    }

exit:
    if (fSuspended)
    {
        if ((DWORD)(-1) == ResumeThread(hThread))
        {
            ERR_PRINT("ResumeThread failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    if (hThread)
    {
        VERIFY(CloseHandle(hThread));
    }

    return status;
}
