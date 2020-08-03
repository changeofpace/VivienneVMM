/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "driver_io.h"

#include "debug.h"


//=============================================================================
// Module Globals
//=============================================================================
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
BOOL
VivienneIoInitialization()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL status = TRUE;

    hDevice = CreateFileW(
        VVMM_LOCALDEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == hDevice)
    {
        status = FALSE;
        goto exit;
    }

    g_hDevice = hDevice;

exit:
    return status;
}


VOID
VivienneIoTermination()
{
    if (INVALID_HANDLE_VALUE != g_hDevice)
    {
        VERIFY(CloseHandle(g_hDevice));
    }
}


//=============================================================================
// Public Interface
//=============================================================================
_Use_decl_annotations_
BOOL
VivienneIoGetProcessInformation(
    ULONG_PTR ProcessId,
    PVIVIENNE_PROCESS_INFORMATION pProcessInfo
)
{
    GET_PROCESS_INFORMATION_REQUEST Request = {};
    GET_PROCESS_INFORMATION_REPLY Reply = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pProcessInfo, sizeof(*pProcessInfo));

    //
    // Initialize the request.
    //
    Request.ProcessId = ProcessId;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_GET_PROCESS_INFORMATION,
        &Request,
        sizeof(Request),
        &Reply,
        sizeof(Reply),
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

    //
    // Set out parameters.
    //
    RtlCopyMemory(
        pProcessInfo,
        &Reply.Info,
        sizeof(VIVIENNE_PROCESS_INFORMATION));

exit:
    return status;
}


//
// VivienneIoQuerySystemDebugState
//
// Query the breakpoint manager's debug register state for all processors.
//
_Use_decl_annotations_
BOOL
VivienneIoQuerySystemDebugState(
    PSYSTEM_DEBUG_STATE pSystemDebugState,
    ULONG cbSystemDebugState
)
{
    PQUERYSYSTEMDEBUGSTATE_REPLY pReply =
        (PQUERYSYSTEMDEBUGSTATE_REPLY)pSystemDebugState;
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pSystemDebugState, cbSystemDebugState);

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_QUERYSYSTEMDEBUGSTATE,
        NULL,
        0,
        pReply,
        cbSystemDebugState,
        &ReturnedBytes,
        NULL);

    return status;
}


//
// VivienneIoSetHardwareBreakpoint
//
// Install a hardware breakpoint on all processors.
//
_Use_decl_annotations_
BOOL
VivienneIoSetHardwareBreakpoint(
    ULONG_PTR ProcessId,
    ULONG DebugRegisterIndex,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size
)
{
    SETHARDWAREBREAKPOINT_REQUEST Request = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Initialize the request.
    //
    Request.ProcessId = ProcessId;
    Request.Index = DebugRegisterIndex;
    Request.Address = Address;
    Request.Type = Type;
    Request.Size = Size;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_SETHARDWAREBREAKPOINT,
        &Request,
        sizeof(Request),
        NULL,
        0,
        &ReturnedBytes,
        NULL);

    return status;
}


//
// VivienneIoClearHardwareBreakpoint
//
// Uninstall a hardware breakpoint on all processors.
//
_Use_decl_annotations_
BOOL
VivienneIoClearHardwareBreakpoint(
    ULONG DebugRegisterIndex
)
{
    CLEARHARDWAREBREAKPOINT_REQUEST Request = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Initialize the request.
    //
    Request.Index = DebugRegisterIndex;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_CLEARHARDWAREBREAKPOINT,
        &Request,
        sizeof(Request),
        NULL,
        0,
        &ReturnedBytes,
        NULL);

    return status;
}


//
// VivienneIoCaptureRegisterValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  examine the contents of the target register and record all unique values
//  to the output buffer.
//
// NOTE This is a synchronous call which will block for the specified
//  duration. The duration is clamped to an internal value to prevent timeouts
//  caused by input error.
//
_Use_decl_annotations_
BOOL
VivienneIoCaptureRegisterValues(
    ULONG_PTR ProcessId,
    ULONG DebugRegisterIndex,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    X64_REGISTER Register,
    ULONG DurationInMilliseconds,
    PCEC_REGISTER_VALUES pValuesCtx,
    ULONG cbValuesCtx
)
{
    CEC_REGISTER_REQUEST Request = {};
    PCEC_REGISTER_REPLY pReply = (PCEC_REGISTER_REPLY)pValuesCtx;
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pValuesCtx, cbValuesCtx);

    //
    // Initialize the request.
    //
    Request.ProcessId = ProcessId;
    Request.Index = DebugRegisterIndex;
    Request.Address = Address;
    Request.Type = Type;
    Request.Size = Size;
    Request.Register = Register;
    Request.DurationInMilliseconds = DurationInMilliseconds;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_CEC_REGISTER,
        &Request,
        sizeof(Request),
        pReply,
        cbValuesCtx,
        &ReturnedBytes,
        NULL);

    return status;
}


//
// VivienneIoCaptureMemoryValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  record all unique values at the memory address defined by the memory
//  description parameter.
//
// NOTE This is a synchronous call which will block for the specified
//  duration. The duration is clamped to an internal value to prevent timeouts
//  caused by input error.
//
_Use_decl_annotations_
BOOL
VivienneIoCaptureMemoryValues(
    ULONG_PTR ProcessId,
    ULONG DebugRegisterIndex,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    PCEC_MEMORY_DESCRIPTION pMemoryDescription,
    ULONG DurationInMilliseconds,
    PCEC_MEMORY_VALUES pValuesCtx,
    ULONG cbValuesCtx
)
{
    CEC_MEMORY_REQUEST Request = {};
    PCEC_MEMORY_REPLY pReply = (PCEC_MEMORY_REPLY)pValuesCtx;
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pValuesCtx, cbValuesCtx);

    //
    // Initialize the request.
    //
    Request.ProcessId = ProcessId;
    Request.Index = DebugRegisterIndex;
    Request.Address = Address;
    Request.Type = Type;
    Request.Size = Size;
    RtlCopyMemory(
        &Request.MemoryDescription,
        pMemoryDescription,
        sizeof(CEC_MEMORY_DESCRIPTION));
    Request.DurationInMilliseconds = DurationInMilliseconds;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_CEC_MEMORY,
        &Request,
        sizeof(Request),
        pReply,
        cbValuesCtx,
        &ReturnedBytes,
        NULL);

    return status;
}


_Use_decl_annotations_
BOOL
VivienneIoQueryEptBreakpointInformationSize(
    PULONG pcbRequired
)
{
    QUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY Reply = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pcbRequired = 0;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION_SIZE,
        NULL,
        0,
        &Reply,
        sizeof(Reply),
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pcbRequired = Reply.RequiredSize;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
VivienneIoQueryEptBreakpointInformation(
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo,
    ULONG cbEptBreakpointInfo
)
{
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pEptBreakpointInfo, cbEptBreakpointInfo);

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION,
        NULL,
        0,
        pEptBreakpointInfo,
        cbEptBreakpointInfo,
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}


_Use_decl_annotations_
BOOL
VivienneIoSetEptBreakpoint(
    ULONG_PTR ProcessId,
    ULONG_PTR Address,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    EPT_BREAKPOINT_LOG_TYPE LogType,
    SIZE_T cbLog,
    BOOLEAN fMakePageResident,
    X64_REGISTER RegisterKey,
    PHANDLE phLog,
    PEPT_BREAKPOINT_LOG* ppLog
)
{
    SET_EPT_BREAKPOINT_REQUEST Request = {};
    SET_EPT_BREAKPOINT_REPLY Reply = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *phLog = NULL;
    *ppLog = NULL;

    //
    // Initialize the request.
    //
    Request.ProcessId = ProcessId;
    Request.Address = Address;
    Request.BreakpointType = BreakpointType;
    Request.BreakpointSize = BreakpointSize;
    Request.LogType = LogType;
    Request.LogSize = cbLog;
    Request.MakePageResident = fMakePageResident;
    Request.RegisterKey = RegisterKey;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_SET_EPT_BREAKPOINT,
        &Request,
        sizeof(Request),
        &Reply,
        sizeof(Reply),
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

    //
    // Set out parameters.
    //
    *phLog = Reply.Handle;
    *ppLog = Reply.Log;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
VivienneIoDisableEptBreakpoint(
    HANDLE Handle
)
{
    CLEAR_EPT_BREAKPOINT_REQUEST Request = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Initialize the request.
    //
    Request.Handle = Handle;

    status = DeviceIoControl(
        g_hDevice,
        IOCTL_DISABLE_EPT_BREAKPOINT,
        &Request,
        sizeof(Request),
        NULL,
        0,
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}


_Use_decl_annotations_
BOOL
VivienneIoClearEptBreakpoint(
    HANDLE Handle
)
{
    CLEAR_EPT_BREAKPOINT_REQUEST Request = {};
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    //
    // Initialize the request.
    //
    Request.Handle = Handle;

    status =  DeviceIoControl(
        g_hDevice,
        IOCTL_CLEAR_EPT_BREAKPOINT,
        &Request,
        sizeof(Request),
        NULL,
        0,
        &ReturnedBytes,
        NULL);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}
