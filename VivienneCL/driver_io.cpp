#include "driver_io.h"


//=============================================================================
// Module Globals
//=============================================================================

// NOTE Not thread safe.
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;


//=============================================================================
// Meta Interface
//=============================================================================

//
// DrvInitialization
//
_Use_decl_annotations_
BOOL
DrvInitialization()
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


//
// DrvTermination
//
_Use_decl_annotations_
BOOL
DrvTermination()
{
    BOOL status = TRUE;

    if (INVALID_HANDLE_VALUE != g_hDevice)
    {
        status = CloseHandle(g_hDevice);
        if (!status)
        {
            goto exit;
        }

        g_hDevice = INVALID_HANDLE_VALUE;
    }

exit:
    return status;
}


//=============================================================================
// Driver Interface
//=============================================================================

//
// DrvQuerySystemDebugState
//
// Query the breakpoint manager's debug register state for all processors.
//
_Use_decl_annotations_
BOOL
DrvQuerySystemDebugState(
    PSYSTEM_DEBUG_STATE pSystemDebugState,
    ULONG cbSystemDebugState
)
{
    PQUERYSYSTEMDEBUGSTATE_REPLY pReply =
        (PQUERYSYSTEMDEBUGSTATE_REPLY)pSystemDebugState;
    DWORD ReturnedBytes = 0;
    BOOL status = TRUE;

    // Zero out parameters.
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
// DrvSetHardwareBreakpoint
//
// Install a hardware breakpoint on all processors.
//
_Use_decl_annotations_
BOOL
DrvSetHardwareBreakpoint(
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
// DrvClearHardwareBreakpoint
//
// Uninstall a hardware breakpoint on all processors.
//
_Use_decl_annotations_
BOOL
DrvClearHardwareBreakpoint(
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
// DrvCaptureRegisterValues
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
DrvCaptureRegisterValues(
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

    // Zero out parameters.
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
// DrvCaptureMemoryValues
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
DrvCaptureMemoryValues(
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

    // Zero out parameters.
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
