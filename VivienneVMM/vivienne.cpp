/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    vivienne.cpp

Abstract:

    This module implements the VivienneVMM interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "vivienne.h"

#include "breakpoint_callback.h"
#include "capture_execution_context.h"
#include "debug.h"
#include "ept_breakpoint_manager.h"
#include "hardware_breakpoint_manager.h"
#include "log.h"
#include "process_util.h"

#include "..\common\config.h"
#include "..\common\driver_io_types.h"
#include "..\common\time_util.h"


//=============================================================================
// Ioctl Interface Prototypes
//=============================================================================
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH
ViviennepVmmDispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH
ViviennepVmmDispatchClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH
ViviennepVmmDispatchDeviceControl;


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
VivienneVmmDriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
)
{
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING DeviceName = {};
    UNICODE_STRING SymlinkName = {};
    BOOLEAN fSymlinkCreated = FALSE;
#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    BOOLEAN fHbmInitialized = FALSE;
    BOOLEAN fCecInitialized = FALSE;
#endif
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    BOOLEAN fEbmInitialized = FALSE;
#endif
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pRegistryPath);

    INF_PRINT("Loading %ls.", VVMM_DRIVER_NAME_W);

    INF_PRINT("Vivienne driver mapped at: %p - %p (0x%X)",
        pDriverObject->DriverStart,
        (ULONG_PTR)pDriverObject->DriverStart + pDriverObject->DriverSize,
        pDriverObject->DriverSize);

    //
    // Initialize the driver.
    //
    DeviceName = RTL_CONSTANT_STRING(VVMM_NT_DEVICE_NAME_W);

    // TODO Use IoCreateDeviceSecure.
    ntstatus = IoCreateDevice(
        pDriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_VVMM,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
#pragma warning(suppress : 6014) // Memory leak.
        &pDeviceObject);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IoCreateDevice failed: 0x%X", ntstatus);
        goto exit;
    }

    SymlinkName = RTL_CONSTANT_STRING(VVMM_SYMLINK_NAME_W);

    //
    // Create a symlink for the user mode client to open.
    //
    ntstatus = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IoCreateSymbolicLink failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fSymlinkCreated = TRUE;

// Accessing undocumented members of a DRIVER_OBJECT structure outside of
//  DriverEntry or DriverUnload.
#pragma warning(push)
#pragma warning(disable : 28175)
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = ViviennepVmmDispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = ViviennepVmmDispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        ViviennepVmmDispatchDeviceControl;
#pragma warning(pop)

    //
    // Load the driver modules.
    //
    ntstatus = TiDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("TiDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    ntstatus = HbmDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("HbmDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fHbmInitialized = TRUE;

    ntstatus = CecDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("CecDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fCecInitialized = TRUE;
#endif

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    ntstatus = EbmDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fEbmInitialized = TRUE;
#endif

    INF_PRINT("Loading %ls.", VVMM_DRIVER_NAME_W);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
        if (fEbmInitialized)
        {
            EbmDriverUnload();
        }
#endif

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
        if (fCecInitialized)
        {
            CecDriverUnload();
        }

        if (fHbmInitialized)
        {
            HbmDriverUnload();
        }
#endif

        if (fSymlinkCreated)
        {
            VERIFY_NTSTATUS(IoDeleteSymbolicLink(&SymlinkName));
        }

        if (pDeviceObject)
        {
            IoDeleteDevice(pDeviceObject);
        }
    }

    return ntstatus;
}


_Use_decl_annotations_
VOID
VivienneVmmDriverUnload(
    PDRIVER_OBJECT pDriverObject
)
{
    UNICODE_STRING SymlinkName = {};

    INF_PRINT("Unloading %ls.", VVMM_DRIVER_NAME_W);

    //
    // Unload the driver modules.
    //
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    EbmDriverUnload();
#endif

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    CecDriverUnload();
    HbmDriverUnload();
#endif

    //
    // Release our symbolic link.
    //
    SymlinkName = RTL_CONSTANT_STRING(VVMM_SYMLINK_NAME_W);

    VERIFY_NTSTATUS(IoDeleteSymbolicLink(&SymlinkName));

    //
    // Release our device object.
    //
    if (pDriverObject->DeviceObject)
    {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }

    INF_PRINT("%ls unloaded.", VVMM_DRIVER_NAME_W);
}


//=============================================================================
// Ioctl Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
ViviennepVmmDispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DBG_PRINT("Processing IRP_MJ_CREATE.");

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    VERIFY_NTSTATUS(EbmRegisterClient(PsGetCurrentProcessId()));
#endif

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ViviennepVmmDispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DBG_PRINT("Processing IRP_MJ_CLOSE.");

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    //
    // TODO Move this to an IRP_MJ_CLEANUP routine?
    //
    VERIFY_NTSTATUS(HbmCleanupBreakpoints());
#endif

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
ViviennepVmmDispatchDeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    PVOID pSystemBuffer = pIrp->AssociatedIrp.SystemBuffer;
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG cbInput = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG cbOutput = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG_PTR Information = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pDeviceObject);

    switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
        //---------------------------------------------------------------------
        // Process
        //---------------------------------------------------------------------
        case IOCTL_GET_PROCESS_INFORMATION:
            DBG_PRINT("Processing IOCTL_GET_PROCESS_INFORMATION.");

            if (sizeof(GET_PROCESS_INFORMATION_REQUEST) == cbInput &&
                sizeof(GET_PROCESS_INFORMATION_REPLY) == cbOutput &&
                pSystemBuffer)
            {
                PGET_PROCESS_INFORMATION_REQUEST pRequest =
                    (PGET_PROCESS_INFORMATION_REQUEST)pSystemBuffer;
                PGET_PROCESS_INFORMATION_REPLY pReply =
                    (PGET_PROCESS_INFORMATION_REPLY)pSystemBuffer;

                ntstatus = PsuGetProcessInformation(
                    (HANDLE)pRequest->ProcessId,
                    &pReply->Info);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = sizeof(*pReply);
                }
                else
                {
                    ERR_PRINT("PsuGetProcessInformation failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
        //---------------------------------------------------------------------
        // Hardware Breakpoint Manager
        //---------------------------------------------------------------------
        case IOCTL_QUERYSYSTEMDEBUGSTATE:
            DBG_PRINT("Processing IOCTL_QUERYSYSTEMDEBUGSTATE.");

            if (sizeof(QUERYSYSTEMDEBUGSTATE_REPLY) <= cbOutput &&
                pSystemBuffer)
            {
                PQUERYSYSTEMDEBUGSTATE_REPLY pReply =
                    (PQUERYSYSTEMDEBUGSTATE_REPLY)pSystemBuffer;

                ntstatus = HbmQuerySystemDebugState(
                    (PSYSTEM_DEBUG_STATE)pReply,
                    cbOutput);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = pReply->Size;
                }
                else if (STATUS_BUFFER_OVERFLOW == ntstatus)
                {
                    Information = sizeof(*pReply);
                }
                else
                {
                    ERR_PRINT(
                        "HbmQuerySystemDebugState failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_SETHARDWAREBREAKPOINT:
            DBG_PRINT("Processing IOCTL_SETHARDWAREBREAKPOINT.");

            if (sizeof(SETHARDWAREBREAKPOINT_REQUEST) == cbInput &&
                pSystemBuffer)
            {
                PSETHARDWAREBREAKPOINT_REQUEST pRequest =
                    (PSETHARDWAREBREAKPOINT_REQUEST)pSystemBuffer;

                ntstatus = HbmSetHardwareBreakpoint(
                    pRequest->ProcessId,
                    pRequest->Index,
                    pRequest->Address,
                    pRequest->Type,
                    pRequest->Size,
                    BpcVmxLogGeneralPurposeRegisters,
                    NULL);
                if (!NT_SUCCESS(ntstatus))
                {
                    ERR_PRINT(
                        "HbmSetHardwareBreakpoint failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_CLEARHARDWAREBREAKPOINT:
            DBG_PRINT("Processing IOCTL_CLEARHARDWAREBREAKPOINT.");

            if (sizeof(CLEARHARDWAREBREAKPOINT_REQUEST) == cbInput &&
                pSystemBuffer)
            {
                PCLEARHARDWAREBREAKPOINT_REQUEST pRequest =
                    (PCLEARHARDWAREBREAKPOINT_REQUEST)pSystemBuffer;

                ntstatus = HbmClearHardwareBreakpoint(pRequest->Index);
                if (!NT_SUCCESS(ntstatus))
                {
                    ERR_PRINT(
                        "HbmClearHardwareBreakpoint failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        //---------------------------------------------------------------------
        // Capture Execution Context
        //---------------------------------------------------------------------
        case IOCTL_CEC_REGISTER:
            DBG_PRINT("Processing IOCTL_CEC_REGISTER.");

            if (sizeof(CEC_REGISTER_REQUEST) == cbInput &&
                sizeof(CEC_REGISTER_REPLY) <= cbOutput &&
                pSystemBuffer)
            {
                PCEC_REGISTER_REQUEST pRequest =
                    (PCEC_REGISTER_REQUEST)pSystemBuffer;
                PCEC_REGISTER_REPLY pReply =
                    (PCEC_REGISTER_REPLY)pSystemBuffer;

                ntstatus = CecCaptureRegisterValues(
                    pRequest->ProcessId,
                    pRequest->Index,
                    pRequest->Address,
                    pRequest->Type,
                    pRequest->Size,
                    pRequest->Register,
                    pRequest->DurationInMilliseconds,
                    (PCEC_REGISTER_VALUES)pReply,
                    cbOutput);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = pReply->Size;
                }
                else
                {
                    ERR_PRINT(
                        "CecCaptureRegisterValues failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_CEC_MEMORY:
            DBG_PRINT("Processing IOCTL_CEC_MEMORY.");

            if (sizeof(CEC_MEMORY_REQUEST) == cbInput &&
                sizeof(CEC_MEMORY_REPLY) <= cbOutput &&
                pSystemBuffer)
            {
                PCEC_MEMORY_REQUEST pRequest =
                    (PCEC_MEMORY_REQUEST)pSystemBuffer;
                PCEC_MEMORY_REPLY pReply =
                    (PCEC_MEMORY_REPLY)pSystemBuffer;

                ntstatus = CecCaptureMemoryValues(
                    pRequest->ProcessId,
                    pRequest->Index,
                    pRequest->Address,
                    pRequest->Type,
                    pRequest->Size,
                    &pRequest->MemoryDescription,
                    pRequest->DurationInMilliseconds,
                    (PCEC_MEMORY_VALUES)pReply,
                    cbOutput);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = pReply->Size;
                }
                else
                {
                    ERR_PRINT(
                        "CecCaptureRegisterValues failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
#endif

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
        //---------------------------------------------------------------------
        // Ept Breakpoint Manager
        //---------------------------------------------------------------------
        case IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION_SIZE:
            DBG_PRINT(
                "Processing IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION_SIZE.");

            if (sizeof(QUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY) == cbOutput
                && pSystemBuffer)
            {
                PQUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY pReply =
                    (PQUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY)pSystemBuffer;

                ntstatus = EbmQueryEptBreakpointInformationSize(
                    &pReply->RequiredSize);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = sizeof(*pReply);
                }
                else
                {
                    ERR_PRINT(
                        "EbmQueryEptBreakpointInformationSize failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION:
            DBG_PRINT("Processing IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION.");

            if (sizeof(QUERY_EPT_BREAKPOINT_INFORMATION_REPLY) <= cbOutput
                && pSystemBuffer)
            {
                PQUERY_EPT_BREAKPOINT_INFORMATION_REPLY pReply =
                    (PQUERY_EPT_BREAKPOINT_INFORMATION_REPLY)pSystemBuffer;
                ULONG cbReturned = 0;

                ntstatus = EbmQueryEptBreakpointInformation(
                    pReply,
                    cbOutput,
                    &cbReturned);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = cbReturned;
                }
                else
                {
                    ERR_PRINT("EbmQueryEptBreakpointInformation failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_SET_EPT_BREAKPOINT:
            DBG_PRINT("Processing IOCTL_SET_EPT_BREAKPOINT.");

            if (sizeof(SET_EPT_BREAKPOINT_REQUEST) == cbInput &&
                sizeof(SET_EPT_BREAKPOINT_REPLY) == cbOutput &&
                pSystemBuffer)
            {
                PSET_EPT_BREAKPOINT_REQUEST pRequest =
                    (PSET_EPT_BREAKPOINT_REQUEST)pSystemBuffer;
                PSET_EPT_BREAKPOINT_REPLY pReply =
                    (PSET_EPT_BREAKPOINT_REPLY)pSystemBuffer;

                ntstatus = EbmSetEptBreakpoint(
                    (HANDLE)pRequest->ProcessId,
                    (HANDLE)pRequest->Address,
                    pRequest->BreakpointType,
                    pRequest->BreakpointSize,
                    pRequest->LogType,
                    pRequest->LogSize,
                    pRequest->MakePageResident,
                    pRequest->RegisterKey,
                    &pReply->Handle,
                    &pReply->Log);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = sizeof(*pReply);
                }
                else
                {
                    ERR_PRINT("EbmSetEptBreakpoint failed: 0x%X", ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_DISABLE_EPT_BREAKPOINT:
            DBG_PRINT("Processing IOCTL_DISABLE_EPT_BREAKPOINT.");

            if (sizeof(DISABLE_EPT_BREAKPOINT_REQUEST) == cbInput &&
                pSystemBuffer)
            {
                PDISABLE_EPT_BREAKPOINT_REQUEST pRequest =
                    (PDISABLE_EPT_BREAKPOINT_REQUEST)pSystemBuffer;

                ntstatus = EbmDisableEptBreakpoint(pRequest->Handle);
                if (!NT_SUCCESS(ntstatus))
                {
                    ERR_PRINT("EbmDisableEptBreakpoint failed: 0x%X", ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

        case IOCTL_CLEAR_EPT_BREAKPOINT:
            DBG_PRINT("Processing IOCTL_CLEAR_EPT_BREAKPOINT.");

            if (sizeof(CLEAR_EPT_BREAKPOINT_REQUEST) == cbInput &&
                pSystemBuffer)
            {
                PCLEAR_EPT_BREAKPOINT_REQUEST pRequest =
                    (PCLEAR_EPT_BREAKPOINT_REQUEST)pSystemBuffer;

                ntstatus = EbmClearEptBreakpoint(pRequest->Handle);
                if (!NT_SUCCESS(ntstatus))
                {
                    ERR_PRINT("EbmClearEptBreakpoint failed: 0x%X", ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
#endif

        default:
            ERR_PRINT(
                "Unhandled ioctl."
                " (Major = %hhu, Minor = %hhu, Control = %hhu)",
                pIrpStack->MajorFunction,
                pIrpStack->MinorFunction,
                pIrpStack->Control);
            ntstatus = STATUS_NOINTERFACE;
            break;
    }

    pIrp->IoStatus.Information = Information;
    pIrp->IoStatus.Status = ntstatus;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ntstatus;
}
