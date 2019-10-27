/*++

Copyright (c) 2019 changeofpace. All rights reserved.

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
#include "breakpoint_manager.h"
#include "capture_execution_context.h"
#include "config.h"
#include "debug.h"
#include "log.h"
#include "process.h"

#include "..\common\driver_io_types.h"
#include "..\common\time_util.h"


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
VivienneDriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
)
{
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING DeviceName = {};
    UNICODE_STRING SymlinkName = {};
    BOOLEAN fSymlinkCreated = FALSE;
    BOOLEAN fBpmInitialized = FALSE;
    BOOLEAN fCecInitialized = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pRegistryPath);

    INF_PRINT("Loading %ls.", VVMM_DRIVER_NAME_W);

    //
    // Initialize the driver.
    //
    DeviceName = RTL_CONSTANT_STRING(VVMM_NT_DEVICE_NAME_W);

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
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = VivienneDispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = VivienneDispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        VivienneDispatchDeviceControl;
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

    ntstatus = BpmDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fBpmInitialized = TRUE;

    ntstatus = CecDriverEntry();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("CecDriverEntry failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fCecInitialized = TRUE;

    INF_PRINT("Loading %ls.", VVMM_DRIVER_NAME_W);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (fCecInitialized)
        {
            CecDriverUnload();
        }

        if (fBpmInitialized)
        {
            BpmDriverUnload();
        }

        if (fSymlinkCreated)
        {
            VERIFY(IoDeleteSymbolicLink(&SymlinkName));
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
VivienneDriverUnload(
    PDRIVER_OBJECT pDriverObject
)
{
    UNICODE_STRING SymlinkName = {};

    INF_PRINT("Unloading %ls.", VVMM_DRIVER_NAME_W);

    //
    // Unload the driver modules.
    //
    CecDriverUnload();
    BpmDriverUnload();

    //
    // Release our symbolic link.
    //
    SymlinkName = RTL_CONSTANT_STRING(VVMM_SYMLINK_NAME_W);

    VERIFY(IoDeleteSymbolicLink(&SymlinkName));

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
// Public Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
VivienneDispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    DBG_PRINT("Processing IRP_MJ_CREATE.");
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
VivienneDispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DBG_PRINT("Processing IRP_MJ_CLOSE.");

    VERIFY(BpmCleanupBreakpoints());

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS
VivienneDispatchDeviceControl(
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
        case IOCTL_QUERYSYSTEMDEBUGSTATE:
            DBG_PRINT("Processing IOCTL_QUERYSYSTEMDEBUGSTATE.");

            if (sizeof(QUERYSYSTEMDEBUGSTATE_REPLY) <= cbOutput &&
                pSystemBuffer)
            {
                PQUERYSYSTEMDEBUGSTATE_REPLY pReply =
                    (PQUERYSYSTEMDEBUGSTATE_REPLY)pSystemBuffer;

                ntstatus = BpmQuerySystemDebugState(
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
                        "BpmQuerySystemDebugState failed: 0x%X",
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

                ntstatus = BpmSetHardwareBreakpoint(
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
                        "BpmSetHardwareBreakpoint failed: 0x%X",
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

                ntstatus = BpmClearHardwareBreakpoint(pRequest->Index);
                if (!NT_SUCCESS(ntstatus))
                {
                    ERR_PRINT(
                        "BpmClearHardwareBreakpoint failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;

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
                    (PCEC_MEMORY_REPLY)pReply,
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

        default:
            ntstatus = STATUS_NOINTERFACE;
            ERR_PRINT("Unhandled IOCTL: 0x%X.", pIrpStack->MajorFunction);
            break;
    }

    pIrp->IoStatus.Information = Information;
    pIrp->IoStatus.Status = ntstatus;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ntstatus;
}
