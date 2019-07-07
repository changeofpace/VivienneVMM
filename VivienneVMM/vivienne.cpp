/*++

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

#include "breakpoint_manager.h"
#include "capture_execution_context.h"
#include "config.h"
#include "dispatch.h"
#include "log.h"

#include "..\common\driver_io_types.h"
#include "..\common\time_util.h"


//=============================================================================
// Meta Interface
//=============================================================================

//
// VvmmInitialization
//
_Use_decl_annotations_
NTSTATUS
VvmmInitialization(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
)
{
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING DeviceName = {};
    UNICODE_STRING SymlinkName = {};
    BOOLEAN fSymlinkCreated = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pRegistryPath);

    INF_PRINT("Initializing %ls.", VVMM_DRIVER_NAME_W);

    // Initialize the driver.
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

    // Create a symlink for the user mode client to open.
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
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
#pragma warning(pop)

    // Initialize the subsystems.
    ntstatus = TiInitialization();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("TiInitialization failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = BpmInitialization();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmInitialization failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = CecInitialization();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("CecInitialization failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (fSymlinkCreated)
        {
            NTSTATUS UnwindStatus = IoDeleteSymbolicLink(&SymlinkName);
            if (!NT_SUCCESS(UnwindStatus))
            {
                ERR_PRINT("IoDeleteSymbolicLink failed: 0x%X", UnwindStatus);
            }
        }

        if (pDeviceObject)
        {
            IoDeleteDevice(pDeviceObject);
        }
    }

    return ntstatus;
}


//
// VvmmTermination
//
// NOTE Failing functions should not trigger an early exit.
//
_Use_decl_annotations_
NTSTATUS
VvmmTermination(
    PDRIVER_OBJECT pDriverObject
)
{
    UNICODE_STRING SymlinkName = {};
    BOOLEAN Failed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT("Terminating %ls.", VVMM_DRIVER_NAME_W);

    ntstatus = BpmTermination();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmTermination failed: 0x%X", ntstatus);
        Failed = TRUE;
    }

    // Release our symbolic link.
    SymlinkName = RTL_CONSTANT_STRING(VVMM_SYMLINK_NAME_W);

    ntstatus = IoDeleteSymbolicLink(&SymlinkName);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IoDeleteSymbolicLink failed: 0x%X", ntstatus);
    }

    // Release our device object.
    if (pDriverObject->DeviceObject)
    {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }

    if (Failed)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
    }

    return ntstatus;
}
