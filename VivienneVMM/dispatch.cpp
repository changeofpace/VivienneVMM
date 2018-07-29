/*++

Module Name:

    dispatch.cpp

Abstract:

    This module implements the IRP_MJ handlers for the driver.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "dispatch.h"

#include "breakpoint_callbacks.h"
#include "breakpoint_manager.h"
#include "capture_execution_context.h"
#include "log_util.h"
#include "process.h"
#include "vivienne.h"

#include "..\common\driver_io_types.h"


//=============================================================================
// Dispatch Interface
//=============================================================================

//
// DispatchCreate
//
_Use_decl_annotations_
NTSTATUS
DispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    dbg_print("Processing IRP_MJ_CREATE.");
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


//
// DispatchClose
//
// Destructor for a FILE_OBJECT which executes in an arbitrary thread context.
//
_Use_decl_annotations_
NTSTATUS
DispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pDeviceObject);

    dbg_print("Processing IRP_MJ_CLOSE.");

    ntstatus = BpmCleanupBreakpoints();
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmCleanupBreakpoints failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    // TODO Determine the impact of returning a failing status here.
    pIrp->IoStatus.Status = ntstatus;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ntstatus;
}


//
// DispatchCleanup
//
_Use_decl_annotations_
NTSTATUS
DispatchCleanup(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    dbg_print("Processing IRP_MJ_CLEANUP.");
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


//
// DispatchDeviceControl
//
_Use_decl_annotations_
NTSTATUS
DispatchDeviceControl(
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
        {
            dbg_print("Processing IOCTL_QUERYSYSTEMDEBUGSTATE.");

            if (cbOutput >= sizeof(QUERYSYSTEMDEBUGSTATE_REPLY) &&
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
                    err_print(
                        "BpmQuerySystemDebugState failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
        }
        case IOCTL_SETHARDWAREBREAKPOINT:
        {
            dbg_print("Processing IOCTL_SETHARDWAREBREAKPOINT.");

            if (cbInput >= sizeof(SETHARDWAREBREAKPOINT_REQUEST) &&
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
                    err_print(
                        "BpmSetHardwareBreakpoint failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
        }
        case IOCTL_CLEARHARDWAREBREAKPOINT:
        {
            dbg_print("Processing IOCTL_CLEARHARDWAREBREAKPOINT.");

            if (cbInput >= sizeof(CLEARHARDWAREBREAKPOINT_REQUEST)
                && pSystemBuffer)
            {
                PCLEARHARDWAREBREAKPOINT_REQUEST pRequest =
                    (PCLEARHARDWAREBREAKPOINT_REQUEST)pSystemBuffer;

                ntstatus = BpmClearHardwareBreakpoint(pRequest->Index);
                if (!NT_SUCCESS(ntstatus))
                {
                    err_print(
                        "BpmClearHardwareBreakpoint failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
        }
        case IOCTL_CAPTUREUNIQUEREGVALS:
        {
            dbg_print("Processing IOCTL_CAPTUREUNIQUEREGVALS.");

            if (cbInput >= sizeof(CAPTUREUNIQUEREGVALS_REQUEST) &&
                cbOutput >= sizeof(CAPTUREUNIQUEREGVALS_REPLY) &&
                pSystemBuffer)
            {
                PCAPTUREUNIQUEREGVALS_REQUEST pRequest =
                    (PCAPTUREUNIQUEREGVALS_REQUEST)pSystemBuffer;
                PCAPTUREUNIQUEREGVALS_REPLY pReply =
                    (PCAPTUREUNIQUEREGVALS_REPLY)pSystemBuffer;

                ntstatus = CecCaptureUniqueRegisterValues(
                    pRequest->ProcessId,
                    pRequest->Index,
                    pRequest->Address,
                    pRequest->Type,
                    pRequest->Size,
                    pRequest->RegisterKey,
                    pRequest->DurationInMilliseconds,
                    (PCAPTURED_UNIQUE_REGVALS)pReply,
                    cbOutput);
                if (NT_SUCCESS(ntstatus))
                {
                    Information = pReply->Size;
                }
                else
                {
                    err_print(
                        "CecCaptureUniqueRegisterValues failed: 0x%X",
                        ntstatus);
                }
            }
            else
            {
                ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            }

            break;
        }
        default:
        {
            ntstatus = STATUS_NOINTERFACE;
            err_print("Unhandled IOCTL: 0x%X.", pIrpStack->MajorFunction);
            break;
        }
    }

    pIrp->IoStatus.Information = Information;
    pIrp->IoStatus.Status = ntstatus;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ntstatus;
}