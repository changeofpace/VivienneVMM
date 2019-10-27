/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    debug_register_facade.cpp

Abstract:

    This module implements the debug register facade interface.

    See FACADE_MANAGER_STATE for implementation details.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "debug_register_facade.h"

#include <intrin.h>

#include "config.h"
#include "log.h"

#include "..\common\arch_x64.h"

#include "HyperPlatform\HyperPlatform\util.h"


//=============================================================================
// Constants and Macros
//=============================================================================
#define MODULE_TITLE    "Debug Register Facade"

#define FCD_TAG         'TdcF'


//=============================================================================
// Private Types
//=============================================================================
typedef struct _FACADE_MANAGER_STATISTICS {
    volatile POINTER_ALIGNMENT LONG64 WriteEvents;
    volatile POINTER_ALIGNMENT LONG64 ReadEvents;
} FACADE_MANAGER_STATISTICS, *PFACADE_MANAGER_STATISTICS;

//
// This struct defines the 'fake' debug registers for a logical processor. The
//  facade manager implements a MovDr VM exit handler which emulates debug
//  register accesses by the guest using this set of fake registers instead of
//  the actual debug registers. This prevents the guest from overwriting a
//  BPM-managed breakpoint via NtSetContextThread and direct debug register
//  access.
//
typedef struct _FCD_PROCESSOR_STATE {
    BOOLEAN Initialized;
    ULONG_PTR DebugRegisters[DR_COUNT];
} FCD_PROCESSOR_STATE, *PFCD_PROCESSOR_STATE;

//
// The core facade manager struct.
//
// NOTE We do not need to synchronize access to the 'Processors' field because
//  each logical processor will only modify its own processor state inside VMX
//  root mode.
//
typedef struct _FACADE_MANAGER_STATE {
    FACADE_MANAGER_STATISTICS Statistics;
    PFCD_PROCESSOR_STATE Processors;
} FACADE_MANAGER_STATE, *PFACADE_MANAGER_STATE;


//=============================================================================
// Module Globals
//=============================================================================
static FACADE_MANAGER_STATE g_FacadeManager = {};


//=============================================================================
// Private Prototypes
//=============================================================================
static
VOID
FcdiLogStatistics();


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
FcdDriverEntry()
{
    ULONG cProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    SIZE_T cbProcessorStates =
        cProcessors * sizeof(*g_FacadeManager.Processors);
    PFCD_PROCESSOR_STATE pProcessorStates = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT("Loading %s.", MODULE_TITLE);

    //
    // Allocate and initialize processor state.
    //
    pProcessorStates = (PFCD_PROCESSOR_STATE)ExAllocatePoolWithTag(
        NonPagedPool,
        cbProcessorStates,
        FCD_TAG);
    if (!pProcessorStates)
    {
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }
    //
    RtlSecureZeroMemory(pProcessorStates, cbProcessorStates);

    //
    // Initialize module globals.
    //
    g_FacadeManager.Processors = pProcessorStates;

    INF_PRINT("%s loaded.", MODULE_TITLE);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pProcessorStates)
        {
            ExFreePoolWithTag(pProcessorStates, FCD_TAG);
        }
    }

    return ntstatus;
}


VOID
FcdDriverUnload()
{
    INF_PRINT("Unloading %s.", MODULE_TITLE);

    //
    // Release processor state resources.
    //
    ExFreePoolWithTag(g_FacadeManager.Processors, FCD_TAG);

    FcdiLogStatistics();

    INF_PRINT("%s unloaded.", MODULE_TITLE);
}


//=============================================================================
// Vmx Interface
//=============================================================================

//
// FcdVmxDriverEntry
//
// Initialize the fake debug registers using the current state of the guest's
//  debug registers.
//
// We must perform this initialization after the processor executes the VMON
//  instruction, but before the processor executes the VMXLAUNCH instruction.
//  If the facade is initialized outside of this window then there is a race
//  between the initilization of the facade debug registers and any MovDr
//  event. We must initialize in VMX root mode so that we do not trigger a
//  MovDr VM exit.
//
_Use_decl_annotations_
VOID
FcdVmxDriverEntry()
{
    //
    // Use the CR4 of the host in case the guest CR4 is being virtualized.
    //
    Cr4 HostCr4 = {UtilVmRead(VmcsField::kHostCr4)};
    ULONG CurrentProcessor = KeGetCurrentProcessorNumberEx(NULL);
    PFCD_PROCESSOR_STATE pFacade = NULL;

    pFacade = &g_FacadeManager.Processors[CurrentProcessor];

    pFacade->DebugRegisters[0] = __readdr(0);
    pFacade->DebugRegisters[1] = __readdr(1);
    pFacade->DebugRegisters[2] = __readdr(2);
    pFacade->DebugRegisters[3] = __readdr(3);

    //
    // TODO Refactor this code to reflect the updates to VmmpHandleDrAccess.
    //

    //
    // If debug extensions are enabled (CR4.DE = 1), accessing DR4 and/or DR5
    //  cause an invalid-opcode exception.
    //
    if (HostCr4.fields.de)
    {
        pFacade->DebugRegisters[4] = 0;
        pFacade->DebugRegisters[5] = 0;
    }
    else
    {
        pFacade->DebugRegisters[4] = __readdr(4);
        pFacade->DebugRegisters[5] = __readdr(5);
    }

    pFacade->DebugRegisters[6] = __readdr(6);
    pFacade->DebugRegisters[7] = UtilVmRead(VmcsField::kGuestDr7);

    pFacade->Initialized = TRUE;
}


//
// FcdVmxDriverUnload
//
// Copy the state of the fake debug registers to the guest's actual debug
//  registers.
//
// We must perform this termination as part of VM shutdown to prevent a race
//  condition involving invalid facade debug registers and MovDr events. We
//  must terminate in VMX root mode so that we do not trigger a MovDr VM exit.
//
_Use_decl_annotations_
VOID
FcdVmxDriverUnload()
{
    //
    // Use the CR4 of the host in case the guest CR4 is being virtualized.
    //
    Cr4 HostCr4 = {UtilVmRead(VmcsField::kHostCr4)};
    ULONG CurrentProcessor = KeGetCurrentProcessorNumberEx(NULL);
    PFCD_PROCESSOR_STATE pFacade = NULL;
    VmxStatus vmxstatus = VmxStatus::kOk;

    pFacade = &g_FacadeManager.Processors[CurrentProcessor];

    //
    // Skip uninitialized facades.
    //
    if (!pFacade->Initialized)
    {
        goto exit;
    }

    __writedr(0, pFacade->DebugRegisters[0]);
    __writedr(1, pFacade->DebugRegisters[1]);
    __writedr(2, pFacade->DebugRegisters[2]);
    __writedr(3, pFacade->DebugRegisters[3]);

    //
    // TODO Refactor this code to reflect the updates to VmmpHandleDrAccess.
    //

    //
    // If debug extensions are enabled (CR4.DE = 1), accessing DR4 and/or DR5
    //  cause an invalid-opcode exception.
    //
    if (!HostCr4.fields.de)
    {
        __writedr(4, pFacade->DebugRegisters[4]);
        __writedr(5, pFacade->DebugRegisters[5]);
    }

    __writedr(6, pFacade->DebugRegisters[6]);

    vmxstatus = UtilVmWrite(VmcsField::kGuestDr7, pFacade->DebugRegisters[7]);
    if (VmxStatus::kOk != vmxstatus)
    {
        ERR_PRINT(
            "Failed to restore Dr7 during facade teardown, val=0x%IX",
            pFacade->DebugRegisters[7]);
    }

exit:
    return;
}


_Use_decl_annotations_
VOID
FcdVmxLogMovDrEvent(
    MovDrQualification ExitQualification,
    PULONG_PTR pRegisterUsed
)
{
    ULONG CurrentProcessor = KeGetCurrentProcessorNumberEx(NULL);
    PFCD_PROCESSOR_STATE pFacade = NULL;
    ULONG Index = 0;

    pFacade = &g_FacadeManager.Processors[CurrentProcessor];

    NT_ASSERT(pFacade->Initialized);

    Index = ExitQualification.fields.debugl_register;

    NT_ASSERT(DR_COUNT > Index);

    switch ((MovDrDirection)ExitQualification.fields.direction)
    {
        case MovDrDirection::kMoveToDr:
            INF_PRINT(
                "FCD: MovDr write dr%u, new=0x%IX, old=0x%IX",
                Index,
                *pRegisterUsed,
                pFacade->DebugRegisters[Index]);
            break;

        case MovDrDirection::kMoveFromDr:
            INF_PRINT(
                "FCD: MovDr read  dr%u, val=0x%IX",
                Index,
                pFacade->DebugRegisters[Index]);
            break;

        default:
            ERR_PRINT(
                "FCD: Unexpected MovDrDirection: %d",
                ExitQualification.fields.direction);
            goto exit;
    }

exit:
    return;
}


//
// FcdVmxProcessMovDrEvent
//
// NOTE Executing a software breakpoint in this function will usually
//  hard-freeze the machine.
//
_Use_decl_annotations_
NTSTATUS
FcdVmxProcessMovDrEvent(
    MovDrQualification ExitQualification,
    PULONG_PTR pRegisterUsed
)
{
    ULONG CurrentProcessor = KeGetCurrentProcessorNumberEx(NULL);
    PFCD_PROCESSOR_STATE pFacade = NULL;
    ULONG Index = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pFacade = &g_FacadeManager.Processors[CurrentProcessor];

    NT_ASSERT(pFacade->Initialized);

    Index = ExitQualification.fields.debugl_register;

    NT_ASSERT(DR_COUNT > Index);

    //
    // Emulate the debug register access using the fake debug registers.
    //
    switch ((MovDrDirection)ExitQualification.fields.direction)
    {
        case MovDrDirection::kMoveToDr:
            pFacade->DebugRegisters[Index] = *pRegisterUsed;
            InterlockedIncrement64(&g_FacadeManager.Statistics.WriteEvents);
            break;

        case MovDrDirection::kMoveFromDr:
            *pRegisterUsed = pFacade->DebugRegisters[Index];
            InterlockedIncrement64(&g_FacadeManager.Statistics.ReadEvents);
            break;

        default:
            ntstatus = STATUS_INTERNAL_ERROR;
            goto exit;
    }

exit:
    return ntstatus;
}


//=============================================================================
// Private Interface
//=============================================================================
static
VOID
FcdiLogStatistics()
{
    INF_PRINT("Facade Manager Statistics:");
    INF_PRINT("    %16lld Write DR events.",
        g_FacadeManager.Statistics.WriteEvents);
    INF_PRINT("    %16lld Read DR events.",
        g_FacadeManager.Statistics.ReadEvents);
}
