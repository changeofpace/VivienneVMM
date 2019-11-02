/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    breakpoint_manager.cpp

Abstract:

    This module implements the hardware breakpoint manager interface.

    See BREAKPOINT_MANAGER_STATE for implementation details.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "breakpoint_manager.h"

#include <intrin.h>

#include "config.h"
#include "debug.h"
#include "log.h"
#include "process.h"

#include "HyperPlatform\HyperPlatform\util.h"
#include "HyperPlatform\HyperPlatform\vmm.h"


//=============================================================================
// Constants and Macros
//=============================================================================
#define MODULE_TITLE    "Breakpoint Manager"

#define BPM_TAG         'TmpB'

#ifdef CFG_VERBOSE_BREAKPOINTMANAGER
#define BPM_VERBOSE_PRINT   INF_PRINT
#else
#define BPM_VERBOSE_PRINT(Format, ...)
#endif


//=============================================================================
// Private Types
//=============================================================================
typedef struct _SETHARDWAREBREAKPOINT_IPI_CONTEXT {
    NTSTATUS ReturnStatus;
    BOOLEAN Enable;
    HARDWARE_BREAKPOINT Breakpoint;
    FPBREAKPOINT_CALLBACK CallbackFn;
    PVOID CallbackCtx;
} SETHARDWAREBREAKPOINT_IPI_CONTEXT, *PSETHARDWAREBREAKPOINT_IPI_CONTEXT;

//
// A description of a triggered hardware breakpoint.
//
typedef struct _DB_CONDITION {
    ULONG Index;        // Debug address register number (#).
    ULONG_PTR Address;  // Dr# value.
    BOOLEAN Local;      // DR7.L#
    BOOLEAN Global;     // DR7.G#
    HWBP_TYPE Type;     // DR7.RW#
    HWBP_SIZE Size;     // DR7.Len#
} DB_CONDITION, *PDB_CONDITION;

//
// Event tracking.
//
typedef struct _BPM_STATISTICS {
    volatile POINTER_ALIGNMENT LONG64 HandledDebugExceptions;
    volatile POINTER_ALIGNMENT LONG64 UnhandledDebugExceptions;
    volatile POINTER_ALIGNMENT LONG64 UnownedBreakpointsSeen;
} BPM_STATISTICS, *PBPM_STATISTICS;

//
// A bookkeeping entry used to associate callbacks with installed breakpoints.
//
typedef struct _BPM_DEBUG_ADDRESS_REGISTER {
    BOOLEAN Enabled;
    HARDWARE_BREAKPOINT Breakpoint;
    FPBREAKPOINT_CALLBACK CallbackFn;
    PVOID CallbackCtx;
} BPM_DEBUG_ADDRESS_REGISTER, *PBPM_DEBUG_ADDRESS_REGISTER;

//
// Bookkeeping for a logical processor used to track installed breakpoints.
//
typedef struct _BPM_PROCESSOR_STATE {
    BPM_DEBUG_ADDRESS_REGISTER DebugRegisters[DAR_COUNT];
} BPM_PROCESSOR_STATE, *PBPM_PROCESSOR_STATE;

//
// The core breakpoint manager struct.
//
// The breakpoint manager interface allows the usermode client process to
//  install/uninstall hardware breakpoints (now referred to as BPM-managed
//  breakpoints). Each breakpoint has a corresponding callback which is invoked
//  whenever the breakpoint condition is met. This interface is designed to be
//  extended via callbacks to implement features such as 'capture execution
//  context', patchless code hooking, etc.
//
// Each BPM-managed breakpoint is (un)installed via the following protocol:
//
//      1. Validate breakpoint parameters and construct a hardware breakpoint.
//
//      2. Issue an IPI broadcast to synchronously execute the (un)install
//          routine on all logical processors.
//
//      3. The broadcast routine executes the vmcall for setting a breakpoint.
//          This routine modifies the debug registers of the guest to reflect
//          the desired hardware breakpoint. We must modify the guest's debug
//          registers in VMX root mode so that we do not trigger MovDr VM
//          exits. (See debug_register_facade for details).
//
// The breakpoint manager processes all debug exception (#DB) VM exit events.
//  If a BPM-managed breakpoint is triggered, resulting in a #DB, the
//  breakpoint manager will execute the breakpoint's callback then consume the
//  exception. On successful VM entry, the guest is unaware that the exception
//  occurred.
//
// NOTE This module does not handle the modification of debug registers by
//  third party drivers. Debug register access performed by the windows kernel
//  for context switches is fully supported.
//
// NOTE See capture_execution_context for a breakpoint callback example.
//
typedef struct _BREAKPOINT_MANAGER_STATE {

    BPM_STATISTICS Statistics;

    //
    // Constant after initialization.
    //
    // NOTE Hot-plugging not supported.
    //
    ULONG NumberOfProcessors;

    //
    // This resource must be acquired before modifying BPM processor state.
    //  Since processor state is only modified inside of a VM exit handler, we
    //  choose to acquire and release the resource in VMX non-root operation.
    //
    POINTER_ALIGNMENT ERESOURCE Resource;
    _Guarded_by_(Resource) PBPM_PROCESSOR_STATE Processors;

} BREAKPOINT_MANAGER_STATE, *PBREAKPOINT_MANAGER_STATE;


//=============================================================================
// Module Globals
//=============================================================================
static BREAKPOINT_MANAGER_STATE g_BreakpointManager = {};


//=============================================================================
// Private Prototypes
//=============================================================================
static
VOID
BpmiCreateProcessNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

static
VOID
BpmiLogStatistics();

static KIPI_BROADCAST_WORKER BpmiIpiSetHardwareBreakpoint;

_Requires_lock_held_(g_BreakpointManager.Resource)
_Check_return_
static
NTSTATUS
BpmiSetHardwareBreakpoint(
    _In_ BOOLEAN Enable,
    _In_ PHARDWARE_BREAKPOINT pBreakpoint,
    _In_opt_ FPBREAKPOINT_CALLBACK pCallbackFn,
    _In_opt_ PVOID pCallbackCtx
);

_Requires_lock_held_(g_BreakpointManager.Resource)
_Check_return_
static
NTSTATUS
BpmiClearHardwareBreakpoint(
    _In_ ULONG Index
);

_Requires_lock_held_(g_BreakpointManager.Resource)
_Check_return_
static
NTSTATUS
BpmiCleanupBreakpoints();

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
BpmiVmxInterpretBreakpointCondition(
    _In_ ULONG Index,
    _In_ DR7 Dr7,
    _Inout_ PDB_CONDITION pCondition
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
BOOLEAN
BpmiVmxIsValidConditionForBreakpoint(
    _In_ PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister,
    _In_ PDB_CONDITION pCondition
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
VOID
BpmiVmxInvokeBreakpointCallback(
    _In_ PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _Inout_ PULONG_PTR pGuestIp
);

_IRQL_requires_(HIGH_LEVEL)
static
VOID
BpmiVmxConsumeDebugException(
    _In_ FlagRegister* GuestFlags
);


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
BpmDriverEntry()
{
    BOOLEAN fResourceInitialized = FALSE;
    ULONG cProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    SIZE_T cbProcessorStates =
        cProcessors * sizeof(*g_BreakpointManager.Processors);
    PBPM_PROCESSOR_STATE pProcessorStates = NULL;
    BOOLEAN ProcessCallbackInstalled = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT("Loading %s.", MODULE_TITLE);

    ntstatus = ExInitializeResourceLite(&g_BreakpointManager.Resource);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("ExInitializeResourceLite failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fResourceInitialized = TRUE;

    //
    // Allocate and initialize processor state.
    //
    pProcessorStates = (PBPM_PROCESSOR_STATE)ExAllocatePoolWithTag(
        NonPagedPool,
        cbProcessorStates,
        BPM_TAG);
    if (!pProcessorStates)
    {
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }
    //
    RtlSecureZeroMemory(pProcessorStates, cbProcessorStates);

    //
    // NOTE We must install the callback after allocating memory for the
    //  internal processor state because the callback may access this data.
    //
    ntstatus = PsSetCreateProcessNotifyRoutine(
        BpmiCreateProcessNotifyRoutine,
        FALSE);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("PsSetCreateProcessNotifyRoutine failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    ProcessCallbackInstalled = TRUE;

    //
    // Initialize module globals.
    //
    g_BreakpointManager.NumberOfProcessors = cProcessors;
    g_BreakpointManager.Processors = pProcessorStates;

    INF_PRINT("%s loaded.", MODULE_TITLE);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (ProcessCallbackInstalled)
        {
            VERIFY(PsSetCreateProcessNotifyRoutine(
                BpmiCreateProcessNotifyRoutine,
                TRUE));
        }

        if (pProcessorStates)
        {
            ExFreePoolWithTag(pProcessorStates, BPM_TAG);
        }

        if (fResourceInitialized)
        {
            VERIFY(ExDeleteResourceLite(&g_BreakpointManager.Resource));
        }
    }

    return ntstatus;
}


VOID
BpmDriverUnload()
{
    INF_PRINT("Unloading %s.", MODULE_TITLE);

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    //
    // Uninstall owned breakpoints.
    //
    VERIFY(BpmiCleanupBreakpoints());

    //
    // Uninstall the process notification callback.
    //
    VERIFY(
        PsSetCreateProcessNotifyRoutine(BpmiCreateProcessNotifyRoutine, TRUE));

    //
    // Release processor state resources.
    //
    ExFreePoolWithTag(g_BreakpointManager.Processors, BPM_TAG);

    BpmiLogStatistics();

    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

    VERIFY(ExDeleteResourceLite(&g_BreakpointManager.Resource));

    INF_PRINT("%s unloaded.", MODULE_TITLE);
}


//=============================================================================
// Client Interface
//=============================================================================

//
// BpmQuerySystemDebugState
//
// Query information about all BPM-managed breakpoints.
//
_Use_decl_annotations_
NTSTATUS
BpmQuerySystemDebugState(
    PSYSTEM_DEBUG_STATE pSystemDebugState,
    ULONG cbSystemDebugState
)
{
    ULONG RequiredSize = 0;
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegisters = NULL;
    PDEBUG_REGISTER_STATE pQuery = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pSystemDebugState, cbSystemDebugState);

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    RequiredSize =
        FIELD_OFFSET(SYSTEM_DEBUG_STATE, Processors) + // Size before array.
        (g_BreakpointManager.NumberOfProcessors *      // Array size.
            sizeof(pSystemDebugState->Processors));

    if (cbSystemDebugState < RequiredSize)
    {
        //
        // The client is likely querying the required size.
        //
        ntstatus = STATUS_BUFFER_OVERFLOW;
        goto exit;
    }

    pSystemDebugState->NumberOfProcessors =
        g_BreakpointManager.NumberOfProcessors;

    //
    // Copy the current state of the debug registers for all processors.
    //
    for (ULONG i = 0; i < g_BreakpointManager.NumberOfProcessors; ++i)
    {
        pBpmDebugRegisters =
            g_BreakpointManager.Processors[i].DebugRegisters;
        pQuery = pSystemDebugState->Processors[i].DebugRegisters;

        for (ULONG j = 0; j < DAR_COUNT; ++j)
        {
            pQuery[j].ProcessId =
                (ULONG_PTR)pBpmDebugRegisters[j].Breakpoint.ProcessId;
            pQuery[j].Address = pBpmDebugRegisters[j].Breakpoint.Address;
            pQuery[j].Type = pBpmDebugRegisters[j].Breakpoint.Type;
            pQuery[j].Size = pBpmDebugRegisters[j].Breakpoint.Size;
        }
    }

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

    //
    // Always set the required size.
    //
    pSystemDebugState->Size = RequiredSize;

    return ntstatus;
}


//
// BpmInitializeBreakpoint
//
// Hardware breakpoint constructor.
//
_Use_decl_annotations_
NTSTATUS
BpmInitializeBreakpoint(
    ULONG_PTR ProcessId,
    ULONG Index,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    PHARDWARE_BREAKPOINT pBreakpoint
)
{
    PEPROCESS pProcess = NULL;
    BOOLEAN fHasProcessReference = FALSE;
    ULONG cbCondition = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pBreakpoint, sizeof(*pBreakpoint));

    //
    // Validate ProcessId.
    //
    // Fail if the pid is not associated with an active process.
    //
    // NOTE This does not guarantee that the target process will be active when
    //  the breakpoint is installed.
    //
    ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pProcess);
    if (!NT_SUCCESS(ntstatus))
    {
        ntstatus = STATUS_INVALID_PARAMETER_1;
        goto exit;
    }
    //
    fHasProcessReference = TRUE;

    //
    // Validate Index.
    //
    if (DAR_COUNT <= Index)
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

    //
    // Validate Address.
    //
    // NOTE This logic must remain synchronized with the address filtering
    //  logic in BpmVmxProcessDebugExceptionEvent.
    //
    if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS < Address)
    {
        ntstatus = STATUS_INVALID_PARAMETER_3;
        goto exit;
    }

    //
    // Validate Type.
    //
    if (HWBP_TYPE::Execute != Type &&
        HWBP_TYPE::Write != Type &&
        HWBP_TYPE::Access != Type)
    {
        ntstatus = STATUS_INVALID_PARAMETER_4;
        goto exit;
    }

    //
    // Execution breakpoints must have size 1.
    //
    if (HWBP_TYPE::Execute == Type &&
        HWBP_SIZE::Byte != Size)
    {
        Size = HWBP_SIZE::Byte;
    }

    //
    // Validate Size.
    //
    // 17.2.5 Breakpoint Field Recognition
    //
    // "The LENn fields permit specification of a 1-, 2-, 4- or 8-byte range,
    //  beginning at the linear address specified in the corresponding debug
    //  register (DRn). Two-byte ranges must be aligned on word boundaries;
    //  4-byte ranges must be aligned on doubleword boundaries, 8-byte ranges
    //  must be aligned on quadword boundaries."
    //
    // Filter invalid sizes.
    //
    switch (Size)
    {
        case HWBP_SIZE::Byte:   cbCondition = 1; break;
        case HWBP_SIZE::Word:   cbCondition = 2; break;
        case HWBP_SIZE::Qword:  cbCondition = 8; break;
        case HWBP_SIZE::Dword:  cbCondition = 4; break;
        default:
            ntstatus = STATUS_INVALID_PARAMETER_5;
            goto exit;
    }

    //
    // Enforce address alignment for data breakpoints.
    //
    if (HWBP_TYPE::Execute != Type &&
        !IS_ALIGNED(Address, cbCondition))
    {
        ntstatus = STATUS_DATATYPE_MISALIGNMENT_ERROR;
        goto exit;
    }

    //
    // Set out parameters.
    //
    pBreakpoint->ProcessId = (HANDLE)ProcessId;
    pBreakpoint->Index = Index;
    pBreakpoint->Address = Address;
    pBreakpoint->Type = Type;
    pBreakpoint->Size = Size;

exit:
    if (fHasProcessReference)
    {
        ObDereferenceObject(pProcess);
    }

    return ntstatus;
}


//
// BpmSetHardwareBreakpoint
//
// Install a validated hardware breakpoint on all processors.
//
_Use_decl_annotations_
NTSTATUS
BpmSetHardwareBreakpoint(
    PHARDWARE_BREAKPOINT pBreakpoint,
    FPBREAKPOINT_CALLBACK pCallbackFn,
    PVOID pCallbackCtx
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    BPM_VERBOSE_PRINT(
        "BPM: Setting bp: Dr%u, pid=0x%IX (%Iu), addr=0x%IX, type=%c, size=%c",
        pBreakpoint->Index,
        pBreakpoint->ProcessId,
        pBreakpoint->ProcessId,
        pBreakpoint->Address,
        HwBpTypeToChar(pBreakpoint->Type),
        HwBpSizeToChar(pBreakpoint->Size));

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    ntstatus = BpmiSetHardwareBreakpoint(
        TRUE,
        pBreakpoint,
        pCallbackFn,
        pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmiSetHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

    return ntstatus;
}


//
// BpmSetHardwareBreakpoint
//
// Validate input parameters, construct a hardware breakpoint, then (un)install
//  the breakpoint on all processors.
//
_Use_decl_annotations_
NTSTATUS
BpmSetHardwareBreakpoint(
    ULONG_PTR ProcessId,
    ULONG Index,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    FPBREAKPOINT_CALLBACK pCallbackFn,
    PVOID pCallbackCtx
)
{
    HARDWARE_BREAKPOINT Breakpoint = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ntstatus = BpmInitializeBreakpoint(
        ProcessId,
        Index,
        Address,
        Type,
        Size,
        &Breakpoint);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmInitializeBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = BpmSetHardwareBreakpoint(
        &Breakpoint,
        pCallbackFn,
        pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmSetHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    return ntstatus;
}


//
// BpmClearHardwareBreakpoint
//
_Use_decl_annotations_
NTSTATUS
BpmClearHardwareBreakpoint(
    ULONG Index
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    BPM_VERBOSE_PRINT("BPM: Clearing Dr%u.", Index);

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    ntstatus = BpmiClearHardwareBreakpoint(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmiClearHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

    return ntstatus;
}


//
// BpmCleanupBreakpoints
//
// Uninstall all BPM-managed breakpoints from all processors.
//
_Use_decl_annotations_
NTSTATUS
BpmCleanupBreakpoints()
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    BPM_VERBOSE_PRINT("BPM: Cleaning up breakpoints.");

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    ntstatus = BpmiCleanupBreakpoints();
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmiCleanupBreakpoints failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

    return ntstatus;
}


//=============================================================================
// Vmx Interface
//=============================================================================

//
// BpmVmxSetHardwareBreakpoint
//
// Modify the target debug address register and its corresponding DR7 bits in
//  the guest's context to (un)install a hardware breakpoint. We modify the
//  debug registers while in VMX root mode so that we do not trigger MovDr VM
//  exits.
//
// NOTE The behavior of the L0-L3 and G0-G3 fields from DR7 do not reflect the
//  Intel specification because Microsoft implements context switches via
//  software. Local breakpoints are not automatically cleared on every task
//  switch. The only observable difference between enabling a local or global
//  hardware breakpoint is that user mode code cannot modify the G0-G3 fields.
//  We choose to use the GO-G3 fields to enable and disable breakpoints for
//  this reason.
//
_Use_decl_annotations_
NTSTATUS
BpmVmxSetHardwareBreakpoint(
    PVOID pVmxContext
)
{
    PSETHARDWAREBREAKPOINT_IPI_CONTEXT pIpiContext =
        (PSETHARDWAREBREAKPOINT_IPI_CONTEXT)pVmxContext;
    PHARDWARE_BREAKPOINT pBreakpoint = &pIpiContext->Breakpoint;
    DR7 PreviousDr7 = {UtilVmRead(VmcsField::kGuestDr7)};
    DR7 NewDr7 = PreviousDr7;
    ULONG Index = pBreakpoint->Index;
    VmxStatus vmxstatus = VmxStatus::kOk;
    BOOLEAN fRevertDr7 = FALSE;
    ULONG nProcessor = 0;
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Store the current value of the target debug address register and
    //  configure the new DR7 value.
    //
    switch (Index)
    {
        //
        // Dr0
        //
        case 0:
            NewDr7.G0 = pIpiContext->Enable;
            NewDr7.RW0 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len0 = (ULONG_PTR)pBreakpoint->Size;
            break;

        //
        // Dr1
        //
        case 1:
            NewDr7.G1 = pIpiContext->Enable;
            NewDr7.RW1 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len1 = (ULONG_PTR)pBreakpoint->Size;
            break;

        //
        // Dr2
        //
        case 2:
            NewDr7.G2 = pIpiContext->Enable;
            NewDr7.RW2 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len2 = (ULONG_PTR)pBreakpoint->Size;
            break;

        //
        // Dr3
        //
        case 3:
            NewDr7.G3 = pIpiContext->Enable;
            NewDr7.RW3 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len3 = (ULONG_PTR)pBreakpoint->Size;
            break;

        //
        // Invalid debug address register index.
        //
        default:
            ntstatus = STATUS_INVALID_TASK_INDEX;
            goto exit;
    }

    //
    // Indicate that we must now revert the guest Dr7 VMCS field if we fail
    //  after the following line.
    //
    fRevertDr7 = TRUE;

    //
    // Write the new DR7 value to the guest's VMCS.
    //
    vmxstatus = UtilVmWrite(VmcsField::kGuestDr7, NewDr7.All);
    if (VmxStatus::kOk != vmxstatus)
    {
        ntstatus = STATUS_HV_OPERATION_DENIED;
        goto exit;
    }

    //
    // Set the value of the target debug address register to the breakpoint
    //  address. The breakpoint will become active when the guest's DR7 is
    //  updated on VM entry.
    //
    // NOTE Installing a hardware breakpoint from kernel code causes the
    //  breakpoint to apply to every process on the system. This is unlike
    //  breakpoints set from user mode code which only affect the current
    //  thread.
    //
    switch (Index)
    {
        case 0: __writedr(0, pBreakpoint->Address); break;
        case 1: __writedr(1, pBreakpoint->Address); break;
        case 2: __writedr(2, pBreakpoint->Address); break;
        case 3: __writedr(3, pBreakpoint->Address); break;
        default:
            ntstatus = STATUS_HV_INVALID_VP_STATE;
            goto exit;
    }

    //
    // Update the breakpoint manager's internal state.
    //
    nProcessor = KeGetCurrentProcessorNumberEx(NULL);

    pBpmDebugRegister =
        &g_BreakpointManager.Processors[nProcessor].DebugRegisters[Index];

    pBpmDebugRegister->Enabled = pIpiContext->Enable;
    RtlCopyMemory(
        &pBpmDebugRegister->Breakpoint,
        pBreakpoint,
        sizeof(HARDWARE_BREAKPOINT));
    pBpmDebugRegister->CallbackFn = pIpiContext->CallbackFn;
    pBpmDebugRegister->CallbackCtx = pIpiContext->CallbackCtx;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        //
        // Attempt to revert the guest Dr7 VMCS field to its previous value. If
        //  we fail during this unwind then system behavior is undefined on VM
        //  entry.
        //
        if (fRevertDr7)
        {
            vmxstatus = UtilVmWrite(VmcsField::kGuestDr7, NewDr7.All);
            if (VmxStatus::kOk != vmxstatus)
            {
                ntstatus = STATUS_HV_INVALID_VP_STATE;
            }
        }
    }

    //
    // The context's return-ntstatus must only be updated to a failing status
    //  code in the event of a failure.
    //
    if (!NT_SUCCESS(ntstatus) &&
        STATUS_HV_INVALID_VP_STATE != pIpiContext->ReturnStatus)
    {
        pIpiContext->ReturnStatus = ntstatus;
    }

    return ntstatus;
}


//
// BpmVmxProcessDebugExceptionEvent
//
// Interpret the guest's debug registers and VM exit qualification to determine
//  if a BPM-managed breakpoint caused this exception. If BPM is responsible
//  for this exception then invoke the corresponding callback if we are in the
//  target process and consume the exception. If BPM is not responsible then
//  return a failing ntstatus code so that the exception is forwarded to the
//  guest.
//
// NOTE This function does not address the special case where a separate driver
//  has installed a hardware breakpoint that matches a BPM-managed breakpoint
//  in a separate debug address register. In this scenario, the exit
//  qualification indicates that the breakpoint conditions for two (or more)
//  debug address registers were met. The breakpoint manager should process the
//  exception, mask the condition for all BPM-managed breakpoints, then set the
//  non-BPM-managed breakpoint conditions as pending debug exceptions. If the
//  debug register facade is enabled then this scenario will never happen.
//
// TODO Analyze the exit qualification when a #DB is triggered for the
//  following scenarios:
//
//      1. Multiple debug address registers have the same breakpoint address
//          and corresponding breakpoint condition.
//
//      2. An execution breakpoint and a data-read breakpoint have the same
//          breakpoint address.
//
//      3. A data-read breakpoint and a data-write breakpoint have the same
//          breakpoint address.
//
_Use_decl_annotations_
NTSTATUS
BpmVmxProcessDebugExceptionEvent(
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    PULONG_PTR pGuestIp
)
{
    DebugExceptionQualification ExitQualification =
        {UtilVmRead(VmcsField::kExitQualification)};
    DR7 Dr7 = {};
    ULONG nProcessor = 0;
    DB_CONDITION Condition = {};
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    BOOLEAN fHandleThisException = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    BPM_VERBOSE_PRINT("BPM: Entering #DB VM exit handler.");

    //
    // Forward irrelevant debug exceptions to the guest.
    //
    if (ExitQualification.fields.debug_register_access)
    {
        BPM_VERBOSE_PRINT("BPM: Observed debug register access during #DB.");
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }
    else if (ExitQualification.fields.single_step_or_branch)
    {
        //
        // NOTE If this occurs then a process may be attempting some type of
        //  anti-debug technique.
        //
        BPM_VERBOSE_PRINT("BPM: Observed single step or branch during #DB.");
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    nProcessor = KeGetCurrentProcessorNumberEx(NULL);
    Dr7 = {UtilVmRead(VmcsField::kGuestDr7)};

    //
    // Examine the debug address register bitmap from the exit qualification to
    //  determine if the breakpoint whose condition was met matches a
    //  BPM-managed breakpoint.
    //
    for (ULONG i = 0; i < DAR_COUNT; ++i)
    {
        //
        // Skip debug address registers with unmet conditions.
        //
        if (!(ExitQualification.fields.condition_bitmap & DAR_INDEX_TO_BITMAP(i)))
        {
            continue;
        }

        ntstatus = BpmiVmxInterpretBreakpointCondition(i, Dr7, &Condition);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT(
                "BpmiVmxInterpretBreakpointCondition failed: 0x%X",
                ntstatus);
            goto exit;
        }

        BPM_VERBOSE_PRINT(
            "BPM: #DB Condition: index=%u, addr=0x%IX, l=%u, g=%u, type=%c,"
            " size=%c",
            Condition.Index,
            Condition.Address,
            Condition.Local,
            Condition.Global,
            HwBpTypeToChar(Condition.Type),
            HwBpSizeToChar(Condition.Size));

        pBpmDebugRegister =
            &g_BreakpointManager.Processors[nProcessor].DebugRegisters[i];

        //
        // Does the BPM-managed breakpoint in Dr[i] match the condition?
        //
        fHandleThisException = BpmiVmxIsValidConditionForBreakpoint(
            pBpmDebugRegister,
            &Condition);
        if (!fHandleThisException)
        {
            //
            // The breakpoint manager is not responsible for this condition.
            //
            InterlockedIncrement64(
                &g_BreakpointManager.Statistics.UnownedBreakpointsSeen);

            BPM_VERBOSE_PRINT(
                "BPM: Encountered #DB caused by unowned breakpoint (%lld).",
                g_BreakpointManager.Statistics.UnownedBreakpointsSeen);

            //
            // Continue enumerating the dar_bitmap.
            //
            continue;
        }

        //
        // The breakpoint manager is responsible for this condition.
        //
        break;
    }
    //
    if (!fHandleThisException)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    //-------------------------------------------------------------------------
    // NOTE We must now return a succeeding status code so that the exception
    //  is not forwarded to the guest on VM entry.
    //-------------------------------------------------------------------------

    //
    // If the breakpoint occurred in the target process then execute the
    //  registered callback.
    //
    if (PsGetProcessId(PsGetCurrentProcess()) ==
        pBpmDebugRegister->Breakpoint.ProcessId)
    {
        BpmiVmxInvokeBreakpointCallback(
            pBpmDebugRegister,
            pGuestRegisters,
            pGuestFlags,
            pGuestIp);
    }

    //
    // TODO We currently always consume the debug exception because we do not
    //  handle the scenario where a debug exception was triggered by multiple
    //  debug address registers (i.e., the exit qualification indicates that
    //  multiple conditions were met). Technically, we should only consume the
    //  exception if it is a fault (i.e., an execution breakpoint).
    //
    BpmiVmxConsumeDebugException(pGuestFlags);

    //
    // Update statistics.
    //
    InterlockedIncrement64(
        &g_BreakpointManager.Statistics.HandledDebugExceptions);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        InterlockedIncrement64(
            &g_BreakpointManager.Statistics.UnhandledDebugExceptions);

        BPM_VERBOSE_PRINT("BPM: Forwarding #DB to guest.");
    }

    return ntstatus;
}


//=============================================================================
// Private Interface
//=============================================================================

//
// BpmiCreateProcessNotifyRoutine
//
// Clear hardware breakpoints associated with a process when that process
//  terminates.
//
_Use_decl_annotations_
static
VOID
BpmiCreateProcessNotifyRoutine(
    HANDLE hParentId,
    HANDLE hProcessId,
    BOOLEAN Create
)
{
    PHARDWARE_BREAKPOINT pBreakpoint = NULL;

    UNREFERENCED_PARAMETER(hParentId);
    UNREFERENCED_PARAMETER(Create);

    //
    // Ignore process creation.
    //
    if (Create)
    {
        goto exit;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_BreakpointManager.Resource);

    //
    // Determine if the breakpoint manager owns a breakpoint assigned to this
    //  terminating process.
    //
    for (ULONG p = 0; p < g_BreakpointManager.NumberOfProcessors; ++p)
    {
        for (ULONG i = 0; i < DAR_COUNT; ++i)
        {
            pBreakpoint =
                &g_BreakpointManager.Processors[p].DebugRegisters[i].Breakpoint;

            if (hProcessId == pBreakpoint->ProcessId)
            {
                VERIFY(BpmiClearHardwareBreakpoint(i));
            }
        }
    }

    ExReleaseResourceAndLeaveCriticalRegion(&g_BreakpointManager.Resource);

exit:
    return;
}


//
// BpmiLogStatistics
//
// Print the statistics for this VM session.
//
static
VOID
BpmiLogStatistics()
{
    INF_PRINT("Breakpoint Manager Statistics");
    INF_PRINT("%16lld debug exceptions handled.",
        g_BreakpointManager.Statistics.HandledDebugExceptions);
    INF_PRINT("%16lld debug exceptions unhandled.",
        g_BreakpointManager.Statistics.UnhandledDebugExceptions);
    INF_PRINT("%16lld unowned breakpoints observed.",
        g_BreakpointManager.Statistics.UnownedBreakpointsSeen);
}


//
// BpmiIpiSetHardwareBreakpoint
//
// Enter VMX root mode to (un)install a hardware breakpoint.
//
_Use_decl_annotations_
static
ULONG_PTR
BpmiIpiSetHardwareBreakpoint(
    ULONG_PTR Argument
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ntstatus = UtilVmCall(
        HypercallNumber::kSetHardwareBreakpoint,
        (PVOID)Argument);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("UtilVmCall (kSetHardwareBreakpoint) failed: 0x%X",
            ntstatus);
    }

    return 0;
}


//
// BpmiSetHardwareBreakpoint
//
// Issue an IPI broadcast to synchronously (un)install a hardware breakpoint on
//  all processors.
//
_Use_decl_annotations_
static
NTSTATUS
BpmiSetHardwareBreakpoint(
    BOOLEAN Enable,
    PHARDWARE_BREAKPOINT pBreakpoint,
    FPBREAKPOINT_CALLBACK pCallbackFn,
    PVOID pCallbackCtx
)
{
    PSETHARDWAREBREAKPOINT_IPI_CONTEXT pIpiContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Allocate nonpaged memory for the IPI context.
    //
    pIpiContext = (PSETHARDWAREBREAKPOINT_IPI_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pIpiContext),
        BPM_TAG);
    if (!pIpiContext)
    {
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }
    //
    RtlSecureZeroMemory(pIpiContext, sizeof(*pIpiContext));

    //
    // Initialize the IPI context.
    //
    pIpiContext->ReturnStatus = STATUS_SUCCESS;
    pIpiContext->Enable = Enable;
    RtlCopyMemory(
        &pIpiContext->Breakpoint,
        pBreakpoint,
        sizeof(HARDWARE_BREAKPOINT));
    pIpiContext->CallbackFn = pCallbackFn;
    pIpiContext->CallbackCtx = pCallbackCtx;

    //
    // Install the breakpoint.
    //
    KeIpiGenericCall(BpmiIpiSetHardwareBreakpoint, (ULONG_PTR)pIpiContext);

    ntstatus = pIpiContext->ReturnStatus;
    if (!NT_SUCCESS(ntstatus))
    {
        if (STATUS_HV_INVALID_VP_STATE == ntstatus)
        {
            ERR_PRINT(
                "A failure during BpmiIpiSetHardwareBreakpoint has corrupted"
                " the guest's debug registers.");
        }
        else
        {
            ERR_PRINT("BpmiIpiSetHardwareBreakpoint failed: 0x%X", ntstatus);
        }

        goto exit;
    }

exit:
    if (pIpiContext)
    {
        ExFreePoolWithTag(pIpiContext, BPM_TAG);
    }

    return ntstatus;
}


//
// BpmiClearHardwareBreakpoint
//
// Zero a debug address register value and its corresponding DR7 bits on all
//  processors.
//
_Use_decl_annotations_
static
NTSTATUS
BpmiClearHardwareBreakpoint(
    ULONG Index
)
{
    HARDWARE_BREAKPOINT Breakpoint = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Initialize the breakpoint here instead of using the constructor function
    //  to avoid unnecessary validation.
    //
    Breakpoint.ProcessId = NULL;
    Breakpoint.Index = Index;
    Breakpoint.Address = 0;
    Breakpoint.Type = (HWBP_TYPE)0;
    Breakpoint.Size = (HWBP_SIZE)0;

    ntstatus = BpmiSetHardwareBreakpoint(FALSE, &Breakpoint, NULL, NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmiSetHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    return ntstatus;
}


_Use_decl_annotations_
static
NTSTATUS
BpmiCleanupBreakpoints()
{
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    BOOLEAN Failed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Iterate all processors.
    //
    for (ULONG p = 0; p < g_BreakpointManager.NumberOfProcessors; ++p)
    {
        //
        // Iterate all debug address registers.
        //
        for (ULONG i = 0;
            i < ARRAYSIZE(g_BreakpointManager.Processors[p].DebugRegisters);
            ++i)
        {
            pBpmDebugRegister =
                &g_BreakpointManager.Processors[p].DebugRegisters[i];

            //
            // Skip unused registers.
            //
            if (!pBpmDebugRegister->Enabled)
            {
                continue;
            }

            ntstatus = BpmiClearHardwareBreakpoint(i);
            if (!NT_SUCCESS(ntstatus))
            {
                //
                // Do not breakout on failure so that we can cleanup as
                //  many breakpoints as possible.
                //
                ERR_PRINT(
                    "BpmiClearHardwareBreakpoint failed: 0x%X, proc=%u,"
                    " dr%u",
                    ntstatus,
                    p,
                    i);
                Failed = TRUE;
            }
        }
    }

    if (Failed)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
    }

    return ntstatus;
}


//
// BpmiVmxInterpretBreakpointCondition
//
// Generate a logical representation of a breakpoint condition which caused a
//  debug exception.
//
// Params
//  Index: Debug address register number from DebugExceptionQualification.
//
// See: Table 17-2. Debug Exception Conditions
//
_Use_decl_annotations_
static
NTSTATUS
BpmiVmxInterpretBreakpointCondition(
    ULONG Index,
    DR7 Dr7,
    PDB_CONDITION pCondition
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero out parameters.
    //
    RtlSecureZeroMemory(pCondition, sizeof(*pCondition));

    switch (Index)
    {
        //
        // Dr0
        //
        case 0:
            pCondition->Index = 0;
            pCondition->Address = __readdr(0);
            pCondition->Local = Dr7.L0;
            pCondition->Global = Dr7.G0;
            pCondition->Type = (HWBP_TYPE)Dr7.RW0;
            pCondition->Size = (HWBP_SIZE)Dr7.Len0;
            break;

        //
        // Dr1
        //
        case 1:
            pCondition->Index = 1;
            pCondition->Address = __readdr(1);
            pCondition->Local = Dr7.L1;
            pCondition->Global = Dr7.G1;
            pCondition->Type = (HWBP_TYPE)Dr7.RW1;
            pCondition->Size = (HWBP_SIZE)Dr7.Len1;
            break;

        //
        // Dr2
        //
        case 2:
            pCondition->Index = 2;
            pCondition->Address = __readdr(2);
            pCondition->Local = Dr7.L2;
            pCondition->Global = Dr7.G2;
            pCondition->Type = (HWBP_TYPE)Dr7.RW2;
            pCondition->Size = (HWBP_SIZE)Dr7.Len2;
            break;

        //
        // Dr3
        //
        case 3:
            pCondition->Index = 3;
            pCondition->Address = __readdr(3);
            pCondition->Local = Dr7.L3;
            pCondition->Global = Dr7.G3;
            pCondition->Type = (HWBP_TYPE)Dr7.RW3;
            pCondition->Size = (HWBP_SIZE)Dr7.Len3;
            break;

        //
        // Invalid debug address register index.
        //
        default:
            ntstatus = STATUS_INVALID_PARAMETER_1;
            goto exit;
    }

exit:
    return ntstatus;
}


//
// BpmiVmxIsValidConditionForBreakpoint
//
// NOTE This function assumes that the condition values are valid.
//
// NOTE We do not compare the L0-L3 or G0-G3 fields because they are not
//  guaranteed to reflect the debug exception exit qualification.
//  
// See: Table 17-2. Debug Exception Conditions
// See: Table 27-1. Exit Qualification for Debug Exceptions
//
_Use_decl_annotations_
static
BOOLEAN
BpmiVmxIsValidConditionForBreakpoint(
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister,
    PDB_CONDITION pCondition
)
{
    PHARDWARE_BREAKPOINT pBreakpoint = &pBpmDebugRegister->Breakpoint;

    return
        pBreakpoint->Index == pCondition->Index &&
        pBreakpoint->Address == pCondition->Address &&
        pBreakpoint->Type == pCondition->Type &&
        pBreakpoint->Size == pCondition->Size;
}


//
// BpmiVmxInvokeBreakpointCallback
//
_Use_decl_annotations_
static
VOID
BpmiVmxInvokeBreakpointCallback(
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister,
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    PULONG_PTR pGuestIp
)
{
    ULONG_PTR GuestIpOriginal = 0;
    FlagRegister GuestFlagsOriginal = {};
    VmxStatus vmxstatus = VmxStatus::kOk;

    //
    // Ignore breakpoints which occur outside of user space.
    //
    // NOTE This logic must remain synchronized with the address validation
    //  logic in BpmInitializeBreakpoint.
    //
    if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS <= (*pGuestIp))
    {
        WRN_PRINT("Unexpected breakpoint address: 0x%IX", (*pGuestIp));
        goto exit;
    }

    //
    // Store the values of the guest instruction pointer and FLAGS register
    //  so that we can determine if the callback modified these variables.
    //
    GuestIpOriginal = *pGuestIp;
    GuestFlagsOriginal.all = pGuestFlags->all;

    //
    // Invoke the callback.
    //
    pBpmDebugRegister->CallbackFn(
        pBpmDebugRegister->Breakpoint.Index,
        pGuestRegisters,
        pGuestFlags,
        pGuestIp,
        pBpmDebugRegister->CallbackCtx);

    //
    // If the callback modified the guest instruction pointer or FLAGS register
    //  then we must update the guest VMCS to reflect these changes. We must
    //  manually modify the guest VMCS because HyperPlatform does not update
    //  these VMCS fields on VM entry.
    //
    if (GuestIpOriginal != (*pGuestIp))
    {
        BPM_VERBOSE_PRINT(
            "BPM: Modifying guest instruction pointer: 0x%IX -> 0x%IX",
            GuestIpOriginal,
            *pGuestIp);

        vmxstatus = UtilVmWrite(VmcsField::kGuestRip, (*pGuestIp));
        if (VmxStatus::kOk != vmxstatus)
        {
            ERR_PRINT("Failed to set guest instruction pointer to 0x%IX",
                *pGuestIp);
        }
    }

    if (GuestFlagsOriginal.all != pGuestFlags->all)
    {
        BPM_VERBOSE_PRINT(
            "BPM: Modifying guest flags register: 0x%IX -> 0x%IX",
            GuestFlagsOriginal.all,
            pGuestFlags->all);

        vmxstatus = UtilVmWrite(VmcsField::kGuestRflags, pGuestFlags->all);
        if (VmxStatus::kOk != vmxstatus)
        {
            ERR_PRINT("Failed to set guest flags register to 0x%IX",
                GuestFlagsOriginal);
        }
    }

exit:
    return;
}


//
// BpmiVmxConsumeDebugException
//
// Set the resume flag in the guest flags VMCS field so that the guest can
//  successfully re-execute the original instruction on VM entry.
//
// NOTE The guest is unable to use the resume flag as a detection vector
//  because the 'PUSHFD' and 'PUSHFQ' instructions clear the value of the RF
//  flag in the FLAGS image stored on the stack.
//
//  See: PUSHF/PUSHFD/PUSHFQ - Push EFLAGS Register onto the Stack
//
_Use_decl_annotations_
static
VOID
BpmiVmxConsumeDebugException(
    FlagRegister* pGuestFlags
)
{
    ULONG_PTR VmxErrorCode = 0;
    VmxStatus vmxstatus = VmxStatus::kOk;

    //
    // Set the resume flag.
    //
    pGuestFlags->fields.rf = 1;

    //
    // We manually update the guest flags VMCS field because HyperPlatform does
    //  not apply changes to the flags variable to the guest state before VM
    //  entry.
    //
    vmxstatus = UtilVmWrite(VmcsField::kGuestRflags, pGuestFlags->all);

    //
    // If we fail to set the resume flag then the guest will enter an infinite
    //  #DB trigger loop if this is an execution breakpoint.
    //
    if (VmxStatus::kOk != vmxstatus)
    {
        if (VmxStatus::kErrorWithStatus == vmxstatus)
        {
            VmxErrorCode = UtilVmRead(VmcsField::kVmInstructionError);
        }

        KeBugCheckEx(
            MANUALLY_INITIATED_CRASH,
            __readeflags(),
            (ULONG_PTR)vmxstatus,
            VmxErrorCode,
            0);
    }
}
