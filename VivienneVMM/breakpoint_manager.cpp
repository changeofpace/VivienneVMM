/*++

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
#include "log_util.h"
#include "process.h"

#include "..\common\kdebug.h"

#include "HyperPlatform\util.h"
#include "HyperPlatform\vmm.h"


//=============================================================================
// Constants and Macros
//=============================================================================
#define BPM_TAG 'TmpB'

#ifdef CFG_VERBOSE_BREAKPOINTMANAGER
#define bpm_verbose_print   info_print
#else
#define bpm_verbose_print(Format, ...) ((VOID)0)
#endif


//=============================================================================
// Internal Types
//=============================================================================
typedef struct _SETHARDWAREBREAKPOINT_IPI_CONTEXT
{
    NTSTATUS ReturnStatus;
    BOOLEAN Enable;
    HARDWARE_BREAKPOINT Breakpoint;
    FPBREAKPOINT_CALLBACK CallbackFn;
    PVOID CallbackCtx;
} SETHARDWAREBREAKPOINT_IPI_CONTEXT, *PSETHARDWAREBREAKPOINT_IPI_CONTEXT;

//
// A description of a triggered hardware breakpoint.
//
typedef struct _DB_CONDITION
{
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
typedef struct _BREAKPOINT_MANAGER_STATISTICS
{
    volatile LONG64 HandledDebugExceptions;
    volatile LONG64 UnhandledDebugExceptions;
    volatile LONG64 UnownedBreakpointsSeen;
} BREAKPOINT_MANAGER_STATISTICS, *PBREAKPOINT_MANAGER_STATISTICS;

//
// A bookkeeping entry used to associate callbacks with installed breakpoints.
//
typedef struct _BPM_DEBUG_ADDRESS_REGISTER
{
    BOOLEAN Enabled;
    HARDWARE_BREAKPOINT Breakpoint;
    FPBREAKPOINT_CALLBACK CallbackFn;
    PVOID CallbackCtx;
} BPM_DEBUG_ADDRESS_REGISTER, *PBPM_DEBUG_ADDRESS_REGISTER;

//
// Bookkeeping for a logical processor used to track installed breakpoints.
//
typedef struct _BPM_PROCESSOR_STATE
{
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
//      1: Validate breakpoint parameters and construct a hardware breakpoint.
//
//      2: Issue an IPI broadcast to synchronously execute the (un)install
//          routine on all logical processors.
//
//      3: The broadcast routine executes the vmcall for setting a breakpoint.
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
typedef struct _BREAKPOINT_MANAGER_STATE
{
    BREAKPOINT_MANAGER_STATISTICS Statistics;
    BOOLEAN ProcessCallbackInstalled;

    //
    // Constant after initialization.
    //
    // NOTE Hot-plugging not supported.
    //
    ULONG NumberOfProcessors;

    //
    // This mutex must be acquired before modifying BPM processor state. Since
    //  processor state is only modified inside of a VM exit handler, we choose
    //  to acquire and release the mutex in VMX non-root operation.
    //
    KGUARDED_MUTEX Mutex;
    _Guarded_by_(Mutex) PBPM_PROCESSOR_STATE Processors;
} BREAKPOINT_MANAGER_STATE, *PBREAKPOINT_MANAGER_STATE;


//=============================================================================
// Module Globals
//=============================================================================
static BREAKPOINT_MANAGER_STATE g_BreakpointManager = {};


//=============================================================================
// Internal Prototypes
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

_Requires_lock_held_(g_BreakpointManager.Mutex)
_Check_return_
static
NTSTATUS
BpmiSetHardwareBreakpoint(
    _In_ BOOLEAN Enable,
    _In_ PHARDWARE_BREAKPOINT pBreakpoint,
    _In_opt_ FPBREAKPOINT_CALLBACK pCallbackFn,
    _In_opt_ PVOID pCallbackCtx
);

_Requires_lock_held_(g_BreakpointManager.Mutex)
_Check_return_
static
NTSTATUS
BpmiClearHardwareBreakpoint(
    _In_ ULONG Index
);

_Requires_lock_held_(g_BreakpointManager.Mutex)
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
NTSTATUS
BpmiVmxConsumeDebugException(
    _In_ FlagRegister* GuestFlags
);


//=============================================================================
// Meta Interface
//=============================================================================

//
// BpmInitialization
//
_Use_decl_annotations_
NTSTATUS
BpmInitialization()
{
    ULONG cProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    SIZE_T cbProcessorStates =
        cProcessors * sizeof(*g_BreakpointManager.Processors);
    PBPM_PROCESSOR_STATE pProcessorStates = NULL;
    BOOLEAN ProcessCallbackInstalled = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    info_print("Initializing breakpoint manager.");

    // Allocate and initialize processor state.
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

    // NOTE We must install the callback after allocating memory for the
    //  internal processor state because the callback may access this data.
    ntstatus = PsSetCreateProcessNotifyRoutine(
        BpmiCreateProcessNotifyRoutine,
        FALSE);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("PsSetCreateProcessNotifyRoutine failed: 0x%X", ntstatus);
        goto exit;
    }

    ProcessCallbackInstalled = TRUE;

    // Initialize module globals.
    KeInitializeGuardedMutex(&g_BreakpointManager.Mutex);
    g_BreakpointManager.ProcessCallbackInstalled = ProcessCallbackInstalled;
    g_BreakpointManager.NumberOfProcessors = cProcessors;
    g_BreakpointManager.Processors = pProcessorStates;

exit:
    // Remove callbacks and free resources on failure. The order of operations
    //  must mirror the order performed above for a successful unwind.
    if (!NT_SUCCESS(ntstatus))
    {
        if (ProcessCallbackInstalled)
        {
            NTSTATUS _ntstatus = PsSetCreateProcessNotifyRoutine(
                BpmiCreateProcessNotifyRoutine,
                TRUE);
            if (!NT_SUCCESS(_ntstatus))
            {
                err_print(
                    "PsSetCreateProcessNotifyRoutine failed: 0x%X",
                    _ntstatus);
            }
        }

        if (pProcessorStates)
        {
            ExFreePoolWithTag(pProcessorStates, BPM_TAG);
        }
    }

    return ntstatus;
}


//
// BpmTermination
//
// NOTE Failing functions should not trigger an early exit.
//
_Use_decl_annotations_
NTSTATUS
BpmTermination()
{
    BOOLEAN Failed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    info_print("Terminating breakpoint manager.");

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);

    // Uninstall owned breakpoints.
    ntstatus = BpmiCleanupBreakpoints();
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmiCleanupBreakpoints failed: 0x%X", ntstatus);
        Failed = TRUE;
    }

    if (g_BreakpointManager.ProcessCallbackInstalled)
    {
        // Uninstall the process notification callback.
        ntstatus = PsSetCreateProcessNotifyRoutine(
            BpmiCreateProcessNotifyRoutine,
            TRUE);
        if (!NT_SUCCESS(ntstatus))
        {
            err_print(
                "PsSetCreateProcessNotifyRoutine failed: 0x%X",
                ntstatus);
            Failed = TRUE;
        }
    }

    // Release processor state resources.
    if (g_BreakpointManager.Processors)
    {
        ExFreePoolWithTag(g_BreakpointManager.Processors, BPM_TAG);
        g_BreakpointManager.Processors = NULL;
    }

    BpmiLogStatistics();

    KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);

    if (Failed)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
    }

    return ntstatus;
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

    // Zero out parameters.
    RtlSecureZeroMemory(pSystemDebugState, cbSystemDebugState);

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);

    RequiredSize =
        FIELD_OFFSET(SYSTEM_DEBUG_STATE, Processors) + // Size before array.
        (g_BreakpointManager.NumberOfProcessors *      // Array size.
            sizeof(pSystemDebugState->Processors));

    if (cbSystemDebugState < RequiredSize)
    {
        // The client is likely querying the required size.
        ntstatus = STATUS_BUFFER_OVERFLOW;
        goto exit;
    }

    pSystemDebugState->NumberOfProcessors =
        g_BreakpointManager.NumberOfProcessors;

    // Copy the current state of the debug registers for all processors.
    for (ULONG i = 0; i < g_BreakpointManager.NumberOfProcessors; ++i)
    {
        pBpmDebugRegisters =
            g_BreakpointManager.Processors[i].DebugRegisters;
        pQuery = pSystemDebugState->Processors[i].DebugRegisters;

        for (ULONG j = 0; j < DAR_COUNT; ++j)
        {
            pQuery[j].ProcessId = pBpmDebugRegisters[j].Breakpoint.ProcessId;
            pQuery[j].Address = pBpmDebugRegisters[j].Breakpoint.Address;
            pQuery[j].Type = pBpmDebugRegisters[j].Breakpoint.Type;
            pQuery[j].Size = pBpmDebugRegisters[j].Breakpoint.Size;
        }
    }

exit:
    KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);

    // Always set the required size.
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

    // Zero out parameters.
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

    // Validate Index.
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

    // Validate Type.
    if (HWBP_TYPE::Execute != Type &&
        HWBP_TYPE::Write != Type &&
        HWBP_TYPE::Access != Type)
    {
        ntstatus = STATUS_INVALID_PARAMETER_4;
        goto exit;
    }

    // Execution breakpoints must have size 1.
    if (HWBP_TYPE::Execute == Type &&
        HWBP_SIZE::Byte != Size)
    {
        Size = HWBP_SIZE::Byte;
    }

    //
    // Validate Size.
    //
    // Intel Manual: Breakpoint Field Recognition
    // ------------------------------------------
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
        {
            ntstatus = STATUS_INVALID_PARAMETER_5;
            goto exit;
        }
    }

    // Enforce address alignment for data breakpoints.
    if (HWBP_TYPE::Execute != Type &&
        !IS_ALIGNED(Address, cbCondition))
    {
        ntstatus = STATUS_DATATYPE_MISALIGNMENT_ERROR;
        goto exit;
    }

    // Set out parameters.
    pBreakpoint->ProcessId = ProcessId;
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
    BOOLEAN HasMutex = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    bpm_verbose_print(
        "BPM: Setting bp: Dr%u, pid=0x%IX (%Iu), addr=0x%IX, type=%c, size=%c",
        pBreakpoint->Index,
        pBreakpoint->ProcessId,
        pBreakpoint->ProcessId,
        pBreakpoint->Address,
        HwBpTypeToChar(pBreakpoint->Type),
        HwBpSizeToChar(pBreakpoint->Size));

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);
    HasMutex = TRUE;

    ntstatus = BpmiSetHardwareBreakpoint(
        TRUE,
        pBreakpoint,
        pCallbackFn,
        pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmiSetHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    if (HasMutex)
    {
        KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);
    }

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
        err_print("BpmInitializeBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = BpmSetHardwareBreakpoint(&Breakpoint, pCallbackFn, pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmSetHardwareBreakpoint failed: 0x%X", ntstatus);
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

    bpm_verbose_print("BPM: Clearing Dr%u.", Index);

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);

    ntstatus = BpmiClearHardwareBreakpoint(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmiClearHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);

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

    bpm_verbose_print("BPM: Cleaning up breakpoints.");

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);

    ntstatus = BpmiCleanupBreakpoints();
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmiCleanupBreakpoints failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);

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
    ULONG Index = pBreakpoint->Index;
    DR7 NewDr7 = {UtilVmRead(VmcsField::kGuestDr7)};
    DR7 PreviousDr7 = {UtilVmRead(VmcsField::kGuestDr7)};
    VmxStatus vmxstatus = VmxStatus::kOk;
    BOOLEAN UndoGuestModifications = FALSE;
    ULONG_PTR PreviousDarValue = 0;
    ULONG nProcessor = 0;
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    // Store the current value of the target debug address register and
    //  configure the new DR7 value.
    switch (Index)
    {
        case 0:
        {
            // Dr0.
            PreviousDarValue = __readdr(0);
            NewDr7.G0 = pIpiContext->Enable;
            NewDr7.RW0 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len0 = (ULONG_PTR)pBreakpoint->Size;
            break;
        }
        case 1:
        {
            // Dr1.
            PreviousDarValue = __readdr(1);
            NewDr7.G1 = pIpiContext->Enable;
            NewDr7.RW1 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len1 = (ULONG_PTR)pBreakpoint->Size;
            break;
        }
        case 2:
        {
            // Dr2.
            PreviousDarValue = __readdr(2);
            NewDr7.G2 = pIpiContext->Enable;
            NewDr7.RW2 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len2 = (ULONG_PTR)pBreakpoint->Size;
            break;
        }
        case 3:
        {
            // Dr3.
            PreviousDarValue = __readdr(3);
            NewDr7.G3 = pIpiContext->Enable;
            NewDr7.RW3 = (ULONG_PTR)pBreakpoint->Type;
            NewDr7.Len3 = (ULONG_PTR)pBreakpoint->Size;
            break;
        }
        default:
        {
            ntstatus = STATUS_INVALID_TASK_INDEX;
            goto exit;
        }
    }

    // Write the new DR7 value to the guest's context.
    vmxstatus = UtilVmWrite(VmcsField::kGuestDr7, NewDr7.All);
    if (VmxStatus::kOk != vmxstatus)
    {
        UndoGuestModifications = TRUE;
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
    //  breakpoints set from user code which only affect the current thread.
    //
    switch (Index)
    {
        case 0: __writedr(0, pBreakpoint->Address); break;
        case 1: __writedr(1, pBreakpoint->Address); break;
        case 2: __writedr(2, pBreakpoint->Address); break;
        case 3: __writedr(3, pBreakpoint->Address); break;
        default:
        {
            UndoGuestModifications = TRUE;
            ntstatus = STATUS_HV_INVALID_VP_STATE;
            goto exit;
        }
    }

    // Update the breakpoint manager's internal state.
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
    if (UndoGuestModifications)
    {
        //
        // We encountered an error which has corrupted the debug registers in
        //  the guest's context. Attempt to revert any changes we may have
        //  made. If we fail at any point during this reset then the values of
        //  the affected debug address registers in the guest become undefined
        //  for this processor. Expect random behavior, e.g., processes
        //  crashing if they trigger a breakpoint.
        //
        vmxstatus = UtilVmWrite(VmcsField::kGuestDr7, NewDr7.All);
        if (VmxStatus::kOk != vmxstatus)
        {
            ntstatus = STATUS_HV_INVALID_VP_STATE;
        }

        switch (Index)
        {
            case 0: __writedr(0, pBreakpoint->Address); break;
            case 1: __writedr(1, pBreakpoint->Address); break;
            case 2: __writedr(2, pBreakpoint->Address); break;
            case 3: __writedr(3, pBreakpoint->Address); break;
            default:
            {
                ntstatus = STATUS_HV_INVALID_VP_STATE;
            }
        }
    }

    // The context's return-ntstatus must only be updated to a failing status
    //  code in the event of a failure.
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
_Use_decl_annotations_
NTSTATUS
BpmVmxProcessDebugExceptionEvent(
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    ULONG_PTR GuestIp
)
{
    DebugExceptionQualification ExitQualification =
        {UtilVmRead(VmcsField::kExitQualification)};
    DR7 Dr7 = {};
    ULONG nProcessor = 0;
    DB_CONDITION Condition = {};
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    BOOLEAN ConsumeThisException = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    bpm_verbose_print("Entering #DB VM exit handler.");

    // Forward irrelevant exception causes to the guest.
    if (ExitQualification.fields.debug_register_access)
    {
        bpm_verbose_print("BPM: Observed debug register access during #DB.");
        ntstatus = STATUS_INVALID_PARAMETER_1;
        goto exit;
    }
    else if (ExitQualification.fields.single_step_or_branch)
    {
        // NOTE If this occurs then a process may be attempting some type of
        //  anti-debug technique.
        bpm_verbose_print("BPM: Observed single step or branch during #DB.");
        ntstatus = STATUS_INVALID_PARAMETER_2;
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
        // Skip debug address registers with unmet conditions.
        if (!(ExitQualification.fields.dar_bitmap & DAR_INDEX_TO_BITMAP(i)))
        {
            continue;
        }

        ntstatus = BpmiVmxInterpretBreakpointCondition(i, Dr7, &Condition);
        if (!NT_SUCCESS(ntstatus))
        {
            err_print(
                "BpmiVmxInterpretBreakpointCondition failed: 0x%X",
                ntstatus);
            goto exit;
        }

        bpm_verbose_print(
            "BPM: #DB Condition: index=%u, addr=0x%IX, l=%u, g=%u, type=%c, size=%c",
            Condition.Index,
            Condition.Address,
            Condition.Local,
            Condition.Global,
            HwBpTypeToChar(Condition.Type),
            HwBpSizeToChar(Condition.Size));

        pBpmDebugRegister =
            &g_BreakpointManager.Processors[nProcessor].DebugRegisters[i];

        // Does the BPM-managed breakpoint in Dr[i] match the condition?
        ConsumeThisException = BpmiVmxIsValidConditionForBreakpoint(
            pBpmDebugRegister,
            &Condition);
        if (!ConsumeThisException)
        {
            // The breakpoint manager is not responsible for this condition.
            InterlockedIncrement64(
                &g_BreakpointManager.Statistics.UnownedBreakpointsSeen);

            bpm_verbose_print(
                "BPM: Encountered #DB caused by unowned breakpoint (%lld).",
                g_BreakpointManager.Statistics.UnownedBreakpointsSeen);

            // Continue enumerating the dar_bitmap.
            continue;
        }

        // The breakpoint manager is responsible for this condition.
        break;
    }
    //
    if (!ConsumeThisException)
    {
        bpm_verbose_print("BPM: Forwarding #DB to guest.");
        ntstatus = STATUS_INVALID_PARAMETER_3;
        goto exit;
    }

    //
    // If the breakpoint occurred in the target process then execute the
    //  registered callback.
    //
    // NOTE If this exception occurred outside of the target process then
    //  we must still consume the exception and return success.
    //
    if ((ULONG_PTR)PsGetProcessId(PsGetCurrentProcess()) ==
        pBpmDebugRegister->Breakpoint.ProcessId)
    {
        //
        // Ignore breakpoints which occur outside of user space.
        //
        // NOTE This logic must remain synchronized with the address validation
        //  logic in BpmInitializeBreakpoint.
        //
        if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS > GuestIp)
        {
            pBpmDebugRegister->CallbackFn(
                Condition.Index,
                pGuestRegisters,
                pGuestFlags,
                GuestIp,
                pBpmDebugRegister->CallbackCtx);
        }
    }

    // Consume the exception.
    ntstatus = BpmiVmxConsumeDebugException(pGuestFlags);
    if (!NT_SUCCESS(ntstatus))
    {
        // Failing to consume this exception will cause undefined behavior on
        //  VM entry.
        err_print("BpmiVmxConsumeDebugException failed: 0x%X", ntstatus);
        ntstatus = STATUS_HV_INVALID_VP_STATE;
        goto exit;
    }

exit:
    // Update statistics.
    if (NT_SUCCESS(ntstatus))
    {
        InterlockedIncrement64(
            &g_BreakpointManager.Statistics.HandledDebugExceptions);

        bpm_verbose_print("BPM: Consuming this exception.");
    }
    else
    {
        InterlockedIncrement64(
            &g_BreakpointManager.Statistics.UnhandledDebugExceptions);

        bpm_verbose_print("BPM: Ignoring this exception.");
    }

    return ntstatus;
}


//=============================================================================
// Internal Interface
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
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(hParentId);
    UNREFERENCED_PARAMETER(Create);

    // Ignore process creation.
    if (Create)
    {
        goto exit;
    }

    KeAcquireGuardedMutex(&g_BreakpointManager.Mutex);

    // Determine if the breakpoint manager owns a breakpoint assigned to this
    //  terminating process.
    for (ULONG p = 0; p < g_BreakpointManager.NumberOfProcessors; ++p)
    {
        for (ULONG i = 0; i < DAR_COUNT; ++i)
        {
            pBreakpoint =
                &g_BreakpointManager.Processors[p].DebugRegisters[i].Breakpoint;

            if (hProcessId == (HANDLE)pBreakpoint->ProcessId)
            {
                ntstatus = BpmiClearHardwareBreakpoint(i);
                if (!NT_SUCCESS(ntstatus))
                {
                    //
                    // NOTE If we fail here then behavior is undefined if a
                    //  new process uses the terminating process's id.
                    //
                    // NOTE We do not exit the loop on failure so that we can
                    //  attempt to cleanup any remaining breakpoints assigned
                    //  to this terminating process.
                    //
                    err_print(
                        "BpmiClearHardwareBreakpoint failed: 0x%X (term pid: 0x%IX)",
                        ntstatus,
                        (ULONG_PTR)hProcessId);
                }
            }
        }
    }

    KeReleaseGuardedMutex(&g_BreakpointManager.Mutex);

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
    info_print("Breakpoint Manager Statistics");
    info_print("%16lld debug exceptions handled.",
        g_BreakpointManager.Statistics.HandledDebugExceptions);
    info_print("%16lld debug exceptions unhandled.",
        g_BreakpointManager.Statistics.UnhandledDebugExceptions);
    info_print("%16lld unowned breakpoints observed.",
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
        err_print("UtilVmCall (kSetHardwareBreakpoint) failed: 0x%X", ntstatus);
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

    // Allocate nonpaged memory for the IPI context.
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

    // Initialize the IPI context.
    pIpiContext->ReturnStatus = STATUS_SUCCESS;
    pIpiContext->Enable = Enable;
    RtlCopyMemory(
        &pIpiContext->Breakpoint,
        pBreakpoint,
        sizeof(HARDWARE_BREAKPOINT));
    pIpiContext->CallbackFn = pCallbackFn;
    pIpiContext->CallbackCtx = pCallbackCtx;

    // Install the breakpoint.
    (VOID)KeIpiGenericCall(BpmiIpiSetHardwareBreakpoint, (ULONG_PTR)pIpiContext);

    ntstatus = pIpiContext->ReturnStatus;
    if (!NT_SUCCESS(ntstatus))
    {
        if (STATUS_HV_INVALID_VP_STATE == ntstatus)
        {
            err_print(
                "A failure during BpmiIpiSetHardwareBreakpoint has corrupted the guest's debug registers.");
        }
        else
        {
            err_print("BpmiIpiSetHardwareBreakpoint failed: 0x%X", ntstatus);
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

    // Initialize the breakpoint here instead of using the constructor function
    //  to avoid unnecessary validation.
    Breakpoint.ProcessId = 0;
    Breakpoint.Index = Index;
    Breakpoint.Address = 0;
    Breakpoint.Type = (HWBP_TYPE)0;
    Breakpoint.Size = (HWBP_SIZE)0;

    ntstatus = BpmiSetHardwareBreakpoint(FALSE, &Breakpoint, NULL, NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmiSetHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    return ntstatus;
}


//
// BpmiCleanupBreakpoints
//
_Use_decl_annotations_
static
NTSTATUS
BpmiCleanupBreakpoints()
{
    PBPM_DEBUG_ADDRESS_REGISTER pBpmDebugRegister = NULL;
    BOOLEAN Failed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    // Iterate all processors.
    for (ULONG p = 0; p < g_BreakpointManager.NumberOfProcessors; ++p)
    {
        // Iterate all debug address registers.
        for (ULONG i = 0;
            i < ARRAYSIZE(g_BreakpointManager.Processors[p].DebugRegisters);
            ++i)
        {
            pBpmDebugRegister =
                &g_BreakpointManager.Processors[p].DebugRegisters[i];

            // Clear any installed breakpoints.
            if (pBpmDebugRegister->Enabled)
            {
                ntstatus = BpmiClearHardwareBreakpoint(i);
                if (!NT_SUCCESS(ntstatus))
                {
                    // Do not breakout on failure so that we can cleanup as
                    //  many breakpoints as possible.
                    err_print(
                        "BpmiClearHardwareBreakpoint failed: 0x%X, proc=%u, dr%u",
                        ntstatus,
                        p,
                        i);
                    Failed = TRUE;
                }
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

    // Zero out parameters.
    RtlSecureZeroMemory(pCondition, sizeof(*pCondition));

    switch (Index)
    {
        case 0:
        {
            // Dr0.
            pCondition->Index = 0;
            pCondition->Address = __readdr(0);
            pCondition->Local = Dr7.L0;
            pCondition->Global = Dr7.G0;
            pCondition->Type = (HWBP_TYPE)Dr7.RW0;
            pCondition->Size = (HWBP_SIZE)Dr7.Len0;
            break;
        }
        case 1:
        {
            // Dr1.
            pCondition->Index = 1;
            pCondition->Address = __readdr(1);
            pCondition->Local = Dr7.L1;
            pCondition->Global = Dr7.G1;
            pCondition->Type = (HWBP_TYPE)Dr7.RW1;
            pCondition->Size = (HWBP_SIZE)Dr7.Len1;
            break;
        }
        case 2:
        {
            // Dr2.
            pCondition->Index = 2;
            pCondition->Address = __readdr(2);
            pCondition->Local = Dr7.L2;
            pCondition->Global = Dr7.G2;
            pCondition->Type = (HWBP_TYPE)Dr7.RW2;
            pCondition->Size = (HWBP_SIZE)Dr7.Len2;
            break;
        }
        case 3:
        {
            // Dr3.
            pCondition->Index = 3;
            pCondition->Address = __readdr(3);
            pCondition->Local = Dr7.L3;
            pCondition->Global = Dr7.G3;
            pCondition->Type = (HWBP_TYPE)Dr7.RW3;
            pCondition->Size = (HWBP_SIZE)Dr7.Len3;
            break;
        }
        default:
        {
            ntstatus = STATUS_INVALID_TASK_INDEX;
            goto exit;
        }
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
//  See: Exit Qualification for Debug Exceptions (Intel Manual).
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
// BpmiVmxConsumeDebugException
//
// Set the resume flag in the RFLAGS of the guest context so that the guest can
//  successfully re-execute the original instruction on VM entry without
//  causing a second debug exception.
//
_Use_decl_annotations_
static
NTSTATUS
BpmiVmxConsumeDebugException(
    FlagRegister* pGuestFlags
)
{
    VmxStatus vmxstatus = VmxStatus::kErrorWithoutStatus;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    // Set the resume flag.
    pGuestFlags->fields.rf = 1;

    // NOTE We must manually perform the write here because the guest flags
    //  variable is not written to the guest state on VM entry.
    vmxstatus = UtilVmWrite(VmcsField::kGuestRflags, pGuestFlags->all);
    if (VmxStatus::kOk == vmxstatus)
    {
        ntstatus = STATUS_SUCCESS;
    }

    return ntstatus;
}
