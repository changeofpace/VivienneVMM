/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    capture_execution_context.cpp

Abstract:

    This module implements the capture execution context callback.

    See CEC_MANAGER_STATE for implementation details.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "capture_execution_context.h"

#include <intrin.h>

#include "breakpoint_manager.h"
#include "config.h"
#include "ioctl_validation.h"
#include "log.h"
#include "register_util.h"

#include "..\common\time_util.h"

#include "HyperPlatform\HyperPlatform\log.h"
#include "HyperPlatform\HyperPlatform\util.h"
#include "HyperPlatform\HyperPlatform\vmm.h"


//=============================================================================
// Constants and Macros
//=============================================================================
#define CEC_TAG 'TceC'

#define CEC_MAX_DURATION_MS     (SECONDS_TO_MILLISECONDS(10))

#ifdef CFG_VERBOSE_CAPTUREEXECUTIONCONTEXT
#define CEC_VERBOSE_PRINT   INF_PRINT
#else
#define CEC_VERBOSE_PRINT(Format, ...)
#endif


//=============================================================================
// Private Types
//=============================================================================

//
// All callback context types must be allocated from the nonpaged pool because
//  they will be modified inside VM exit handlers. The 'Values' buffers are
//  implicitly allocated from the nonpaged pool because they are part of
//  METHOD_BUFFERED requests.
//
typedef struct _CEC_REGISTER_CALLBACK_CONTEXT {
    X64_REGISTER Register;
    KSPIN_LOCK Lock;
    _Write_guarded_by_(Lock) ULONG HitCount;
    _Guarded_by_(Lock) PCEC_REGISTER_VALUES ValuesCtx;
} CEC_REGISTER_CALLBACK_CONTEXT, *PCEC_REGISTER_CALLBACK_CONTEXT;

typedef struct _CEC_MEMORY_CALLBACK_CONTEXT {
    CEC_MEMORY_DESCRIPTION MemoryDescription;
    KSPIN_LOCK Lock;
    _Write_guarded_by_(Lock) CEC_MEMORY_STATISTICS Statistics;
    _Guarded_by_(Lock) PCEC_MEMORY_VALUES ValuesCtx;
} CEC_MEMORY_CALLBACK_CONTEXT, *PCEC_MEMORY_CALLBACK_CONTEXT;

//
// The capture execution context callback stores unique values for a target
//  register for the duration of its corresponding breakpoint. This callback
//  allows the user to sample the register context for an instruction (or data
//  access) without hooking the target memory via code patching.
//
typedef struct _CEC_MANAGER_STATE {
    //
    // We use one mutex for each debug address register to ensure that only one
    //  CEC request is using a debug address register at any given time.
    //
    // NOTE These mutexes do not prevent users from installing a breakpoint,
    //  via the breakpoint manager interface, in a debug address register which
    //  is being used to complete a CEC request.
    //
    POINTER_ALIGNMENT KGUARDED_MUTEX DarMutexes[DAR_COUNT];

} CEC_MANAGER_STATE, *PCEC_MANAGER_STATE;


//=============================================================================
// Module Globals
//=============================================================================
CEC_MANAGER_STATE g_CecManager = {};


//=============================================================================
// Private Prototypes
//=============================================================================
_Check_return_
static
NTSTATUS
CeciInitializeInterval(
    _In_ ULONG DurationInMilliseconds,
    _Out_ PLARGE_INTEGER pInterval
);

_Check_return_
static
NTSTATUS
CeciInitializeRegisterCallbackContext(
    _Inout_ PCEC_REGISTER_CALLBACK_CONTEXT pCallbackCtx,
    _In_ PCEC_REGISTER_VALUES pValuesCtx,
    _In_ X64_REGISTER Register
);

static
VOID
CeciInitializeRegisterValuesContext(
    _Inout_ PCEC_REGISTER_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx
);

_IRQL_requires_min_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
CeciVmxRegisterBreakpointCallback(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _Inout_ PULONG_PTR pGuestIp,
    _Inout_ PVOID pCallbackCtx
);

_Check_return_
static
NTSTATUS
CeciInitializeMemoryCallbackContext(
    _Inout_ PCEC_MEMORY_CALLBACK_CONTEXT pCallbackCtx,
    _In_ PCEC_MEMORY_VALUES pValuesCtx,
    _In_ PCEC_MEMORY_DESCRIPTION pMemoryDescription
);

static
VOID
CeciInitializeMemoryValuesContext(
    _Inout_ PCEC_MEMORY_VALUES pValuesCtx,
    _In_ ULONG cbValuesCtx,
    _In_ MEMORY_DATA_TYPE MemoryDataType
);

_IRQL_requires_min_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
CeciVmxMemoryBreakpointCallback(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _Inout_ PULONG_PTR pGuestIp,
    _Inout_ PVOID pCallbackCtx
);


//=============================================================================
// Meta Interface
//=============================================================================
VOID
CecDriverEntry()
{
    INF_PRINT("Initializing capture execution context.");

    for (ULONG i = 0; i < DAR_COUNT; ++i)
    {
        KeInitializeGuardedMutex(&g_CecManager.DarMutexes[i]);
    }
}


//=============================================================================
// Public Interface
//=============================================================================

//
// CecCaptureRegisterValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  examine the contents of the target register and record all unique values
//  to the output buffer.
//
// NOTE This is a synchronous call which will block for the specified
//  duration. The duration is clamped to CEC_MAX_DURATION_MS to prevent
//  timeouts caused by input error.
//
_Use_decl_annotations_
NTSTATUS
CecCaptureRegisterValues(
    ULONG_PTR ProcessId,
    ULONG Index,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    X64_REGISTER Register,
    ULONG DurationInMilliseconds,
    PCEC_REGISTER_VALUES pValuesCtx,
    ULONG cbValuesCtx
)
{
    HARDWARE_BREAKPOINT Breakpoint = {};
    LARGE_INTEGER DelayInterval = {};
    PCEC_REGISTER_CALLBACK_CONTEXT pCallbackCtx = {};
    BOOLEAN HasMutex = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Validate in parameters.
    //
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

    //
    // The debug register index should have been validated by the breakpoint
    //  constructor, but we perform internal validation because the index
    //  determines which mutex we acquire.
    //
    ntstatus = IvValidateDebugRegisterIndex(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IvValidateDebugRegisterIndex failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = IvValidateGeneralPurposeRegister(Register);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IvValidateGeneralPurposeRegister failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // Convert the duration to an NT interval.
    //
    ntstatus = CeciInitializeInterval(DurationInMilliseconds, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("CeciInitializeInterval failed: 0x%X", ntstatus);
        goto exit;
    }

    pCallbackCtx = (PCEC_REGISTER_CALLBACK_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pCallbackCtx),
        CEC_TAG);
    if (!pCallbackCtx)
    {
        ERR_PRINT("Out of memory.");
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }

    //
    // Initialize contexts.
    //
    ntstatus = CeciInitializeRegisterCallbackContext(
        pCallbackCtx,
        pValuesCtx,
        Register);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "CeciInitializeRegisterCallbackContext failed: 0x%X",
            ntstatus);
        goto exit;
    }

    CeciInitializeRegisterValuesContext(pValuesCtx, cbValuesCtx);

    CEC_VERBOSE_PRINT(
        "CEC: Register request: dr%u, pid=0x%IX, addr=0x%IX, bptype=%c,"
        " bpsize=%c, reg=%s, time=%u",
        Breakpoint.Index,
        Breakpoint.ProcessId,
        Breakpoint.Address,
        HwBpTypeToChar(Breakpoint.Type),
        HwBpSizeToChar(Breakpoint.Size),
        GpRegToString(pCallbackCtx->Register),
        DurationInMilliseconds);

    //
    // Acquire the mutex for the target debug address register.
    //
    KeAcquireGuardedMutex(&g_CecManager.DarMutexes[Index]);
    HasMutex = TRUE;

    //
    // Install the hardware breakpoint on all processors.
    //
    ntstatus = BpmSetHardwareBreakpoint(
        ProcessId,
        Index,
        Address,
        Type,
        Size,
        CeciVmxRegisterBreakpointCallback,
        pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmSetHardwareBreakpoint failed: 0x%X (CECR)", ntstatus);
        goto exit;
    }

    //
    // Allow the breakpoint to be active for the desired duration.
    //
    // NOTE We do not fail the request if the timer expires.
    //
    ntstatus = KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "KeDelayExecutionThread returned unexpected status: 0x%X (CECR)",
            ntstatus);
    }

    //
    // Clear the breakpoint.
    //
    ntstatus = BpmClearHardwareBreakpoint(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmClearHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    CEC_VERBOSE_PRINT(
        "CEC: Register request complete: processed %u exceptions.",
        pCallbackCtx->HitCount);

exit:
    if (HasMutex)
    {
        KeReleaseGuardedMutex(&g_CecManager.DarMutexes[Index]);
    }

    if (pCallbackCtx)
    {
        ExFreePoolWithTag(pCallbackCtx, CEC_TAG);
    }

    return ntstatus;
}


//
// CecCaptureMemoryValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  record all unique values at the memory address defined by the memory
//  description parameter.
//
// NOTE This is a synchronous call which will block for the specified
//  duration. The duration is clamped to CEC_MAX_DURATION_MS to prevent
//  timeouts caused by input error.
//
_Use_decl_annotations_
NTSTATUS
CecCaptureMemoryValues(
    ULONG_PTR ProcessId,
    ULONG Index,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    PCEC_MEMORY_DESCRIPTION pMemoryDescription,
    ULONG DurationInMilliseconds,
    PCEC_MEMORY_VALUES pValuesCtx,
    ULONG cbValuesCtx
)
{
    HARDWARE_BREAKPOINT Breakpoint = {};
    LARGE_INTEGER DelayInterval = {};
    PCEC_MEMORY_CALLBACK_CONTEXT pCallbackCtx = {};
    BOOLEAN HasMutex = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Validate in parameters.
    //
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

    //
    // The debug register index should have been validated by the breakpoint
    //  constructor, but we perform internal validation because the index
    //  determines which mutex we acquire.
    //
    ntstatus = IvValidateDebugRegisterIndex(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IvValidateDebugRegisterIndex failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = IvValidateMemoryDescription(pMemoryDescription);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IvValidateMemoryDescription failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // Convert the duration to an NT interval.
    //
    ntstatus = CeciInitializeInterval(DurationInMilliseconds, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("CeciInitializeInterval failed: 0x%X", ntstatus);
        goto exit;
    }

    pCallbackCtx = (PCEC_MEMORY_CALLBACK_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pCallbackCtx),
        CEC_TAG);
    if (!pCallbackCtx)
    {
        ERR_PRINT("Out of memory.");
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }

    //
    // Initialize contexts.
    //
    ntstatus = CeciInitializeMemoryCallbackContext(
        pCallbackCtx,
        pValuesCtx,
        pMemoryDescription);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "CeciInitializeMemoryCallbackContext failed: 0x%X",
            ntstatus);
        goto exit;
    }

    //
    // NOTE The following call will invalidate all parameters stored in the
    //  irp system buffer.
    //
    CeciInitializeMemoryValuesContext(
        pValuesCtx,
        cbValuesCtx,
        pMemoryDescription->DataType);

#if defined(CFG_VERBOSE_CAPTUREEXECUTIONCONTEXT)
    if (pCallbackCtx->MemoryDescription.IsIndirectAddress)
    {
        CEC_VERBOSE_PRINT(
            "CEC: Memory request (ind): dr%u, pid=0x%IX, bpaddr=0x%IX,"
            " bptype=%c, bpsize=%c, mdt=%c, bsreg=%s, ixreg=%s, sf=%u,"
            " disp=%Id, time=%u",
            Breakpoint.Index,
            Breakpoint.ProcessId,
            Breakpoint.Address,
            HwBpTypeToChar(Breakpoint.Type),
            HwBpSizeToChar(Breakpoint.Size),
            MemoryDataTypeToChar(pCallbackCtx->MemoryDescription.DataType),
            GpRegToString(
                pCallbackCtx->MemoryDescription.u.IndirectAddress.BaseRegister),
            GpRegToString(
                pCallbackCtx->MemoryDescription.u.IndirectAddress.IndexRegister),
            pCallbackCtx->MemoryDescription.u.IndirectAddress.ScaleFactor,
            pCallbackCtx->MemoryDescription.u.IndirectAddress.Displacement,
            DurationInMilliseconds);
    }
    else
    {
        CEC_VERBOSE_PRINT(
            "CEC: Memory request (abs): dr%u, pid=0x%IX, bpaddr=0x%IX,"
            " bptype=%c, bpsize=%c, mdt=%c, va=0x%IX, time=%u",
            Breakpoint.Index,
            Breakpoint.ProcessId,
            Breakpoint.Address,
            HwBpTypeToChar(Breakpoint.Type),
            HwBpSizeToChar(Breakpoint.Size),
            MemoryDataTypeToChar(pCallbackCtx->MemoryDescription.DataType),
            pCallbackCtx->MemoryDescription.u.VirtualAddress,
            DurationInMilliseconds);
    }
#endif

    //
    // Acquire the mutex for the target debug address register.
    //
    KeAcquireGuardedMutex(&g_CecManager.DarMutexes[Index]);
    HasMutex = TRUE;

    //
    // Install the hardware breakpoint on all processors.
    //
    ntstatus = BpmSetHardwareBreakpoint(
        ProcessId,
        Index,
        Address,
        Type,
        Size,
        CeciVmxMemoryBreakpointCallback,
        pCallbackCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmSetHardwareBreakpoint failed: 0x%X (CECM)", ntstatus);
        goto exit;
    }

    //
    // Allow the breakpoint to be active for the desired duration.
    //
    // NOTE We do not fail the request if the timer expires.
    //
    ntstatus = KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "KeDelayExecutionThread returned unexpected status: 0x%X (CECR)",
            ntstatus);
    }

    //
    // Clear the breakpoint.
    //
    ntstatus = BpmClearHardwareBreakpoint(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("BpmClearHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // Copy statistics to the values context.
    //
    RtlCopyMemory(
        &pValuesCtx->Statistics,
        &pCallbackCtx->Statistics,
        sizeof(CEC_MEMORY_STATISTICS));

    //
    // Log statistics.
    //
    CEC_VERBOSE_PRINT(
        "CEC: Memory request complete: hits=%Iu, skips=%Iu, invpte=%Iu,"
        " utpage=%Iu, spanaddr=%Iu, sysaddr=%Iu, valerr=%Iu",
        pCallbackCtx->Statistics.HitCount,
        pCallbackCtx->Statistics.SkipCount,
        pCallbackCtx->Statistics.InvalidPteErrors,
        pCallbackCtx->Statistics.UntouchedPageErrors,
        pCallbackCtx->Statistics.SpanningAddressErrors,
        pCallbackCtx->Statistics.SystemAddressErrors,
        pCallbackCtx->Statistics.ValidationErrors);

exit:
    if (HasMutex)
    {
        KeReleaseGuardedMutex(&g_CecManager.DarMutexes[Index]);
    }

    if (pCallbackCtx)
    {
        ExFreePoolWithTag(pCallbackCtx, CEC_TAG);
    }

    return ntstatus;
}


//=============================================================================
// Private Interface
//=============================================================================

//
// CeciInitializeInterval
//
// Convert the desired duration in milliseconds to a valid NT delay interval.
//
_Use_decl_annotations_
static
NTSTATUS
CeciInitializeInterval(
    ULONG DurationInMilliseconds,
    PLARGE_INTEGER pInterval
)
{
    ULONG ClampedDuration = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    if (!DurationInMilliseconds)
    {
        ntstatus = STATUS_INVALID_PARAMETER_1;
        goto exit;
    }

    ClampedDuration =
        DurationInMilliseconds > CEC_MAX_DURATION_MS
        ? CEC_MAX_DURATION_MS
        : DurationInMilliseconds;

    pInterval->QuadPart = MILLISECONDS_TO_RELATIVE_NTINTERVAL(ClampedDuration);

    //
    // Sanity check: The final time should be negative.
    //
    if (pInterval->QuadPart >= 0)
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

exit:
    return ntstatus;
}


//=============================================================================
// Capture Register Values Interface
//=============================================================================

//
// CeciInitializeRegisterCallbackContext
//
// CEC_REGISTER_CALLBACK_CONTEXT constructor.
//
_Use_decl_annotations_
static
NTSTATUS
CeciInitializeRegisterCallbackContext(
    PCEC_REGISTER_CALLBACK_CONTEXT pCallbackCtx,
    PCEC_REGISTER_VALUES pValuesCtx,
    X64_REGISTER Register
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    RtlSecureZeroMemory(pCallbackCtx, sizeof(*pCallbackCtx));

    pCallbackCtx->Register = Register;
    KeInitializeSpinLock(&pCallbackCtx->Lock);
    pCallbackCtx->ValuesCtx = pValuesCtx;

    return ntstatus;
}


//
// CeciInitializeRegisterValuesContext
//
// CEC_REGISTER_VALUES constructor.
//
// NOTE This function zeros the request's values buffer which is backed by the
//  irp's system buffer. All required ioctl data should be copied to local
//  storage before invoking This function.
//
_Use_decl_annotations_
static
VOID
CeciInitializeRegisterValuesContext(
    PCEC_REGISTER_VALUES pValuesCtx,
    ULONG cbValuesCtx
)
{
    RtlSecureZeroMemory(pValuesCtx, cbValuesCtx);

    pValuesCtx->Size = cbValuesCtx;
    pValuesCtx->MaxIndex =
        (cbValuesCtx - FIELD_OFFSET(CEC_REGISTER_VALUES, Values))
            / (RTL_FIELD_SIZE(CEC_REGISTER_VALUES, Values));
}


//
// CeciVmxRegisterBreakpointCallback
//
// Store unique values from the target register in the values buffer.
//
_Use_decl_annotations_
static
NTSTATUS
CeciVmxRegisterBreakpointCallback(
    ULONG OwnerIndex,
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    PULONG_PTR pGuestIp,
    PVOID pCallbackCtx
)
{
    PCEC_REGISTER_CALLBACK_CONTEXT pCecCtx =
        (PCEC_REGISTER_CALLBACK_CONTEXT)pCallbackCtx;
    ULONG_PTR RegisterValue = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OwnerIndex);
    UNREFERENCED_PARAMETER(pGuestFlags);

    //
    // NOTE Code analysis considers it invalid to acquire a spin lock at
    //  HIGH_LEVEL, but since this lock will only be acquired inside a VM exit
    //  handler it should not cause issues (famous last words). An alternate
    //  solution is to divide the values buffer into even ranges which are
    //  indexed by processor number. This guarantees that each region can only
    //  be accessed by one processor at any given time, but will most likely
    //  result in unused buffer space because of thread affinity.
    //
#pragma warning(suppress : 28123)
    KeAcquireSpinLockAtDpcLevel(&pCecCtx->Lock);

    pCecCtx->HitCount++;

    //
    // If the values buffer is full then we cannot store new values so we must
    //  exit.
    //
    // NOTE Previously the CEC callback contained a completion event object
    //  which was signalled if the values buffer became full. This was removed
    //  because KeSetEvent can only be safely called at IRQL <= DISPATCH_LEVEL.
    //  Once the values buffer is full this callback is essentially a waste
    //  of cycles until the breakpoint timer associated with this CECR request
    //  expires.
    //
    if (pCecCtx->ValuesCtx->NumberOfValues >=
        pCecCtx->ValuesCtx->MaxIndex)
    {
        goto exit;
    }

    ntstatus = ReadGuestGpRegisterValue(
        pCecCtx->Register,
        pGuestRegisters,
        *pGuestIp,
        &RegisterValue);
    if (!NT_SUCCESS(ntstatus))
    {
        goto exit;
    }

    //
    // Ignore zeros because we use zero as our end-of-values-buffer sentinel.
    //
    if (!RegisterValue)
    {
        goto exit;
    }

    //
    // Walk the values buffer to determine if this is a new value.
    //
    for (ULONG i = 0; i < pCecCtx->ValuesCtx->MaxIndex; ++i)
    {
        //
        // We have reached the end of the buffer so this must be a new value.
        //
        if (!pCecCtx->ValuesCtx->Values[i])
        {
            pCecCtx->ValuesCtx->Values[i] = RegisterValue;
            pCecCtx->ValuesCtx->NumberOfValues++;
            break;
        }

        //
        // We have already recorded this value so exit.
        //
        if (RegisterValue == pCecCtx->ValuesCtx->Values[i])
        {
            goto exit;
        }
    }

exit:
#pragma warning(suppress : 28123) // See above.
    KeReleaseSpinLockFromDpcLevel(&pCecCtx->Lock);

    return ntstatus;
}


//=============================================================================
// Capture Memory Values Interface
//=============================================================================

//
// CeciInitializeMemoryCallbackContext
//
// CEC_MEMORY_CALLBACK_CONTEXT constructor.
//
_Use_decl_annotations_
static
NTSTATUS
CeciInitializeMemoryCallbackContext(
    PCEC_MEMORY_CALLBACK_CONTEXT pCallbackCtx,
    PCEC_MEMORY_VALUES pValuesCtx,
    PCEC_MEMORY_DESCRIPTION pMemoryDescription
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    RtlSecureZeroMemory(pCallbackCtx, sizeof(*pCallbackCtx));

    RtlCopyMemory(
        &pCallbackCtx->MemoryDescription,
        pMemoryDescription,
        sizeof(CEC_MEMORY_DESCRIPTION));

    KeInitializeSpinLock(&pCallbackCtx->Lock);

    pCallbackCtx->ValuesCtx = pValuesCtx;

    return ntstatus;
}


//
// CeciInitializeMemoryValuesContext
//
// CEC_MEMORY_VALUES constructor.
//
// NOTE This function zeros the request's values buffer which is backed by the
//  irp's system buffer. All required ioctl data should be copied to local
//  storage before invoking This function.
//
_Use_decl_annotations_
static
VOID
CeciInitializeMemoryValuesContext(
    PCEC_MEMORY_VALUES pValuesCtx,
    ULONG cbValuesCtx,
    MEMORY_DATA_TYPE MemoryDataType
)
{
    RtlSecureZeroMemory(pValuesCtx, cbValuesCtx);

    pValuesCtx->DataType = MemoryDataType;
    pValuesCtx->Size = cbValuesCtx;
    pValuesCtx->MaxIndex =
        (cbValuesCtx - FIELD_OFFSET(CEC_MEMORY_VALUES, Values))
            / (RTL_FIELD_SIZE(CEC_MEMORY_VALUES, Values));
}


//
// CeciVmxMemoryBreakpointCallback
//
// Store unique values at the effective address in the values buffer. The
//  effective address is calculated using the memory description parameter from
//  the corresponding CECM request.
//
// NOTE This function only accesses effective addresses which point to user
//  space.
//
_Use_decl_annotations_
static
NTSTATUS
CeciVmxMemoryBreakpointCallback(
    ULONG OwnerIndex,
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    PULONG_PTR pGuestIp,
    PVOID pCallbackCtx
)
{
    PCEC_MEMORY_CALLBACK_CONTEXT pCecCtx =
        (PCEC_MEMORY_CALLBACK_CONTEXT)pCallbackCtx;
    PINDIRECT_ADDRESS pIndirectAddress = NULL;
    ULONG_PTR BaseRegisterValue = 0;
    ULONG_PTR IndexRegisterValue = 0;
    ULONG_PTR EffectiveAddress = 0;
    ULONG_PTR HostCr3 = 0;
    ULONG_PTR GuestCr3 = 0;
    HardwarePte* pEffectivePte = NULL;
    PMEMORY_DATA_VALUE pMemoryDataValue = NULL;
    ULONG cbMemoryDataType = 0;
    ULONG_PTR EffectiveValue = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OwnerIndex);
    UNREFERENCED_PARAMETER(pGuestFlags);

#pragma warning(suppress : 28123) // See CeciVmxRegisterBreakpointCallback.
    KeAcquireSpinLockAtDpcLevel(&pCecCtx->Lock);

    pCecCtx->Statistics.HitCount++;

    //
    // If the values buffer is full then we cannot store new values so we must
    //  exit.
    //
    if (pCecCtx->ValuesCtx->NumberOfValues >=
        pCecCtx->ValuesCtx->MaxIndex)
    {
        pCecCtx->Statistics.SkipCount++;
        goto exit;
    }

    //
    // Calculate the effective target address.
    //
    if (pCecCtx->MemoryDescription.IsIndirectAddress)
    {
        pIndirectAddress = &pCecCtx->MemoryDescription.u.IndirectAddress;

        //
        // Evaluate the memory description.
        //
        ntstatus = ReadGuestGpRegisterValue(
            pIndirectAddress->BaseRegister,
            pGuestRegisters,
            *pGuestIp,
            &BaseRegisterValue);
        if (!NT_SUCCESS(ntstatus))
        {
            pCecCtx->Statistics.ValidationErrors++;
            goto exit;
        }

        EffectiveAddress = BaseRegisterValue;

        if (REGISTER_INVALID != pIndirectAddress->IndexRegister)
        {
            ntstatus = ReadGuestGpRegisterValue(
                pIndirectAddress->IndexRegister,
                pGuestRegisters,
                *pGuestIp,
                &IndexRegisterValue);
            if (!NT_SUCCESS(ntstatus))
            {
                pCecCtx->Statistics.ValidationErrors++;
                goto exit;
            }

            if (SCALE_INVALID != pIndirectAddress->ScaleFactor)
            {
                //
                // NOTE We update the index register value in-place here so
                //  that we only perform the multiplication when necessary.
                //
                IndexRegisterValue *= pIndirectAddress->ScaleFactor;
            }

            EffectiveAddress += IndexRegisterValue;
        }

        EffectiveAddress += pIndirectAddress->Displacement;
    }
    else
    {
        EffectiveAddress = pCecCtx->MemoryDescription.u.VirtualAddress;
    }

    //
    // Restrict the effective address to user space for now.
    //
    if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS <= EffectiveAddress)
    {
        pCecCtx->Statistics.SystemAddressErrors++;
        ntstatus = STATUS_INVALID_ADDRESS;
        goto exit;
    }

    //
    // Update the host CR3 so that we can access the virtual address space of
    //  the target process.
    //
    HostCr3 = __readcr3();
    GuestCr3 = VmmGetKernelCr3();
    __writecr3(GuestCr3);

    //
    // Check if the effective address is valid.
    //
    pEffectivePte = UtilAddressToPte((PVOID)EffectiveAddress);
    if (!pEffectivePte)
    {
        pCecCtx->Statistics.InvalidPteErrors++;
        goto exit;
    }

    //
    // Check if the address has been accessed.
    //
    // TODO Create a test case for this scenario.
    //
    if (!pEffectivePte->accessed)
    {
        pCecCtx->Statistics.UntouchedPageErrors++;
        goto exit;
    }

    //
    // Calculate the size of the read.
    //
    cbMemoryDataType = GetMemoryDataTypeSize(
        pCecCtx->MemoryDescription.DataType);
    if (!cbMemoryDataType)
    {
        pCecCtx->Statistics.ValidationErrors++;
        ntstatus = STATUS_INTERNAL_ERROR;
        goto exit;
    }

    //
    // Verify that reading memory-data-type-size bytes at the effective address
    //  will only access one page.
    //
    if (1 != ADDRESS_AND_SIZE_TO_SPAN_PAGES(EffectiveAddress, cbMemoryDataType))
    {
        pCecCtx->Statistics.SpanningAddressErrors++;
        goto exit;
    }

    pMemoryDataValue = (PMEMORY_DATA_VALUE)EffectiveAddress;

    //
    // TODO We store all data types in pointer-sized elements in the values
    //  buffer to reduce complexity. In the future, refactor the values buffer
    //  to have memory-data-type-sized elements.
    //
    switch (pCecCtx->MemoryDescription.DataType)
    {
        case MDT_BYTE:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Byte;
            break;
        case MDT_WORD:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Word;
            break;
        case MDT_DWORD:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Dword;
            break;
        case MDT_QWORD:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Qword;
            break;
        case MDT_FLOAT:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Float;
            break;
        case MDT_DOUBLE:
            EffectiveValue = (ULONG_PTR)pMemoryDataValue->Double;
            break;
        default:
            pCecCtx->Statistics.ValidationErrors++;
            ntstatus = STATUS_INTERNAL_ERROR;
            goto exit;
    }

    //
    // Ignore zeros because we use zero as our end-of-values-buffer sentinel.
    //
    if (!EffectiveValue)
    {
        goto exit;
    }

    //
    // Walk the values buffer to determine if this is a new value.
    //
    for (ULONG i = 0; i < pCecCtx->ValuesCtx->MaxIndex; ++i)
    {
        //
        // We have reached the end of the buffer so this must be a new value.
        //
        if (!pCecCtx->ValuesCtx->Values[i])
        {
            pCecCtx->ValuesCtx->Values[i] = EffectiveValue;
            pCecCtx->ValuesCtx->NumberOfValues++;
            break;
        }

        //
        // We have already recorded this value so exit.
        //
        if (EffectiveValue == pCecCtx->ValuesCtx->Values[i])
        {
            goto exit;
        }
    }

exit:
    if (HostCr3)
    {
        __writecr3(HostCr3);
    }

#pragma warning(suppress : 28123) // See CeciVmxRegisterBreakpointCallback.
    KeReleaseSpinLockFromDpcLevel(&pCecCtx->Lock);

    return ntstatus;
}
