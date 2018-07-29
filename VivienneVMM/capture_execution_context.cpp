/*++

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

#include "breakpoint_manager.h"
#include "log_util.h"
#include "register_util.h"

#include "..\common\time_util.h"

#include "HyperPlatform\log.h"


//=============================================================================
// Constants and Macros
//=============================================================================
#define CEC_TAG 'TceC'

#define CEC_MAX_DURATION_MS     (SECONDS_TO_MILLISECONDS(10))

#ifdef CFG_VERBOSE_CAPTUREEXECUTIONCONTEXT
#define cec_verbose_print       info_print
#else
#define cec_verbose_print(Format, ...) ((VOID)0)
#endif


//=============================================================================
// Internal Types
//=============================================================================

//
// This breakpoint callback context represents an active CURV request.
//
typedef struct _CEC_CALLBACK_CONTEXT
{
    ULONG RegisterKey; // See REGISTER_*.
    KSPIN_LOCK Lock;
    _Write_guarded_by_(Lock) ULONG ExceptionCount;
    _Guarded_by_(Lock) PCAPTURED_UNIQUE_REGVALS CapturedCtx;
} CEC_CALLBACK_CONTEXT, *PCEC_CALLBACK_CONTEXT;

//
// The capture execution context callback stores unique values for a target
//  register for the duration of its corresponding breakpoint. This callback
//  allows the user to sample the register context for an instruction (or data
//  access) without hooking the target memory via code patching.
//
typedef struct _CEC_MANAGER_STATE
{
    //
    // We use one mutex for each debug address register to ensure that only one
    //  CURV request is using a debug address register at any given time.
    //
    // NOTE These mutexes do not prevent users from installing a breakpoint,
    //  via the breakpoint manager interface, in a debug address register which
    //  is being used to complete a CURV request.
    //
    KGUARDED_MUTEX DarMutexes[DAR_COUNT];
} CEC_MANAGER_STATE, *PCEC_MANAGER_STATE;


//=============================================================================
// Module Globals
//=============================================================================
CEC_MANAGER_STATE g_CecManager = {};


//=============================================================================
// Internal Prototypes
//=============================================================================
_Check_return_
static
NTSTATUS
CeciSanitizeDebugRegisterIndex(
    _In_ ULONG Index
);

_Check_return_
static
NTSTATUS
CeciSanitizeRegisterKey(
    _In_ ULONG RegisterKey
);

_Check_return_
static
NTSTATUS
CeciInitializeInterval(
    _In_ ULONG DurationInMilliseconds,
    _Out_ PLARGE_INTEGER pInterval
);

static
VOID
CeciInitializeCurvContext(
    _Inout_ PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    _In_ ULONG cbCapturedCtx
);

_Check_return_
static
NTSTATUS
CeciInitializeCurvCallbackContext(
    _Inout_ PCEC_CALLBACK_CONTEXT pCallbackCtx,
    _In_ PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    _In_ ULONG RegisterKey
);

_IRQL_requires_min_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
CeciVmxBreakpointCallback(
    _In_ ULONG OwnerIndex,
    _Inout_ GpRegisters* pGuestRegisters,
    _Inout_ FlagRegister* pGuestFlags,
    _In_ ULONG_PTR GuestIp,
    _Inout_ PVOID pCallbackCtx
);


//=============================================================================
// Meta Interface
//=============================================================================

//
// CecInitialization
//
_Use_decl_annotations_
NTSTATUS
CecInitialization()
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    info_print("Initializing capture execution context.");

    for (ULONG i = 0; i < DAR_COUNT; ++i)
    {
        KeInitializeGuardedMutex(&g_CecManager.DarMutexes[i]);
    }

    return ntstatus;
}


//=============================================================================
// Client Interface
//=============================================================================

//
// CecCaptureUniqueRegisterValues
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
CecCaptureUniqueRegisterValues(
    ULONG_PTR ProcessId,
    ULONG Index,
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size,
    ULONG RegisterKey,
    ULONG DurationInMilliseconds,
    PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    ULONG cbCapturedCtx
)
{
    HARDWARE_BREAKPOINT Breakpoint = {};
    LARGE_INTEGER DelayInterval = {};
    PCEC_CALLBACK_CONTEXT pCecCtx = {};
    BOOLEAN HasMutex = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    // Sanitize in parameters.
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

    // The debug register index should have been sanitized by the breakpoint
    //  constructor, but we perform internal sanitization because the index
    //  determines which mutex we acquire.
    ntstatus = CeciSanitizeDebugRegisterIndex(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("CeciSanitizeDebugRegisterIndex failed: 0x%X", ntstatus);
        goto exit;
    }

    ntstatus = CeciInitializeInterval(DurationInMilliseconds, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("CeciInitializeInterval failed: 0x%X", ntstatus);
        goto exit;
    }

    // The callback context must be allocated from the nonpaged pool because it
    //  will be accessed at HIGH_LEVEL.
#pragma warning(suppress : 30030) // NonPagedPoolNx is only available in Win8+.
    pCecCtx = (PCEC_CALLBACK_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pCecCtx),
        CEC_TAG);
    if (!pCecCtx)
    {
        err_print("Out of memory.");
        ntstatus = STATUS_NO_MEMORY;
        goto exit;
    }

    // Initialize contexts.
    CeciInitializeCurvContext(pCapturedCtx, cbCapturedCtx);
    
    ntstatus = CeciInitializeCurvCallbackContext(
        pCecCtx,
        pCapturedCtx,
        RegisterKey);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print(
            "CeciInitializeCurvCallbackContext (CURV) failed: 0x%X",
            ntstatus);
        goto exit;
    }

    cec_verbose_print(
        "CEC: CURV request start: DR%u, pid=0x%IX (%Iu), address=0x%IX, type=%c, size=%c, reg=0x%X, time=%u",
        Breakpoint.Index,
        Breakpoint.ProcessId,
        Breakpoint.ProcessId,
        Breakpoint.Address,
        HwBpTypeToChar(Breakpoint.Type),
        HwBpSizeToChar(Breakpoint.Size),
        RegisterKey,
        DurationInMilliseconds);

    // Acquire the mutex for the target debug address register.
    KeAcquireGuardedMutex(&g_CecManager.DarMutexes[Index]);
    HasMutex = TRUE;

    // Install the hardware breakpoint on all processors.
    ntstatus = BpmSetHardwareBreakpoint(
        ProcessId,
        Index,
        Address,
        Type,
        Size,
        CeciVmxBreakpointCallback,
        pCecCtx);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmSetHardwareBreakpoint (CURV) failed: 0x%X", ntstatus);
        goto exit;
    }

    // Allow the breakpoint to be active for the desired duration.
    //
    // NOTE We do not fail the request if the timer expires.
    //
    ntstatus = KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print(
            "KeDelayExecutionThread (CURV) returned unexpected status: 0x%X",
            ntstatus);
    }

    // Clear the breakpoint.
    ntstatus = BpmClearHardwareBreakpoint(Index);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("BpmClearHardwareBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    cec_verbose_print(
        "CEC: CURV request complete: processed %u exceptions.",
        pCecCtx->ExceptionCount);

exit:
    if (HasMutex)
    {
        KeReleaseGuardedMutex(&g_CecManager.DarMutexes[Index]);
    }

    if (pCecCtx)
    {
        ExFreePoolWithTag(pCecCtx, CEC_TAG);
    }

    return ntstatus;
}


//=============================================================================
// Internal Interface
//=============================================================================

//
// CeciSanitizeDebugRegisterIndex
//
_Use_decl_annotations_
static
NTSTATUS
CeciSanitizeDebugRegisterIndex(
    ULONG Index
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    if (DAR_COUNT <= Index)
    {
        ntstatus = STATUS_INVALID_PARAMETER;
        goto exit;
    }

exit:
    return ntstatus;
}


//
// CeciSanitizeRegisterKey
//
_Use_decl_annotations_
static
NTSTATUS
CeciSanitizeRegisterKey(
    ULONG RegisterKey
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    switch (RegisterKey)
    {
        case REGISTER_RIP:
        case REGISTER_RAX:
        case REGISTER_RCX:
        case REGISTER_RDX:
        case REGISTER_RDI:
        case REGISTER_RSI:
        case REGISTER_RBX:
        case REGISTER_RBP:
        case REGISTER_RSP:
        case REGISTER_R8:
        case REGISTER_R9:
        case REGISTER_R10:
        case REGISTER_R11:
        case REGISTER_R12:
        case REGISTER_R13:
        case REGISTER_R14:
        case REGISTER_R15:
        {
            break;
        }
        case REGISTER_INVALID:
        {
            __fallthrough;
        }
        default:
        {
            ntstatus = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    return ntstatus;
}


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

    // Sanity check: The final time should be negative.
    if (pInterval->QuadPart >= 0)
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

exit:
    return ntstatus;
}


//
// CeciInitializeCurvContext
//
// CAPTURED_UNIQUE_REGVALS constructor.
//
_Use_decl_annotations_
static
VOID
CeciInitializeCurvContext(
    PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    ULONG cbCapturedCtx
)
{
    RtlSecureZeroMemory(pCapturedCtx, cbCapturedCtx);

    pCapturedCtx->Size = cbCapturedCtx;
    pCapturedCtx->MaxIndex =
        (cbCapturedCtx - FIELD_OFFSET(CAPTURED_UNIQUE_REGVALS, Values))
            / (RTL_FIELD_SIZE(CAPTURED_UNIQUE_REGVALS, Values));
}


//
// CeciInitializeCurvCallbackContext
//
// CEC_CALLBACK_CONTEXT constructor.
//
_Use_decl_annotations_
static
NTSTATUS
CeciInitializeCurvCallbackContext(
    PCEC_CALLBACK_CONTEXT pCallbackCtx,
    PCAPTURED_UNIQUE_REGVALS pCapturedCtx,
    ULONG RegisterKey
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    RtlSecureZeroMemory(pCallbackCtx, sizeof(*pCallbackCtx));

    ntstatus = CeciSanitizeRegisterKey(RegisterKey);
    if (!NT_SUCCESS(ntstatus))
    {
        err_print("CeciSanitizeRegisterKey failed: 0x%X", ntstatus);
        goto exit;
    }

    KeInitializeSpinLock(&pCallbackCtx->Lock);
    pCallbackCtx->CapturedCtx = pCapturedCtx;
    pCallbackCtx->RegisterKey = RegisterKey;

exit:
    return ntstatus;
}


//
// CeciVmxBreakpointCallback
//
// Store unique values from the target register in the values-buffer.
//
_Use_decl_annotations_
static
NTSTATUS
CeciVmxBreakpointCallback(
    ULONG OwnerIndex,
    GpRegisters* pGuestRegisters,
    FlagRegister* pGuestFlags,
    ULONG_PTR GuestIp,
    PVOID pCallbackCtx
)
{
    PCEC_CALLBACK_CONTEXT pCecCtx = (PCEC_CALLBACK_CONTEXT)pCallbackCtx;
    ULONG_PTR RegisterValue = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OwnerIndex);
    UNREFERENCED_PARAMETER(pGuestFlags);

    //
    // NOTE Code analysis considers it invalid to acquire a spin lock at
    //  HIGH_LEVEL, but since this lock will only be acquired inside a VM exit
    //  handler it should not cause issues (famous last words). An alternate
    //  solution is to divide the values-buffer into even ranges which are
    //  indexed by processor number. This guarantees that each region can only
    //  be accessed by one processor at any given time, but will most likely
    //  result in unused buffer space because of thread affinity.
    //
#pragma warning(suppress : 28123)
    KeAcquireSpinLockAtDpcLevel(&pCecCtx->Lock);

    //
    // If the values-buffer is full then we cannot store new values so we must
    //  exit.
    //
    // NOTE Previously the CEC callback contained a completion event object
    //  which was signalled if the values-buffer became full. This was removed
    //  because KeSetEvent can only be safely called at IRQL <= DISPATCH_LEVEL.
    //  Once the values-buffer is full this callback is essentially a waste
    //  of cycles until the breakpoint timer associated with this CURV request
    //  expires.
    //
    if (pCecCtx->CapturedCtx->NumberOfValues >=
        pCecCtx->CapturedCtx->MaxIndex)
    {
        goto exit;
    }

    pCecCtx->ExceptionCount++;

    ntstatus = ReadGuestRegisterValue(
        pCecCtx->RegisterKey,
        pGuestRegisters,
        GuestIp,
        &RegisterValue);
    if (!NT_SUCCESS(ntstatus))
    {
        goto exit;
    }

    // Ignore zeros because we use zero as our end-of-values-buffer sentinel.
    if (!RegisterValue)
    {
        goto exit;
    }

    // Walk the values-buffer to determine if this is a new value.
    for (ULONG i = 0; i < pCecCtx->CapturedCtx->MaxIndex; ++i)
    {
        // We have reached the end of the buffer so this must be a new value.
        if (!pCecCtx->CapturedCtx->Values[i])
        {
            pCecCtx->CapturedCtx->Values[i] = RegisterValue;
            pCecCtx->CapturedCtx->NumberOfValues++;
            break;
        }

        // We have already recorded this value so exit.
        if (RegisterValue == pCecCtx->CapturedCtx->Values[i])
        {
            goto exit;
        }
    }

exit:
#pragma warning(suppress : 28123) // See above.
    KeReleaseSpinLockFromDpcLevel(&pCecCtx->Lock);

    return ntstatus;
}