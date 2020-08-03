/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    ept_breakpoint_manager.cpp

Abstract:

    This module implements the ept breakpoint manager interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "ept_breakpoint_manager.h"

#include <intrin.h>
#include <ntintsafe.h>

#include "debug.h"
#include "log.h"
#include "nt.h"
#include "register_util.h"
#include "system_util.h"

#include "../common/config.h"

#include "HyperPlatform/HyperPlatform/util.h"
#include "HyperPlatform/HyperPlatform/vmm.h"


//
// TODO Determine a strategy to safely probe and read vmcall context pointers
//  inside VM exit handlers.
//
// TODO Remove the concept of an 'EBM client' to allow kernel code to use the
//  EBM interface.
//
// TODO Determine if section views are always mapped at addresses that are
//  aligned to the system allocation granularity. If yes then consider using
//  an alternate strategy for locking / securing logs.
//


//=============================================================================
// Constants
//=============================================================================
#define MODULE_TITLE    "EptBreakpointManager"
#define MODULE_TAG      'TmbE'

//
// TODO This is a quick fix for hardware breakpoint manager builds.
//
#if !defined(CFG_EBM_LOG_SIZE_MAX)
#define CFG_EBM_LOG_SIZE_MAX    (0x1000 * 50)
#endif


//=============================================================================
// Macros
//=============================================================================
///#define CFG_VERBOSE_EPT_BREAKPOINT_MANAGER

#ifdef CFG_VERBOSE_EPT_BREAKPOINT_MANAGER
#define DBG_PRINT_V     DBG_PRINT
#define INF_PRINT_V     INF_PRINT
#define WRN_PRINT_V     WRN_PRINT
#define ERR_PRINT_V     ERR_PRINT
#else
#define DBG_PRINT_V(Format, ...)
#define INF_PRINT_V(Format, ...)
#define WRN_PRINT_V(Format, ...)
#define ERR_PRINT_V(Format, ...)
#endif


//=============================================================================
// Private Vmx Shared Types
//=============================================================================
/*++

Name:

    EBM_LOG_CONTEXT

Description:

    Bookkeeping object for the section and mapped views of an ept breakpoint
    log.

Remarks:

    An ept breakpoint log is a page-file-backed section with two mapped views:
    the kernel mapping and user mapping.

    The kernel mapping has read / write access to the log section. Log elements
    are inserted by 'LOG_EPT_BREAKPOINT_HIT_ROUTINE' routines in vmx root mode
    when the corresponding breakpoint condition is triggered. 

    The user mapping has read-only access to the log section. This view is
    mapped into the virtual address space of the EBM client.

    The log section is created with the 'SEC_NO_CHANGE' allocation attribute to
    prevent third parties from modifying the page protection or unmapping the
    kernel view. The virtual memory region backing the user mapping is secured
    to prevent the EBM client from modifying the page protection or unmapping
    the user view.

        TODO Determine if securing the virtual address space for the user view
        is redundant.

    In release builds, the object creation information is deleted from the
    section's object header in an effort to hide the log from third party
    drivers.

    'EBM_LOG_CONTEXT' objects are allocated from the NonPagedPool.

--*/
typedef struct _EBM_LOG_CONTEXT {

    //
    // Section bookkeeping.
    //
    PVOID SectionObject;
    HANDLE SectionHandle;
    HANDLE SecureHandle;
    SIZE_T LogViewSize;

    //
    // 'LOG_EPT_BREAKPOINT_HIT_ROUTINE' routines must acquire this lock
    //  exclusively to update log elements.
    //
    KSPIN_LOCK UpdateLock;

    //
    // The kernel view of the log section mapped into system space. RW access.
    //
    union {
        PVOID BaseAddress;
        _Guarded_by_(UpdateLock) PEPT_BREAKPOINT_LOG Log;
    } KernelMapping;

    //
    // The user view of the log section mapped into the EBM client's virtual
    //  address space. RO access.
    //
    union {
        PVOID BaseAddress;
        _Guarded_by_(UpdateLock) PEPT_BREAKPOINT_LOG Log;
    } UserMapping;

} EBM_LOG_CONTEXT, *PEBM_LOG_CONTEXT;

typedef struct _EPT_BREAKPOINT {
    HANDLE Handle;
    HANDLE ProcessId;
    PVOID GuestVirtualAddress;
    ULONG64 GuestPhysicalAddress;
    EPT_BREAKPOINT_TYPE BreakpointType;
    EPT_BREAKPOINT_SIZE BreakpointSize;
    PEBM_LOG_CONTEXT LogContext;
} EPT_BREAKPOINT, *PEPT_BREAKPOINT;


//=============================================================================
// Private Vmx Non-Root Types
//=============================================================================
/*++

Name:

    LOCKED_PAGE_ENTRY

Description:

    Bookkeeping object for locked pages that contain active ept breakpoints.

Remarks:

    During ept breakpoint installation, we lock the physical page that contains
    the breakpoint address to prevent that page from being paged out or stolen
    by ntoskrnl. A 'locked page entry' is a bookkeeping object for tracking
    these locked pages.

    Each ept breakpoint is tied to a single locked page entry. A single locked
    page entry can have multiple ept breakpoints tied to it.

    Locked page entries are 'keyed' by the process context in which they were
    locked. Therefore, it is possible to have multiple locked page entries for
    a single physical page. For example, suppose that a physical page is shared
    between process 'A' and process 'B'. If we install an ept breakpoint at an
    address which maps to that shared page in process 'A', and we repeat this
    action in process 'B', then there will be two locked page entries which
    represent the same physical page.

    Locking a page increments the 'ReferenceCount' of the corresponding MMPFN
    object. If a locked page entry's physical page is freed by the original
    owner process then all ept breakpoints for that locked page entry become
    stale. We currently do not handle this scenario. Stale ept breakpoints are
    still considered 'active' in their corresponding breakpoint logs.

        TODO If a locked page entry becomes the last outstanding reference for
        the page then is it possible for that page to be reused by the original
        owner process?

    Locked page entries are automatically destroyed when their last ept
    breakpoint is destroyed.

    'LOCKED_PAGE_ENTRY' objects are allocated from the NonPagedPool.

--*/
typedef struct _LOCKED_PAGE_ENTRY {

    //
    // List entry for the EBM client locked page list.
    //
    // See: 'EBM_CLIENT_CONTEXT.LockedPageListHead'.
    //
    LIST_ENTRY ListEntry;

    //
    // The process context in which the EBM locked the page.
    //
    HANDLE ProcessId;
    PEPROCESS Process;

    //
    // The corresponding guest physical page for the locked page.
    //
    ULONG64 PhysicalPage;

    //
    // Resource bookkeeping.
    //
    PMDL Mdl;

    //
    // A list of 'EPT_BREAKPOINT_NON_ROOT_ENTRY' objects corresponding to
    //  active ept breakpoints in the locked page.
    //
    LIST_ENTRY BreakpointListHead;
    ULONG NumberOfBreakpoints;

} LOCKED_PAGE_ENTRY, *PLOCKED_PAGE_ENTRY;

/*++

Name:

    EPT_BREAKPOINT_NON_ROOT_ENTRY

Description:

    Bookkeeping object for active and inactive ept breakpoints in vmx non-root
    mode.

Remarks:

    An 'ept breakpoint non-root entry' is a bookkeeping container object for
    active and inactive ept breakpoints.

    An ept breakpoint is considered 'active' after it is successfully installed
    on all processors on the system. An active ept breakpoint is tied to a
    single locked page entry. The breakpoint log for an active ept breakpoint
    is readable and valid. Ept breakpoints remain active until they are
    disabled or manually cleared.

    When an active ept breakpoint is disabled, it is uninstalled from all
    processors and its corresponding non-root entry is moved from the 'active
    breakpoint list' to the 'inactive breakpoint list'. The breakpoint log for
    an inactive ept breakpoint is readable and valid, but it will no longer
    be updated by the 'LOG_EPT_BREAKPOINT_HIT_ROUTINE' routines. When a process
    terminates, all ept breakpoints targeting that process are automatically
    disabled.

    'EPT_BREAKPOINT_NON_ROOT_ENTRY' objects are allocated from the
    NonPagedPool.

--*/
typedef struct _EPT_BREAKPOINT_NON_ROOT_ENTRY {

    //
    // The vmx non-root copy of the corresponding ept breakpoint. Allocated
    //  from the NonPagedPool.
    //
    PEPT_BREAKPOINT Breakpoint;

    //
    // TRUE if the ept breakpoint is active.
    //
    BOOLEAN IsActive;

    union {
        struct {

            //
            // List entry for the breakpoint list of the 'LockedPage'.
            //
            // See: LOCKED_PAGE_ENTRY.BreakpointListHead.
            //
            LIST_ENTRY LockedPageListEntry;

            //
            // The locked page that contains this ept breakpoint.
            //
            PLOCKED_PAGE_ENTRY LockedPage;

            //
            // List entry for the active breakpoint list in the EBM client
            //  context.
            //
            // See: EBM_CLIENT_CONTEXT.ActiveBreakpointListHead.
            //
            LIST_ENTRY ListEntry;

        } Active;

        struct {

            //
            // List entry for the inactive breakpoint list in the EBM client
            //  context.
            //
            // See: EBM_CLIENT_CONTEXT.InactiveBreakpointListHead.
            //
            LIST_ENTRY ListEntry;

        } Inactive;
    } u;

} EPT_BREAKPOINT_NON_ROOT_ENTRY, *PEPT_BREAKPOINT_NON_ROOT_ENTRY;

/*++

Name:

    EBM_CLIENT_CONTEXT

Description:

    A context object associated with a single client that maintains all of the
    vmx non-root mode bookkeeping.

Remarks:

    Callers must register themselves as the EBM client before they are able to
    use the public EBM interface.

    There can only be one registered EBM client at any point in time.

    Currently, the EBM client must be a user mode process.

--*/
typedef struct _EBM_CLIENT_CONTEXT {

    //
    // The process id of the user mode client process.
    //
    // TODO Change this to be a unique identifier so that kernel code can be
    //  the EBM client.
    //
    HANDLE ProcessId;

    //
    // The unique identifier for the next ept breakpoint.
    //
    LONG_PTR NextFreeHandle;

    //
    // The list of 'LOCKED_PAGE_ENTRY' objects.
    //
    LIST_ENTRY LockedPageListHead;
    ULONG NumberOfLockedPages;

    //
    // The list of all active 'EPT_BREAKPOINT_NON_ROOT_ENTRY' objects.
    //
    LIST_ENTRY ActiveBreakpointListHead;
    ULONG NumberOfActiveBreakpoints;

    //
    // The list of all inactive 'EPT_BREAKPOINT_NON_ROOT_ENTRY' objects.
    //
    LIST_ENTRY InactiveBreakpointListHead;
    ULONG NumberOfInactiveBreakpoints;

} EBM_CLIENT_CONTEXT, *PEBM_CLIENT_CONTEXT;

/*++

Name:

    EBM_VMX_NON_ROOT_CONTEXT

Description:

    A context object that synchronizes access to the EBM client context.

Remarks:

    The gate ensures that only one thread can be executing code inside a public
    EBM vmx non-root routine.

--*/
typedef struct _EBM_VMX_NON_ROOT_CONTEXT {

    //
    // Synchronization gate.
    //
    POINTER_ALIGNMENT ERESOURCE Gate;

    //
    // If TRUE then there is a registered EBM client and 'Client' is valid. If
    //  FALSE then there is no registered EBM client and 'Client' is invalid.
    //
    _Guarded_by_(Gate) BOOLEAN ClientRegistered;

    //
    // Client context for the registered EBM client.
    //
    _Guarded_by_(Gate) EBM_CLIENT_CONTEXT Client;

} EBM_VMX_NON_ROOT_CONTEXT, *PEBM_VMX_NON_ROOT_CONTEXT;


//=============================================================================
// Private Vmx Root Types
//=============================================================================
/*++

Name:

    LOG_EPT_BREAKPOINT_HIT_ROUTINE

Description:

    A callback that logs guest context information when the corresponding
    ept breakpoint condition is triggered.

Parameters:

    pLogContext - The log context of the triggered breakpoint.

    pGuestRegisters - The guest general purpose register context when the
        breakpoint condition was triggered.

    GuestFlags - The value of the guest RFLAGS register when the breakpoint
        condition was triggered.

    GuestIp - The address of the instruction that triggered the breakpoint
        condition.

--*/
_IRQL_requires_(HIGH_LEVEL)
_Requires_exclusive_lock_held_(pLogContext->UpdateLock)
typedef
VOID
NTAPI
LOG_EPT_BREAKPOINT_HIT_ROUTINE(
    _Inout_ PEBM_LOG_CONTEXT pLogContext,
    _In_ GpRegisters* pGuestRegisters,
    _In_ FlagRegister GuestFlags,
    _In_ ULONG_PTR GuestIp
);

typedef LOG_EPT_BREAKPOINT_HIT_ROUTINE *PLOG_EPT_BREAKPOINT_HIT_ROUTINE;

/*++

Name:

    HOOKED_PAGE_ENTRY

Description:

    Bookkeeping object for hooked guest physical pages.

Remarks:

    We implement hardware breakpoint functionality by modifying the access bits
    of an ept entry so that the desired breakpoint condition triggers an ept
    violation VM exit. A 'hooked page entry' is a bookkeeping object for
    tracking the pages corresponding to these modified ept entries.

    Each processor maintains its own hooked page entry bookkeeping. Ept
    breakpoint (un)installation is implicitly synchronized by the EBM client
    gate in vmx non-root mode.

    Hooked page entries are automatically destroyed when their last ept
    breakpoint is destroyed.

    'HOOKED_PAGE_ENTRY' objects are allocated from the NonPagedPool.

--*/
typedef struct _HOOKED_PAGE_ENTRY {

    //
    // List entry for the hooked page list of an EBM processor context.
    //
    // See: 'EBM_PROCESSOR_CONTEXT.HookedPageListHead'.
    //
    LIST_ENTRY ListEntry;

    //
    // The guest physical page address for this hooked page.
    //
    ULONG64 GuestPhysicalPage;

    //
    // The ept entry for the 'GuestPhysicalPage'.
    //
    EptCommonEntry* EptEntry;

    //
    // The number of read-access ept breakpoints in this hooked page.
    //
    ULONG ReadBreakpointCount;

    //
    // The number of write-access ept breakpoints in this hooked page.
    //
    ULONG WriteBreakpointCount;

    //
    // The number of execute-access ept breakpoints in this hooked page.
    //
    ULONG ExecuteBreakpointCount;

    //
    // A list of 'EPT_BREAKPOINT_ROOT_ENTRY' objects corresponding to ept
    //  breakpoints in the hooked page.
    //
    LIST_ENTRY BreakpointListHead;
    ULONG NumberOfBreakpoints;

} HOOKED_PAGE_ENTRY, *PHOOKED_PAGE_ENTRY;

/*++

Name:

    EPT_BREAKPOINT_ROOT_ENTRY

Description:

    Bookkeeping object for ept breakpoints in vmx root mode.

Remarks:

    An 'ept breakpoint root entry' is a bookkeeping container object for an
    ept breakpoint installed on a processor.

    Each root entry is tied to a single hooked page entry.

    'EPT_BREAKPOINT_ROOT_ENTRY' objects are allocated from the NonPagedPool.

--*/
typedef struct _EPT_BREAKPOINT_ROOT_ENTRY {

    //
    // List entry for the breakpoint list of an EBM processor context.
    //
    // See: 'EBM_PROCESSOR_CONTEXT.BreakpointListHead'.
    //
    LIST_ENTRY ListEntry;

    //
    // The ept breakpoint.
    //
    EPT_BREAKPOINT Breakpoint;

    //
    // List entry for the breakpoint list of the 'HookedPage'.
    //
    // See: HOOKED_PAGE_ENTRY.BreakpointListHead.
    //
    LIST_ENTRY HookedPageListEntry;

    //
    // The hooked page that contains this ept breakpoint.
    //
    PHOOKED_PAGE_ENTRY HookedPage;

} EPT_BREAKPOINT_ROOT_ENTRY, *PEPT_BREAKPOINT_ROOT_ENTRY;

/*++

Name:

    EPT_RESTORATION_ENTRY

Description:

    Bookkeeping object for restoring ept access bits after single-stepping an
    instruction in the guest using the monitor trap flag VM execution control.

Remarks:

    Each processor maintains a list of restoration entries to handle the
    scenario where successive ept violation VM exits delay a monitor trap flag
    event.

    'EPT_RESTORATION_ENTRY' objects are allocated from the NonPagedPool.

--*/
typedef struct _EPT_RESTORATION_ENTRY {
    LIST_ENTRY ListEntry;
    EptCommonEntry* EptEntry;
    EptCommonEntry PreviousEptEntry;
} EPT_RESTORATION_ENTRY, *PEPT_RESTORATION_ENTRY;

/*++

Name:

    EBM_PROCESSOR_STATISTICS

Description:

    Statistics for an EBM processor context.

Remarks:

    All fields are running total counts since the hypervisor was installed.

--*/
typedef struct _EBM_PROCESSOR_STATISTICS {
    ULONG64 HookedPageEntries;
    ULONG64 BreakpointHits;
    ULONG64 BreakpointMisses;
    ULONG64 EptViolationExits;
    ULONG64 MonitorTrapFlagExits;
} EBM_PROCESSOR_STATISTICS, *PEBM_PROCESSOR_STATISTICS;

/*++

Name:

    EBM_PROCESSOR_CONTEXT

Description:

    A context object that maintains all of the vmx root mode bookkeeping for a
    processor.

Remarks:

    'EBM_PROCESSOR_CONTEXT' objects are allocated from the NonPagedPool.

--*/
typedef struct _EBM_PROCESSOR_CONTEXT {

    //
    // The list of 'HOOKED_PAGE_ENTRY' objects.
    //
    LIST_ENTRY HookedPageListHead;
    ULONG NumberOfHookedPages;

    //
    // The list of 'EPT_BREAKPOINT_ROOT_ENTRY' objects.
    //
    LIST_ENTRY BreakpointListHead;
    ULONG NumberOfBreakpoints;

    //
    // The number of pending monitor trap flag events.
    //
    ULONG NumberOfPendingSingleSteps;

    //
    // The list of 'EPT_RESTORATION_ENTRY' objects.
    //
    // NOTE This list must be maintained as a LIFO stack.
    //
    LIST_ENTRY EptRestorationListHead;
    ULONG NumberOfEptRestorations;

    //
    // Processor statistics.
    //
    EBM_PROCESSOR_STATISTICS Statistics;

} EBM_PROCESSOR_CONTEXT, *PEBM_PROCESSOR_CONTEXT;

/*++

Name:

    EBM_VMX_ROOT_CONTEXT

Description:

    A vmx root context object that contains the EBM processor contexts.

--*/
typedef struct _EBM_VMX_ROOT_CONTEXT {
    ULONG NumberOfProcessors;
    PEBM_PROCESSOR_CONTEXT Processors;
} EBM_VMX_ROOT_CONTEXT, *PEBM_VMX_ROOT_CONTEXT;


//=============================================================================
// Callback Context Types
//=============================================================================
typedef struct _INSTALL_EPT_BREAKPOINT_CONTEXT {
    volatile POINTER_ALIGNMENT NTSTATUS NtStatus;
    PEPROCESS Process;
    PEPT_BREAKPOINT Breakpoint;
} INSTALL_EPT_BREAKPOINT_CONTEXT, *PINSTALL_EPT_BREAKPOINT_CONTEXT;

typedef struct _UNINSTALL_EPT_BREAKPOINT_CONTEXT {
    volatile POINTER_ALIGNMENT NTSTATUS NtStatus;
    HANDLE Handle;
} UNINSTALL_EPT_BREAKPOINT_CONTEXT, *PUNINSTALL_EPT_BREAKPOINT_CONTEXT;

typedef struct _UNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT {
    volatile POINTER_ALIGNMENT NTSTATUS NtStatus;
    HANDLE ProcessId;
} UNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT,
*PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT;


//=============================================================================
// Module Globals
//=============================================================================
static EBM_VMX_NON_ROOT_CONTEXT g_EbmVmxNonRootContext = {};
static EBM_VMX_ROOT_CONTEXT g_EbmVmxRootContext = {};


//=============================================================================
// Shared Prototypes
//=============================================================================
DECLSPEC_NORETURN
static
VOID
EbmpBugCheckEx(
    _In_ ULONG_PTR BugCheckParameter1,
    _In_ ULONG_PTR BugCheckParameter2,
    _In_ ULONG_PTR BugCheckParameter3,
    _In_ ULONG_PTR BugCheckParameter4
);

static
CHAR
EbmpEptBreakpointTypeToCharacter(
    _In_ EPT_BREAKPOINT_TYPE BreakpointType
);

static
CHAR
EbmpEptBreakpointSizeToCharacter(
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize
);


//=============================================================================
// Private Vmx Non-Root Prototypes
//=============================================================================
static
VOID
EbmpCreateProcessNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN fCreate
);

static
VOID
EbmpPrintProcessorStatistics();

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
VOID
EbmpResetClientContext(
    _Out_ PEBM_CLIENT_CONTEXT pClientContext
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
VOID
EbmpReleaseClientContext(
    _Inout_ PEBM_CLIENT_CONTEXT pClientContext
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
BOOLEAN
EbmpVerifyClientContext();

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpGetEptBreakpointInformationSize(
    _Out_ PULONG pcbRequired
);

_Check_return_
static
NTSTATUS
EbmpCalculateLogMaxIndex(
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType,
    _In_ SIZE_T cbLog,
    _Out_ PULONG pMaxIndex
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpCreateLogContext(
    _In_ HANDLE ProcessId,
    _In_ PVOID pVirtualAddress,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ EPT_BREAKPOINT_LOG_TYPE LogType,
    _In_ SIZE_T cbLog,
    _In_opt_ X64_REGISTER RegisterKey,
    _Outptr_result_nullonfailure_ PEBM_LOG_CONTEXT* ppLogContext
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
VOID
EbmpDestroyLogContext(
    _Inout_ PEBM_LOG_CONTEXT pLogContext
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpCreateLockedPageEntry(
    _In_ HANDLE ProcessId,
    _In_ PVOID pVirtualAddress,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ BOOLEAN fMakePageResident,
    _Outptr_result_nullonfailure_ PLOCKED_PAGE_ENTRY* ppLockedPageEntry,
    _Out_ PBOOLEAN pfLockedPageEntryCreated
);

_IRQL_requires_max_(APC_LEVEL)
_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
VOID
EbmpDestroyLockedPageEntry(
    _Inout_ PLOCKED_PAGE_ENTRY pLockedPageEntry
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpCreateEptBreakpoint(
    _In_ HANDLE ProcessId,
    _In_ PVOID pVirtualAddress,
    _In_ EPT_BREAKPOINT_TYPE BreakpointType,
    _In_ EPT_BREAKPOINT_SIZE BreakpointSize,
    _In_ PEBM_LOG_CONTEXT pLogContext,
    _Outptr_result_nullonfailure_ PEPT_BREAKPOINT* ppEptBreakpoint
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
VOID
EbmpDestroyEptBreakpoint(
    _Inout_ PEPT_BREAKPOINT pEptBreakpoint
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpCreateEptBreakpointNonRootEntry(
    _In_ PLOCKED_PAGE_ENTRY pLockedPageEntry,
    _In_ PEPT_BREAKPOINT pEptBreakpoint,
    _Outptr_result_nullonfailure_
        PEPT_BREAKPOINT_NON_ROOT_ENTRY* ppNonRootEntry
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
BOOLEAN
EbmpDestroyEptBreakpointNonRootEntry(
    _Inout_ PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
BOOLEAN
EbmpVerifyEptBreakpointAddressSpanInLockedPage(
    _In_ PLOCKED_PAGE_ENTRY pLockedPageEntry,
    _In_ PEPT_BREAKPOINT pEptBreakpoint
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
VOID
EbmpMakeEptBreakpointInactive(
    _Inout_ PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry,
    _In_ BOOLEAN fDestroyLockedPage
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
NTSTATUS
EbmpUninstallEptBreakpointsByProcessId(
    _In_ HANDLE ProcessId
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
PLOCKED_PAGE_ENTRY
EbmpLookupLockedPageEntry(
    _In_ HANDLE ProcessId,
    _In_ ULONG64 PhysicalPage
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
_Check_return_
static
PEPT_BREAKPOINT_NON_ROOT_ENTRY
EbmpLookupEptBreakpointNonRootEntry(
    _In_ HANDLE Handle,
    _Out_ PBOOLEAN pfInactive
);

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
SYSTEM_PROCESSOR_CALLBACK_ROUTINE
EbmpInstallEptBreakpointCallback;

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
SYSTEM_PROCESSOR_CALLBACK_ROUTINE
EbmpUninstallEptBreakpointCallback;

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
SYSTEM_PROCESSOR_CALLBACK_ROUTINE
EbmpUninstallEptBreakpointsByProcessIdCallback;

_Requires_exclusive_lock_held_(g_EptBreakpointManager.Gate)
static
SYSTEM_PROCESSOR_CALLBACK_ROUTINE
EbmpUninstallAllEptBreakpointsCallback;


//=============================================================================
// Private Vmx Root Prototypes
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
FORCEINLINE
static
PEBM_PROCESSOR_CONTEXT
EbmxpGetCurrentProcessorContext();

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
EbmxpValidateEptBreakpoint(
    _In_ EptData* pEptData,
    _In_ PEPT_BREAKPOINT pEptBreakpoint,
    _Outptr_result_nullonfailure_ EptCommonEntry** ppEptEntry
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
EbmxpCreateHookedPageEntry(
    _In_ PEBM_PROCESSOR_CONTEXT pProcessorContext,
    _In_ EptCommonEntry* pEptEntry,
    _In_ ULONG64 GuestPhysicalPage,
    _Outptr_result_nullonfailure_ PHOOKED_PAGE_ENTRY* ppHookedPageEntry
);

_IRQL_requires_(HIGH_LEVEL)
static
VOID
EbmxpDestroyHookedPageEntry(
    _Inout_ PHOOKED_PAGE_ENTRY pHookedPageEntry
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
NTSTATUS
EbmxpCreateEptBreakpointRootEntry(
    _In_ PEBM_PROCESSOR_CONTEXT pProcessorContext,
    _In_ PEPT_BREAKPOINT pEptBreakpoint,
    _In_ PHOOKED_PAGE_ENTRY pHookedPageEntry,
    _Outptr_result_nullonfailure_ PEPT_BREAKPOINT_ROOT_ENTRY* ppRootEntry
);

_IRQL_requires_(HIGH_LEVEL)
static
BOOLEAN
EbmxpDestroyEptBreakpointRootEntry(
    _Inout_ PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry,
    _In_ BOOLEAN fInvalidateEptCache
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
BOOLEAN
EbmxpVerifyEptBreakpointAddressSpanInHookedPage(
    _In_ PHOOKED_PAGE_ENTRY pHookedPageEntry,
    _In_ PEPT_BREAKPOINT pEptBreakpoint
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
VOID
EbmxpInsertEptRestorationEntry(
    _In_ PEBM_PROCESSOR_CONTEXT pProcessorContext,
    _In_ EptCommonEntry* pEptEntry
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
PHOOKED_PAGE_ENTRY
EbmxpLookupHookedPageEntry(
    _In_ PLIST_ENTRY pHookedPageListHead,
    _In_ ULONG64 GuestPhysicalPage
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
PEPT_BREAKPOINT_ROOT_ENTRY
EbmxpLookupEptBreakpointRootEntryByHandle(
    _In_ PLIST_ENTRY pBreakpointListHead,
    _In_ HANDLE Handle
);

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
static
PEPT_BREAKPOINT_ROOT_ENTRY
EbmxpFindEptBreakpointRootEntryForEptViolation(
    _In_ PHOOKED_PAGE_ENTRY pHookedPageEntry,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ EptViolationQualification ExitQualification
);

_IRQL_requires_(HIGH_LEVEL)
_Requires_lock_not_held_(pLogContext->UpdateLock)
static
VOID
EbmxpLogEptBreakpointHit(
    _Inout_ PEBM_LOG_CONTEXT pLogContext,
    _In_ GpRegisters* pGuestRegisters,
    _In_ FlagRegister GuestFlags,
    _In_ ULONG_PTR GuestIp
);

static
LOG_EPT_BREAKPOINT_HIT_ROUTINE
EbmxpLogEptBreakpointHitBasic;

static
LOG_EPT_BREAKPOINT_HIT_ROUTINE
EbmxpLogEptBreakpointHitGeneralRegisterContext;

static
LOG_EPT_BREAKPOINT_HIT_ROUTINE
EbmxpLogEptBreakpointHitKeyedRegisterContext;

_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
EbmxpSetMonitorTrapFlag(
    _In_ BOOLEAN fEnable
);


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
NTSTATUS
EbmDriverEntry()
{
    BOOLEAN fResourceInitialized = FALSE;
    ULONG nProcessors = 0;
    PEBM_PROCESSOR_CONTEXT pProcessors = NULL;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    ULONG i = 0;
    BOOLEAN fCallbackRegistered = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT("Loading %s.", MODULE_TITLE);

    //
    // Initialize the vmx non-root context.
    //
    ntstatus = ExInitializeResourceLite(&g_EbmVmxNonRootContext.Gate);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("ExInitializeResourceLite failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fResourceInitialized = TRUE;

    g_EbmVmxNonRootContext.ClientRegistered = FALSE;

    EbmpResetClientContext(&g_EbmVmxNonRootContext.Client);

    //
    // Initialize the vmx root context.
    //
    nProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    pProcessors = (PEBM_PROCESSOR_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        nProcessors * sizeof(*pProcessors),
        MODULE_TAG);
    if (!pProcessors)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    for (i = 0; i < nProcessors; i++)
    {
        pProcessorContext = &pProcessors[i];

        InitializeListHead(&pProcessorContext->HookedPageListHead);
        pProcessorContext->NumberOfHookedPages = 0;
        InitializeListHead(&pProcessorContext->BreakpointListHead);
        pProcessorContext->NumberOfBreakpoints = 0;
        pProcessorContext->NumberOfPendingSingleSteps = 0;
        InitializeListHead(&pProcessorContext->EptRestorationListHead);
        pProcessorContext->NumberOfEptRestorations = 0;
        pProcessorContext->Statistics = {};
    }

    g_EbmVmxRootContext.NumberOfProcessors = nProcessors;
    g_EbmVmxRootContext.Processors = pProcessors;

    //
    // Register a process notify callback after the global contexts have been
    //  initialized because our callback will access them.
    //
    ntstatus =
        PsSetCreateProcessNotifyRoutine(EbmpCreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("PsSetCreateProcessNotifyRoutine failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fCallbackRegistered = TRUE;

    INF_PRINT("%s loaded.", MODULE_TITLE);

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (fCallbackRegistered)
        {
            VERIFY_NTSTATUS(
                PsSetCreateProcessNotifyRoutine(
                    EbmpCreateProcessNotifyRoutine,
                    TRUE));
        }

        if (pProcessors)
        {
            ExFreePoolWithTag(pProcessors, MODULE_TAG);
        }

        if (fResourceInitialized)
        {
            VERIFY_NTSTATUS(
                ExDeleteResourceLite(
                    &g_EbmVmxNonRootContext.Gate));
        }
    }

    return ntstatus;
}


VOID
EbmDriverUnload()
{
#if defined(DBG)
    ULONG i = 0;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
#endif

    INF_PRINT("Unloading %s.", MODULE_TITLE);

    VERIFY_NTSTATUS(
        PsSetCreateProcessNotifyRoutine(
            EbmpCreateProcessNotifyRoutine,
            TRUE));

    //
    // Release vmx root context resources.
    //
#if defined(DBG)
    for (i = 0; i < g_EbmVmxRootContext.NumberOfProcessors; i++)
    {
        pProcessorContext = &g_EbmVmxRootContext.Processors[i];

        NT_ASSERT(IsListEmpty(&pProcessorContext->HookedPageListHead));
        NT_ASSERT(!pProcessorContext->NumberOfHookedPages);
        NT_ASSERT(IsListEmpty(&pProcessorContext->BreakpointListHead));
        NT_ASSERT(!pProcessorContext->NumberOfBreakpoints);
        NT_ASSERT(!pProcessorContext->NumberOfPendingSingleSteps);
        NT_ASSERT(IsListEmpty(&pProcessorContext->EptRestorationListHead));
        NT_ASSERT(!pProcessorContext->NumberOfEptRestorations);
    }
#endif

    EbmpPrintProcessorStatistics();

    ExFreePoolWithTag(g_EbmVmxRootContext.Processors, MODULE_TAG);

    //
    // Release vmx non-root context resources.
    //
    NT_ASSERT(!g_EbmVmxNonRootContext.ClientRegistered);
    NT_ASSERT(IsListEmpty(&g_EbmVmxNonRootContext.Client.LockedPageListHead));
    NT_ASSERT(!g_EbmVmxNonRootContext.Client.NumberOfLockedPages);
    NT_ASSERT(
        IsListEmpty(
            &g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead));
    NT_ASSERT(!g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints);
    NT_ASSERT(
        IsListEmpty(
            &g_EbmVmxNonRootContext.Client.InactiveBreakpointListHead));
    NT_ASSERT(!g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints);

    VERIFY_NTSTATUS(ExDeleteResourceLite(&g_EbmVmxNonRootContext.Gate));

    INF_PRINT("%s unloaded.", MODULE_TITLE);
}


//=============================================================================
// Public Vmx Non-Root Interface
//=============================================================================
/*++

Description:

    Registers an EBM client.

Parameters:

    ProcessId - The process id of the user mode process to be registered.

Requirements:

    This routine must be invoked in the process context of the process
    specified by 'ProcessId'.

Remarks:

    This routine fails if an EBM client is already registered.

    The client context is automatically released and reset when the client
    process terminates. See: 'EbmpCreateProcessNotifyRoutine'.

    TODO This routine needs to be refactored to support kernel mode EBM
    clients.

--*/
_Use_decl_annotations_
NTSTATUS
EbmRegisterClient(
    HANDLE ProcessId
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    INF_PRINT("Registering EBM client. (ProcessId = %Iu)", ProcessId);

    //
    // TODO Reject the idle and system processes for now.
    //
    if (!ProcessId || ProcessId == (HANDLE)4)
    {
        ntstatus = STATUS_NOT_IMPLEMENTED;
        goto exit;
    }

    if (PsGetProcessId(PsGetCurrentProcess()) != ProcessId)
    {
        ntstatus = STATUS_THREAD_NOT_IN_PROCESS;
        goto exit;
    }

    if (PsGetCurrentProcessId() != ProcessId)
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    if (g_EbmVmxNonRootContext.ClientRegistered)
    {
        ntstatus = STATUS_IMPLEMENTATION_LIMIT;
        goto exit;
    }

    g_EbmVmxNonRootContext.Client.ProcessId = ProcessId;

    g_EbmVmxNonRootContext.ClientRegistered = TRUE;

    INF_PRINT("EBM client registered.");

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Unregisters an EBM client.

Parameters:

    ProcessId - The process id of the registered client.

Requirements:

    This routine must be invoked in the process context of the process
    specified by 'ProcessId'.

Remarks:

    TODO This routine needs to be refactored to support kernel mode EBM
    clients.

--*/
_Use_decl_annotations_
NTSTATUS
EbmUnregisterClient(
    HANDLE ProcessId
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    INF_PRINT("Unregistering EBM client. (PID = %Iu)", ProcessId);

    if (PsGetProcessId(PsGetCurrentProcess()) != ProcessId)
    {
        ntstatus = STATUS_THREAD_NOT_IN_PROCESS;
        goto exit;
    }

    if (PsGetCurrentProcessId() != ProcessId)
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    if (!g_EbmVmxNonRootContext.ClientRegistered)
    {
        ntstatus = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    EbmpReleaseClientContext(&g_EbmVmxNonRootContext.Client);

    EbmpResetClientContext(&g_EbmVmxNonRootContext.Client);

    g_EbmVmxNonRootContext.ClientRegistered = FALSE;

    INF_PRINT("EBM client unregistered.");

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Returns TRUE if an EBM client is registered.

--*/
_Use_decl_annotations_
BOOLEAN
EbmIsClientRegistered()
{
    BOOLEAN status = TRUE;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    status = g_EbmVmxNonRootContext.ClientRegistered;

    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return status;
}


/*++

Description:

    Calculates the size in bytes required to store ept breakpoint information
    for all active and inactive ept breakpoints.

Parameters:

    pcbRequired - Returns the required size in bytes.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

--*/
_Use_decl_annotations_
NTSTATUS
EbmQueryEptBreakpointInformationSize(
    PULONG pcbRequired
)
{
    ULONG cbRequired = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *pcbRequired = 0;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    if (!EbmpVerifyClientContext())
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    ntstatus = EbmpGetEptBreakpointInformationSize(&cbRequired);
    if (!NT_SUCCESS(ntstatus))
    {
        goto exit;
    }

    //
    // Set output parameters.
    //
    *pcbRequired = cbRequired;

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Initializes an ept breakpoint information object with information about all
    active and inactive ept breakpoints.

Parameters:

    pEptBreakpointInfo - Returns the ept breakpoint information.

    cbEptBreakpointInfo - The size in bytes of the buffer specified by
        'pEptBreakpointInfo'.

    pcbReturned - The size in bytes written to the buffer specified by
        'pEptBreakpointInfo'.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

--*/
_Use_decl_annotations_
NTSTATUS
EbmQueryEptBreakpointInformation(
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo,
    ULONG cbEptBreakpointInfo,
    PULONG pcbReturned
)
{
    ULONG cbRequired = 0;
    ULONG nBreakpoints = 0;
    ULONG i = 0;
    ULONG nHookedPages = 0;
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    PEPT_BREAKPOINT_INFORMATION_ELEMENT pElement = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    RtlSecureZeroMemory(pEptBreakpointInfo, cbEptBreakpointInfo);
    *pcbReturned = 0;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    if (!EbmpVerifyClientContext())
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    //
    // Check if the provided buffer is large enough.
    //
    ntstatus = EbmpGetEptBreakpointInformationSize(&cbRequired);
    if (!NT_SUCCESS(ntstatus))
    {
        goto exit;
    }

    if (cbRequired > cbEptBreakpointInfo)
    {
        ERR_PRINT(
            "Ept breakpoint information buffer is too small."
            " (RequiredSize = 0x%X, ProvidedSize = 0x%X)",
            cbRequired,
            cbEptBreakpointInfo);
        ntstatus = STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    nBreakpoints =
        g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints +
        g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints;

    //
    // Write output information.
    //
    pEptBreakpointInfo->NumberOfActiveBreakpoints =
        g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints;
    pEptBreakpointInfo->NumberOfInactiveBreakpoints =
        g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints;
    pEptBreakpointInfo->NumberOfLockedPages =
        g_EbmVmxNonRootContext.Client.NumberOfLockedPages;

    //
    // NOTE We can safely touch the processor contexts of the vmx root context
    //  because their backing buffer was allocated in vmx non-root mode inside
    //  'EbmDriverEntry'.
    //
    for (i = 0; i < g_EbmVmxRootContext.NumberOfProcessors; i++)
    {
        //
        // Verify that each processor has the same number of hooked pages.
        //
        if (!nHookedPages)
        {
            nHookedPages =
                g_EbmVmxRootContext.Processors[i].NumberOfHookedPages;
        }
        else
        {
            VERIFY_BOOLEAN(
                g_EbmVmxRootContext.Processors[i].NumberOfHookedPages ==
                nHookedPages);
        }
    }

    //
    // Copy the active breakpoint information to the output buffer.
    //
    for (pListEntry =
            g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead.Flink,
                i = 0;
        pListEntry != &g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead;
        pListEntry = pListEntry->Flink,
            i++)
    {
        NT_ASSERT(i < nBreakpoints);

        pNonRootEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.ListEntry);

        NT_ASSERT(pNonRootEntry->IsActive);

        pElement = &pEptBreakpointInfo->Elements[i];

        pElement->Handle = pNonRootEntry->Breakpoint->Handle;

        RtlCopyMemory(
            &pElement->Header,
            &pNonRootEntry->Breakpoint->LogContext->KernelMapping.Log->Header,
            sizeof(EPT_BREAKPOINT_LOG_HEADER));
    }

    //
    // Copy the inactive breakpoint information to the output buffer.
    //
    for (pListEntry =
            g_EbmVmxNonRootContext.Client.InactiveBreakpointListHead.Flink;
        pListEntry !=
            &g_EbmVmxNonRootContext.Client.InactiveBreakpointListHead;
        pListEntry = pListEntry->Flink,
            i++)
    {
        NT_ASSERT(i < nBreakpoints);

        pNonRootEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Inactive.ListEntry);

        NT_ASSERT(!pNonRootEntry->IsActive);

        pElement = &pEptBreakpointInfo->Elements[i];

        pElement->Handle = pNonRootEntry->Breakpoint->Handle;

        RtlCopyMemory(
            &pElement->Header,
            &pNonRootEntry->Breakpoint->LogContext->KernelMapping.Log->Header,
            sizeof(EPT_BREAKPOINT_LOG_HEADER));
    }

    //
    // Set the array size.
    //
    pEptBreakpointInfo->NumberOfElements = nBreakpoints;

    //
    // Set output parameters.
    //
    *pcbReturned = cbRequired;

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Install an ept breakpoint on all processors.

Parameters:

    ProcessId - The target process of the ept breakpoint.

    pVirtualAddress - The target virtual address of the ept breakpoint.

    BreakpointType - The breakpoint type of the ept breakpoint.

    BreakpointSize - The breakpoint size of the ept breakpoint.

    LogType - The log type of the ept breakpoint.

    cbLog - The size in bytes of the ept breakpoint log.

    fMakePageResident - If TRUE then the page containing the target virtual
        address is made resident (if it is currently paged out) then locked in
        memory. If FALSE then this routine fails if the target page is not
        resident in memory.

    RegisterKey - If 'LogType' is 'EptBreakpointLogTypeKeyedRegisterContext'
        then this parameter specifies which register is used to determine the
        uniqueness of a guest context when the corresponding ept breakpoint is
        triggered.

    phLog - Returns the unique identifier for the installed ept breakpoint.

    ppLog - Returns a pointer to the ept breakpoint log.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

Remarks:

    The following is a summary of the actions performed by this routine:

        1. Validate input parameters.

        2. Create a log context inside the caller's process context.

        3. Attach to the target process:

           [Target process context]

            a. Create a locked page entry for the target virtual address.

            b. Create an ept breakpoint object using the log context.

            c. Create an ept breakpoint non-root entry for the ept breakpoint
                object.

            d. Serially install the ept breakpoint on all processors by
                invoking the 'kInstallEptBreakpoint' hypercall:

                [Vmx root mode]

                i. Validate the ept breakpoint object.

                ii. Create a hooked page entry for the target guest physical
                    page.

                iii. Create an ept breakpoint root entry which contains a
                    processor-local copy of the ept breakpoint object.

        4. Update the breakpoint status in the breakpoint log to
            'EptBreakpointStatusActive'.

--*/
_Use_decl_annotations_
NTSTATUS
EbmSetEptBreakpoint(
    HANDLE ProcessId,
    PVOID pVirtualAddress,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    EPT_BREAKPOINT_LOG_TYPE LogType,
    SIZE_T cbLog,
    BOOLEAN fMakePageResident,
    X64_REGISTER RegisterKey,
    PHANDLE phLog,
    PEPT_BREAKPOINT_LOG* ppLog
)
{
    PEPROCESS pProcess = NULL;
    BOOLEAN fProcessReferenced = FALSE;
    BOOLEAN fExitSynchronizationAcquired = FALSE;
    PEBM_LOG_CONTEXT pLogContext = NULL;
    KAPC_STATE ApcState = {};
    BOOLEAN fAttached = FALSE;
    PLOCKED_PAGE_ENTRY pLockedPageEntry = NULL;
    BOOLEAN fLockedPageEntryCreated = FALSE;
    PEPT_BREAKPOINT pEptBreakpoint = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    PINSTALL_EPT_BREAKPOINT_CONTEXT pCallbackContext = NULL;
    PUNINSTALL_EPT_BREAKPOINT_CONTEXT pUnwindContext = NULL;
    BOOLEAN fLockedPageEntryDestroyed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *phLog = NULL;
    *ppLog = NULL;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    INF_PRINT_V(
        "Setting ept breakpoint. (PID = %Iu, GVA = %p, BP = %c%c, LT = %d, LS = 0x%IX)",
        ProcessId,
        pVirtualAddress,
        EbmpEptBreakpointTypeToCharacter(BreakpointType),
        EbmpEptBreakpointSizeToCharacter(BreakpointSize),
        LogType,
        cbLog);

    if (!EbmpVerifyClientContext())
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    //
    // 1. Validate input parameters.
    //
    if (!MI_RESERVED_BITS_CANONICAL(pVirtualAddress))
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

    if (!IS_ALIGNED(pVirtualAddress, BreakpointSize))
    {
        ntstatus = STATUS_DATATYPE_MISALIGNMENT_ERROR;
        goto exit;
    }

    if (1 != ADDRESS_AND_SIZE_TO_SPAN_PAGES(pVirtualAddress, BreakpointSize))
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

    if (EptBreakpointTypeRead != BreakpointType &&
        EptBreakpointTypeWrite != BreakpointType &&
        EptBreakpointTypeExecute != BreakpointType)
    {
        ntstatus = STATUS_INVALID_PARAMETER_3;
        goto exit;
    }

    if (EptBreakpointSizeByte != BreakpointSize &&
        EptBreakpointSizeWord != BreakpointSize &&
        EptBreakpointSizeDword != BreakpointSize &&
        EptBreakpointSizeQword != BreakpointSize)
    {
        ntstatus = STATUS_INVALID_PARAMETER_4;
        goto exit;
    }

    if (EptBreakpointTypeExecute == BreakpointType &&
        EptBreakpointSizeByte != BreakpointSize)
    {
        ntstatus = STATUS_INSTRUCTION_MISALIGNMENT;
        goto exit;
    }

    if (EptBreakpointLogTypeKeyedRegisterContext == LogType)
    {
        switch (RegisterKey)
        {
            case REGISTER_RIP:
            case REGISTER_R15:
            case REGISTER_R14:
            case REGISTER_R13:
            case REGISTER_R12:
            case REGISTER_R11:
            case REGISTER_R10:
            case REGISTER_R9:
            case REGISTER_R8:
            case REGISTER_RDI:
            case REGISTER_RSI:
            case REGISTER_RBP:
            case REGISTER_RSP:
            case REGISTER_RBX:
            case REGISTER_RDX:
            case REGISTER_RCX:
            case REGISTER_RAX:
                break;
            default:
                ntstatus = STATUS_INVALID_PARAMETER_8;
                goto exit;
        }
    }

    ntstatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("PsLookupProcessByProcessId failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fProcessReferenced = TRUE;

    ntstatus = PsAcquireProcessExitSynchronization(pProcess);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("PsAcquireProcessExitSynchronization failed: 0x%X",
            ntstatus);
        goto exit;
    }
    //
    fExitSynchronizationAcquired = TRUE;

    //
    // 2. Create a log context inside the caller's process context.
    //
    ntstatus = EbmpCreateLogContext(
        ProcessId,
        pVirtualAddress,
        BreakpointType,
        BreakpointSize,
        LogType,
        cbLog,
        RegisterKey,
        &pLogContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpCreateLogContext failed: 0x%X", ntstatus);
        goto exit;
    }

    INF_PRINT_V(
        "Created log context. (PID = %Iu, GVA = %p, BP = %c%c, LT = %d, LS = 0x%IX, K = %p, U = %p)",
        ProcessId,
        pVirtualAddress,
        EbmpEptBreakpointTypeToCharacter(BreakpointType),
        EbmpEptBreakpointSizeToCharacter(BreakpointSize),
        LogType,
        cbLog,
        pLogContext->KernelMapping.BaseAddress,
        pLogContext->UserMapping.BaseAddress);

    //
    // 3. Attach to the target process.
    //
    KeStackAttachProcess(pProcess, &ApcState);
    fAttached = TRUE;

    //
    // a. Create a locked page entry for the target virtual address.
    //
    ntstatus = EbmpCreateLockedPageEntry(
        ProcessId,
        pVirtualAddress,
        BreakpointSize,
        fMakePageResident,
        &pLockedPageEntry,
        &fLockedPageEntryCreated);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpCreateLockedPageEntry failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // b. Create an ept breakpoint object using the log context.
    //
    ntstatus = EbmpCreateEptBreakpoint(
        ProcessId,
        pVirtualAddress,
        BreakpointType,
        BreakpointSize,
        pLogContext,
        &pEptBreakpoint);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpCreateEptBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // Sanity check.
    //
    if (pLockedPageEntry->PhysicalPage !=
        (ULONG64)PAGE_ALIGN(pEptBreakpoint->GuestPhysicalAddress))
    {
        ERR_PRINT(
            "Unexpected PA mismatch."
            " (LockedPageEntry.PA = %p, EptBreakpoint.PA",
            pLockedPageEntry->PhysicalPage,
            (ULONG64)PAGE_ALIGN(pEptBreakpoint->GuestPhysicalAddress));
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    //
    // Fail if there is a conflicting breakpoint in the locked page.
    //
    if (!EbmpVerifyEptBreakpointAddressSpanInLockedPage(
            pLockedPageEntry,
            pEptBreakpoint))
    {
        ERR_PRINT("Ept breakpoint collides with existing ept breakpoint.");
        ntstatus = STATUS_CONFLICTING_ADDRESSES;
        goto exit;
    }

    //
    // c. Create an ept breakpoint non-root entry for the ept breakpoint
    //  object.
    //
    ntstatus = EbmpCreateEptBreakpointNonRootEntry(
        pLockedPageEntry,
        pEptBreakpoint,
        &pNonRootEntry);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpCreateEptBreakpointNonRootEntry failed: 0x%X",
            ntstatus);
        goto exit;
    }

    //
    // Initialize the callback context.
    //
    pCallbackContext = (PINSTALL_EPT_BREAKPOINT_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pCallbackContext),
        MODULE_TAG);
    if (!pCallbackContext)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pCallbackContext->NtStatus = STATUS_SUCCESS;
    pCallbackContext->Process = pProcess;
    pCallbackContext->Breakpoint = pNonRootEntry->Breakpoint;

    //
    // Initialize the unwind context.
    //
    pUnwindContext = (PUNINSTALL_EPT_BREAKPOINT_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pUnwindContext),
        MODULE_TAG);
    if (!pUnwindContext)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pUnwindContext->NtStatus = STATUS_SUCCESS;
    pUnwindContext->Handle = pNonRootEntry->Breakpoint->Handle;

    //
    // d. Serially install the ept breakpoint on all processors by invoking the
    //  'kInstallEptBreakpoint' hypercall.
    //
    ntstatus = SysExecuteProcessorCallback(
        EbmpInstallEptBreakpointCallback,
        pCallbackContext,
        EbmpUninstallEptBreakpointCallback,
        pUnwindContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpInstallEptBreakpointCallback failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // 4. Update the breakpoint status in the breakpoint log to
    //  'EptBreakpointStatusActive'.
    //
    pLogContext->KernelMapping.Log->Header.BreakpointStatus =
        EptBreakpointStatusActive;

    //
    // Set output parameters.
    //
    *phLog = pNonRootEntry->Breakpoint->Handle;
    *ppLog = pLogContext->UserMapping.Log;

exit:
    if (pCallbackContext)
    {
        ExFreePoolWithTag(pCallbackContext, MODULE_TAG);
    }

    if (!NT_SUCCESS(ntstatus))
    {
        if (pNonRootEntry)
        {
            fLockedPageEntryDestroyed =
                EbmpDestroyEptBreakpointNonRootEntry(pNonRootEntry);
        }

        if (pEptBreakpoint)
        {
            EbmpDestroyEptBreakpoint(pEptBreakpoint);
        }

        if (fLockedPageEntryCreated && !fLockedPageEntryDestroyed)
        {
            EbmpDestroyLockedPageEntry(pLockedPageEntry);
        }
    }

    if (fAttached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    if (!NT_SUCCESS(ntstatus))
    {
        if (pLogContext)
        {
            EbmpDestroyLogContext(pLogContext);
        }
    }

    if (fExitSynchronizationAcquired)
    {
        PsReleaseProcessExitSynchronization(pProcess);
    }

    if (fProcessReferenced)
    {
        ObDereferenceObject(pProcess);
    }

    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Disable an active ept breakpoint.

Parameters:

    Handle - The handle to the ept breakpoint to be disabled.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

Remarks:

    When an ept breakpoint is disabled:
    
        1. Its corresponding vmx root bookkeeping is destroyed.
        
        2. Its vmx non-root entry is moved from the active breakpoint list to
            the inactive breakpoint list.

        3. Its breakpoint log status is set to 'EptBreakpointStatusInactive'.

    The breakpoint log of a disabled / inactive ept breakpoint will never be
    updated because the breakpoint condition can no longer occur. The EBM
    client can still freely view the logs of disabled / inactive ept
    breakpoints.

--*/
_Use_decl_annotations_
NTSTATUS
EbmDisableEptBreakpoint(
    HANDLE Handle
)
{
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    BOOLEAN fInactive = FALSE;
    PUNINSTALL_EPT_BREAKPOINT_CONTEXT pCallbackContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    INF_PRINT_V("Disabling ept breakpoint. (H = %Iu)", Handle);

    if (!EbmpVerifyClientContext())
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    pNonRootEntry = EbmpLookupEptBreakpointNonRootEntry(Handle, &fInactive);
    if (!pNonRootEntry)
    {
        ERR_PRINT("EbmpLookupEptBreakpointNonRootEntry failed. (Handle = %Iu)",
            Handle);
        ntstatus = STATUS_TRANSACTION_INVALID_ID;
        goto exit;
    }
    //
    if (fInactive)
    {
        ERR_PRINT("Ept breakpoint is already disabled.");
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    //
    // Uninstall the breakpoint on all processors.
    //
    pCallbackContext =
        (PUNINSTALL_EPT_BREAKPOINT_CONTEXT)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(*pCallbackContext),
            MODULE_TAG);
    if (!pCallbackContext)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pCallbackContext->NtStatus = STATUS_SUCCESS;
    pCallbackContext->Handle = Handle;

    ntstatus = SysExecuteProcessorCallback(
        EbmpUninstallEptBreakpointCallback,
        pCallbackContext,
        NULL,
        NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpUninstallEptBreakpointCallback failed: 0x%X", ntstatus);
        DEBUG_BREAK();
        goto exit;
    }

    EbmpMakeEptBreakpointInactive(pNonRootEntry, TRUE);

exit:
    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


/*++

Description:

    Clear an ept breakpoint on all processors.

Parameters:

    Handle - The handle to the ept breakpoint to be cleared.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

Remarks:

    When an ept breakpoint is cleared all of its corresponding vmx non-root and
    vmx root bookkeping is destroyed (including the breakpoint log).

--*/
_Use_decl_annotations_
NTSTATUS
EbmClearEptBreakpoint(
    HANDLE Handle
)
{
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    BOOLEAN fInactive = FALSE;
    PEPT_BREAKPOINT pEptBreakpoint = NULL;
    PEBM_LOG_CONTEXT pLogContext = NULL;
    PUNINSTALL_EPT_BREAKPOINT_CONTEXT pCallbackContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);

    INF_PRINT_V("Clearing ept breakpoint. (H = %Iu)", Handle);

    if (!EbmpVerifyClientContext())
    {
        ntstatus = STATUS_ACCESS_DENIED;
        goto exit;
    }

    pNonRootEntry = EbmpLookupEptBreakpointNonRootEntry(Handle, &fInactive);
    if (!pNonRootEntry)
    {
        ERR_PRINT("EbmpLookupEptBreakpointNonRootEntry failed. (Handle = %Iu)",
            Handle);
        ntstatus = STATUS_TRANSACTION_INVALID_ID;
        goto exit;
    }

    if (!fInactive)
    {
        //
        // Uninstall the breakpoint on all processors.
        //
        pCallbackContext =
            (PUNINSTALL_EPT_BREAKPOINT_CONTEXT)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(*pCallbackContext),
                MODULE_TAG);
        if (!pCallbackContext)
        {
            ntstatus = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }
        //
        pCallbackContext->NtStatus = STATUS_SUCCESS;
        pCallbackContext->Handle = Handle;

        ntstatus = SysExecuteProcessorCallback(
            EbmpUninstallEptBreakpointCallback,
            pCallbackContext,
            NULL,
            NULL);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT("EbmpUninstallEptBreakpointCallback failed: 0x%X",
                ntstatus);
            DEBUG_BREAK();
            goto exit;
        }
    }

    //
    // Destroy all vmx non-root bookkeeping for the breakpoint.
    //
    pEptBreakpoint = pNonRootEntry->Breakpoint;
    pLogContext = pEptBreakpoint->LogContext;

    EbmpDestroyEptBreakpointNonRootEntry(pNonRootEntry);
    EbmpDestroyEptBreakpoint(pEptBreakpoint);
    EbmpDestroyLogContext(pLogContext);

exit:
    if (pCallbackContext)
    {
        ExFreePoolWithTag(pCallbackContext, MODULE_TAG);
    }

    ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);

    return ntstatus;
}


//=============================================================================
// Public Vmx Root Interface
//=============================================================================

//
// TODO All vmcall handlers should verify their calling context and fail if
//  they were not invoked by the EBM client.
//
// TODO WARNING The vmcall handlers do not probe their hypercall context
//  parameter.
//

/*++

Description:

    Install an ept breakpoint on the current processor in vmx root mode.

Parameters:

    pEptData - Pointer to the ept data for this processor.

    pContext - Pointer to the hypercall context object.

--*/
_Use_decl_annotations_
VOID
EbmxInstallEptBreakpoint(
    EptData* pEptData,
    PVOID pContext
)
{
    PINSTALL_EPT_BREAKPOINT_CONTEXT pVmxContext = NULL;
    EPT_BREAKPOINT EptBreakpoint = {};
    EptCommonEntry* pEptEntry = NULL;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    ULONG64 GuestPhysicalPage = 0;
    PHOOKED_PAGE_ENTRY pHookedPageEntry = NULL;
    BOOLEAN fHookedPageEntryCreated = FALSE;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    BOOLEAN fHookedPageEntryDestroyed = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pVmxContext = (PINSTALL_EPT_BREAKPOINT_CONTEXT)pContext;

    RtlCopyMemory(
        &EptBreakpoint,
        pVmxContext->Breakpoint,
        sizeof(EPT_BREAKPOINT));

    INF_PRINT_V(
        "Installing ept breakpoint. (H = %Iu, PID = %Iu, GVA = %p, GPA = %p, BP = %c%c)",
        EptBreakpoint.Handle,
        EptBreakpoint.ProcessId,
        EptBreakpoint.GuestVirtualAddress,
        EptBreakpoint.GuestPhysicalAddress,
        EbmpEptBreakpointTypeToCharacter(EptBreakpoint.BreakpointType),
        EbmpEptBreakpointSizeToCharacter(EptBreakpoint.BreakpointSize));

    //
    // Validate the breakpoint.
    //
    ntstatus =
        EbmxpValidateEptBreakpoint(pEptData, &EptBreakpoint, &pEptEntry);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmxpValidateEptBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    GuestPhysicalPage =
        (ULONG64)PAGE_ALIGN(EptBreakpoint.GuestPhysicalAddress);

    //
    // Check if there is a hooked page entry for the target guest physical
    //  page.
    //
    pHookedPageEntry = EbmxpLookupHookedPageEntry(
        &pProcessorContext->HookedPageListHead,
        GuestPhysicalPage);
    if (!pHookedPageEntry)
    {
        //
        // We did not find a hooked page entry so create one.
        //
        ntstatus = EbmxpCreateHookedPageEntry(
            pProcessorContext,
            pEptEntry,
            GuestPhysicalPage,
            &pHookedPageEntry);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT("EbmxpCreateHookedPageEntry failed: 0x%X", ntstatus);
            goto exit;
        }
        //
        fHookedPageEntryCreated = TRUE;

        INF_PRINT_V("Created hooked page entry. (EPT = %p, GPP = %p)",
            pHookedPageEntry->EptEntry,
            pHookedPageEntry->GuestPhysicalPage);
    }
    else
    {
        //
        // Fail if there is a conflicting breakpoint in the hooked page.
        //
        if (!EbmxpVerifyEptBreakpointAddressSpanInHookedPage(
                pHookedPageEntry,
                &EptBreakpoint))
        {
            ERR_PRINT("Ept breakpoint collides with existing ept breakpoint.");
            ntstatus = STATUS_CONFLICTING_ADDRESSES;
            goto exit;
        }

        INF_PRINT_V(
            "Using existing hooked page entry. (EPT = %p, GPP = %p, RC = %u, WC = %u, EC = %u)",
            pHookedPageEntry->EptEntry,
            pHookedPageEntry->GuestPhysicalPage,
            pHookedPageEntry->ReadBreakpointCount,
            pHookedPageEntry->WriteBreakpointCount,
            pHookedPageEntry->ExecuteBreakpointCount);
    }

    NT_ASSERT(pEptEntry == pHookedPageEntry->EptEntry);

    ntstatus = EbmxpCreateEptBreakpointRootEntry(
        pProcessorContext,
        &EptBreakpoint,
        pHookedPageEntry,
        &pRootEntry);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmxpCreateEptBreakpointRootEntry failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pRootEntry)
        {
            fHookedPageEntryDestroyed =
                EbmxpDestroyEptBreakpointRootEntry(pRootEntry, TRUE);
        }

        if (fHookedPageEntryCreated && !fHookedPageEntryDestroyed)
        {
            EbmxpDestroyHookedPageEntry(pHookedPageEntry);
        }

        //
        // Update the callback status if this is the first error.
        //
        InterlockedCompareExchange(
            &pVmxContext->NtStatus,
            ntstatus,
            STATUS_SUCCESS);
    }
}


/*++

Description:

    Uninstall an ept breakpoint on the current processor in vmx root mode.

Parameters:

    pEptData - Pointer to the ept data for this processor.

    pContext - Pointer to the hypercall context object.

--*/
_Use_decl_annotations_
VOID
EbmxUninstallEptBreakpoint(
    EptData* pEptData,
    PVOID pContext
)
{
    PUNINSTALL_EPT_BREAKPOINT_CONTEXT pVmxContext = NULL;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pEptData);

    pVmxContext = (PUNINSTALL_EPT_BREAKPOINT_CONTEXT)pContext;

    INF_PRINT_V("Uninstalling ept breakpoint. (H = %Iu)",
        pVmxContext->Handle);

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    pRootEntry = EbmxpLookupEptBreakpointRootEntryByHandle(
        &pProcessorContext->BreakpointListHead,
        pVmxContext->Handle);
    if (!pRootEntry)
    {
        ERR_PRINT(
            "EbmxpLookupEptBreakpointRootEntryByHandle failed. (Handle = %Iu)",
            pVmxContext->Handle);
        ntstatus = STATUS_INTERNAL_DB_ERROR;
        DEBUG_BREAK();
        goto exit;
    }

    EbmxpDestroyEptBreakpointRootEntry(pRootEntry, TRUE);

exit:
    //
    // Update the callback status if this is the first error.
    //
    if (!NT_SUCCESS(ntstatus))
    {
        InterlockedCompareExchange(
            &pVmxContext->NtStatus,
            ntstatus,
            STATUS_SUCCESS);
    }
}


/*++

Description:

    Uninstall all ept breakpoints by target process id on the current processor
    in vmx root mode.

Parameters:

    pEptData - Pointer to the ept data for this processor.

    pContext - Pointer to the hypercall context object.

--*/
_Use_decl_annotations_
VOID
EbmxUninstallEptBreakpointsByProcessId(
    EptData* pEptData,
    PVOID pContext
)
{
    PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT pVmxContext = NULL;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    PLIST_ENTRY pNextEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    BOOLEAN fEptBreakpointsUninstalled = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pEptData);

    pVmxContext = (PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT)pContext;

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    //
    // Search the breakpoint list for breakpoints whose 'ProcessId' matches the
    //  specified process id.
    //
    pNextEntry = pProcessorContext->BreakpointListHead.Flink;

    while (pNextEntry != &pProcessorContext->BreakpointListHead)
    {
        pRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_ROOT_ENTRY,
            ListEntry);

        pNextEntry = pRootEntry->ListEntry.Flink;

        if (pRootEntry->Breakpoint.ProcessId != pVmxContext->ProcessId)
        {
            continue;
        }

        EbmxpDestroyEptBreakpointRootEntry(pRootEntry, FALSE);

        fEptBreakpointsUninstalled = TRUE;
    }

    if (fEptBreakpointsUninstalled)
    {
        VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
    }

    //
    // Update the callback status if this is the first error.
    //
    if (!NT_SUCCESS(ntstatus))
    {
        InterlockedCompareExchange(
            &pVmxContext->NtStatus,
            ntstatus,
            STATUS_SUCCESS);
    }
}


/*++

Description:

    Uninstall all ept breakpoints on the current processor in vmx root mode.

Parameters:

    pEptData - Pointer to the ept data for this processor.

--*/
_Use_decl_annotations_
VOID
EbmxUninstallAllEptBreakpoints(
    EptData* pEptData,
    PVOID pContext
)
{
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    PLIST_ENTRY pNextEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    BOOLEAN fEptBreakpointsUninstalled = FALSE;

    UNREFERENCED_PARAMETER(pEptData);
    UNREFERENCED_PARAMETER(pContext);

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    pNextEntry = pProcessorContext->BreakpointListHead.Flink;

    while (pNextEntry != &pProcessorContext->BreakpointListHead)
    {
        pRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_ROOT_ENTRY,
            ListEntry);

        pNextEntry = pRootEntry->ListEntry.Flink;

        EbmxpDestroyEptBreakpointRootEntry(pRootEntry, FALSE);

        fEptBreakpointsUninstalled = TRUE;
    }

    if (fEptBreakpointsUninstalled)
    {
        VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
    }

    VERIFY_BOOLEAN(IsListEmpty(&pProcessorContext->HookedPageListHead));
    VERIFY_BOOLEAN(!pProcessorContext->NumberOfHookedPages);
    VERIFY_BOOLEAN(IsListEmpty(&pProcessorContext->BreakpointListHead));
    VERIFY_BOOLEAN(!pProcessorContext->NumberOfBreakpoints);
    VERIFY_BOOLEAN(IsListEmpty(&pProcessorContext->EptRestorationListHead));
    VERIFY_BOOLEAN(!pProcessorContext->NumberOfEptRestorations);
}


/*++

Description:

    Ept violation VM exit handler.

Parameters:

    pGuestContext - Pointer to the guest context.

Return Value:

    Returns TRUE if the EBM handled this ept violation event.

    Returns FALSE if the EBM did not handle this ept violation event.

Remarks:

    If an ept violation is caused by an EBM-managed ept breakpoint then this
    routine handles the event by performing the following actions:

        1. Modify the access bits of the ept entry for the effective page so
            that the guest can successfully (re)execute the instruction on VM
            entry.

        2. If the ept violation maps to an ept breakpoint condition then the
            corresponding ept breakpoint log is updated to track the hit.

        3. Enable the monitor trap flag VM execution control so that the EBM
            can revert the access bit modification from step (1).

    Generally, if the EBM handles an ept violation then the guest will
    re-execute the original instruction on VM entry. The guest will then VM
    exit for a monitor trap flag event. Finally, the EBM will handle this event
    by restoring the access bits of the ept entry so that the ept breakpoint
    catches future accesses.

    However, if the EBM enables the monitor trap flag VM execution control and
    a system-management interrupt (SMI), INIT signal, or an exception /
    interrupt with a higher priority occurs on VM entry then the guest will
    single step into the handler for the event which took priority.

    See: Intel SDM,
        25.5.2 Monitor Trap Flag
        6.9 PRIORITY AMONG SIMULTANEOUS EXCEPTIONS AND INTERRUPTS

--*/
_Use_decl_annotations_
BOOLEAN
EbmxHandleEptViolation(
    GuestContext* pGuestContext
)
{
    EptViolationQualification ExitQualification = {};
    ULONG64 GuestPhysicalAddress = 0;
    ULONG64 GuestPhysicalPage = 0;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    PHOOKED_PAGE_ENTRY pHookedPageEntry = NULL;
    EptCommonEntry* pEptEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    BOOLEAN handled = TRUE;

    ExitQualification.all =
        (unsigned int)UtilVmRead(VmcsField::kExitQualification);

    GuestPhysicalAddress = UtilVmRead64(VmcsField::kGuestPhysicalAddress);

    GuestPhysicalPage = (ULONG64)PAGE_ALIGN(GuestPhysicalAddress);

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    pProcessorContext->NumberOfPendingSingleSteps++;
    pProcessorContext->Statistics.EptViolationExits++;

    //
    // Determine if an ept breakpoint caused this ept violation.
    //
    pHookedPageEntry = EbmxpLookupHookedPageEntry(
        &pProcessorContext->HookedPageListHead,
        GuestPhysicalPage);
    if (!pHookedPageEntry)
    {
        INF_PRINT_V("Passing EPT violation. (GPA = %p)", GuestPhysicalAddress);
        handled = FALSE;
        goto exit;
    }

    //
    // This ept violation was caused by an ept breakpoint so we must handle it.
    //

    pEptEntry = pHookedPageEntry->EptEntry;

    //
    // Insert a restoration entry before we modify the ept access bits. This
    //  restoration entry will be consumed in the EBM monitor trap flag VM exit
    //  handler.
    //
    EbmxpInsertEptRestorationEntry(pProcessorContext, pEptEntry);

    //
    // Update the ept access bits so that the guest can successfully execute
    //  the instruction on VM entry.
    //
    if (ExitQualification.fields.read_access &&
        !ExitQualification.fields.ept_readable)
    {
        pEptEntry->fields.read_access = TRUE;
    }

    if (ExitQualification.fields.write_access &&
        !ExitQualification.fields.ept_writeable)
    {
        pEptEntry->fields.read_access = TRUE;
        pEptEntry->fields.write_access = TRUE;
    }

    if (ExitQualification.fields.execute_access &&
        !ExitQualification.fields.ept_executable)
    {
        pEptEntry->fields.execute_access = TRUE;
    }

    //
    // Determine if this ept violation was caused by an access that maps to an
    //  ept breakpoint condition.
    //
    pRootEntry = EbmxpFindEptBreakpointRootEntryForEptViolation(
        pHookedPageEntry,
        GuestPhysicalAddress,
        ExitQualification);
    if (!pRootEntry)
    {
        pProcessorContext->Statistics.BreakpointMisses++;
        goto exit;
    }

    pProcessorContext->Statistics.BreakpointHits++;

    //
    // Log this ept breakpoint hit in the corresponding breakpoint log.
    //
    EbmxpLogEptBreakpointHit(
        pRootEntry->Breakpoint.LogContext,
        pGuestContext->gp_regs,
        pGuestContext->flag_reg,
        pGuestContext->ip);

exit:
    if (handled)
    {
        VERIFY_NTSTATUS(EbmxpSetMonitorTrapFlag(TRUE));

        VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
    }

    return handled;
}


/*++

Description:

    Monitor trap flag VM exit handler.

Parameters:

    pGuestContext - Pointer to the guest context.

--*/
_Use_decl_annotations_
VOID
EbmxHandleMonitorTrapFlag(
    GuestContext* pGuestContext
)
{
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;
    PLIST_ENTRY pListEntry = NULL;
    PEPT_RESTORATION_ENTRY pRestorationEntry = NULL;

    UNREFERENCED_PARAMETER(pGuestContext);

    pProcessorContext = EbmxpGetCurrentProcessorContext();

    //
    // Process all ept restoration entries.
    //
    while (!IsListEmpty(&pProcessorContext->EptRestorationListHead))
    {
        pListEntry =
            RemoveHeadList(&pProcessorContext->EptRestorationListHead);

        pRestorationEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_RESTORATION_ENTRY,
            ListEntry);

        //
        // Restore the ept access bits.
        //
        *pRestorationEntry->EptEntry = pRestorationEntry->PreviousEptEntry;

#pragma warning(suppress : 28121) // Current IRQL level is too high.
        ExFreePoolWithTag(pRestorationEntry, MODULE_TAG);

        pProcessorContext->NumberOfPendingSingleSteps--;
        pProcessorContext->NumberOfEptRestorations--;
    }

    pProcessorContext->Statistics.MonitorTrapFlagExits++;

    VERIFY_NTSTATUS(EbmxpSetMonitorTrapFlag(FALSE));

    VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
}


//=============================================================================
// Shared Interface
//=============================================================================
_Use_decl_annotations_
static
VOID
EbmpBugCheckEx(
    ULONG_PTR BugCheckParameter1,
    ULONG_PTR BugCheckParameter2,
    ULONG_PTR BugCheckParameter3,
    ULONG_PTR BugCheckParameter4
)
{
    DEBUG_BREAK();

    KeBugCheckEx(
        MANUALLY_INITIATED_CRASH,
        BugCheckParameter1,
        BugCheckParameter2,
        BugCheckParameter3,
        BugCheckParameter4);
}


_Use_decl_annotations_
static
CHAR
EbmpEptBreakpointTypeToCharacter(
    EPT_BREAKPOINT_TYPE BreakpointType
)
{
    CHAR Character = NULL;

    switch (BreakpointType)
    {
        case EptBreakpointTypeRead:
            Character = 'R';
            break;

        case EptBreakpointTypeWrite:
            Character = 'W';
            break;

        case EptBreakpointTypeExecute:
            Character = 'X';
            break;

        default:
            ERR_PRINT("Unhandled BreakpointType: %d", BreakpointType);
            Character = '?';
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return Character;
}


_Use_decl_annotations_
static
CHAR
EbmpEptBreakpointSizeToCharacter(
    EPT_BREAKPOINT_SIZE BreakpointSize
)
{
    CHAR Character = NULL;

    switch (BreakpointSize)
    {
        case EptBreakpointSizeByte:
            Character = '1';
            break;

        case EptBreakpointSizeWord:
            Character = '2';
            break;

        case EptBreakpointSizeDword:
            Character = '4';
            break;

        case EptBreakpointSizeQword:
            Character = '8';
            break;

        default:
            ERR_PRINT("Unhandled BreakpointSize: %d", BreakpointSize);
            Character = '?';
            DEBUG_BREAK();
            goto exit;
    }

exit:
    return Character;
}


//=============================================================================
// Private Vmx Non-Root Interface
//=============================================================================
_Use_decl_annotations_
static
VOID
EbmpCreateProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN fCreate
)
{
    BOOLEAN fGateAcquired = FALSE;
    PLIST_ENTRY pNextEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    BOOLEAN fClearRequired = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ParentId);

    //
    // Ignore process creation.
    //
    if (fCreate)
    {
        goto exit;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(
        &g_EbmVmxNonRootContext.Gate);
    //
    fGateAcquired = TRUE;

    //
    // If there is no registered EBM client then there is no work to be done.
    //
    if (!g_EbmVmxNonRootContext.ClientRegistered)
    {
        goto exit;
    }

    //
    // If the EBM client process terminated then unregister them.
    //
    if (g_EbmVmxNonRootContext.Client.ProcessId == ProcessId)
    {
        VERIFY_NTSTATUS(EbmUnregisterClient(ProcessId));
        goto exit;
    }

    //
    // TODO Add a process-breakpoint bookkeeping list or table so that we do
    //  not need to traverse the entire breakpoint list whenever a process
    //  terminates.
    //

    //
    // Determine if there are any active ept breakpoints in the terminating
    //  process.
    //
    pNextEntry = g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead.Flink;

    while (
        pNextEntry != &g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead)
    {
        pNonRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.ListEntry);

        pNextEntry = pNonRootEntry->u.Active.ListEntry.Flink;

        NT_ASSERT(pNonRootEntry->IsActive);

        if (pNonRootEntry->Breakpoint->ProcessId == ProcessId)
        {
            fClearRequired = TRUE;
            break;
        }
    }
    //
    if (!fClearRequired)
    {
        goto exit;
    }

    ntstatus = EbmpUninstallEptBreakpointsByProcessId(ProcessId);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpUninstallEptBreakpointsByProcessId failed: 0x%X",
            ntstatus);
        DEBUG_BREAK();
        goto exit;
    }

    //
    // Disable all active ept breakpoints in the terminating process.
    //
    pNextEntry = g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead.Flink;

    while (
        pNextEntry != &g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead)
    {
        pNonRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.ListEntry);

        pNextEntry = pNonRootEntry->u.Active.ListEntry.Flink;

        if (pNonRootEntry->Breakpoint->ProcessId == ProcessId)
        {
            //
            // NOTE All locked pages in the terminating process will be
            //  unlocked and destroyed when their breakpoint count reaches
            //  zero.
            //
            EbmpMakeEptBreakpointInactive(pNonRootEntry, TRUE);
        }
    }

exit:
    if (fGateAcquired)
    {
        ExReleaseResourceAndLeaveCriticalRegion(&g_EbmVmxNonRootContext.Gate);
    }

    return;
}


static
VOID
EbmpPrintProcessorStatistics()
{
    ULONG i = 0;
    PEBM_PROCESSOR_CONTEXT pProcessorContext = NULL;

    INF_PRINT("EBM Processor Statistics:");

    for (i = 0; i < g_EbmVmxRootContext.NumberOfProcessors; i++)
    {
        pProcessorContext = &g_EbmVmxRootContext.Processors[i];

        INF_PRINT("    Processor %u", i);
        INF_PRINT("        HookedPageEntries:       %I64u",
            pProcessorContext->Statistics.HookedPageEntries);
        INF_PRINT("        BreakpointHits:          %I64u",
            pProcessorContext->Statistics.BreakpointHits);
        INF_PRINT("        BreakpointMisses:        %I64u",
            pProcessorContext->Statistics.BreakpointMisses);
        INF_PRINT("        EptViolationExits:       %I64u",
            pProcessorContext->Statistics.EptViolationExits);
        INF_PRINT("        MonitorTrapFlagExits:    %I64u",
            pProcessorContext->Statistics.MonitorTrapFlagExits);
    }
}


/*++

Description:

    Resets an EBM client context.

Parameters:

    pClientContext - Pointer to the EBM client context to be reset.

Requirements:

    The caller must release the resources associated with an EBM client context
    by calling 'EbmpReleaseClientContext' before calling this routine.

--*/
_Use_decl_annotations_
static
VOID
EbmpResetClientContext(
    PEBM_CLIENT_CONTEXT pClientContext
)
{
    pClientContext->ProcessId = NULL;
    pClientContext->NextFreeHandle = 0;
    pClientContext->NumberOfLockedPages = 0;
    InitializeListHead(&pClientContext->LockedPageListHead);
    pClientContext->NumberOfActiveBreakpoints = 0;
    InitializeListHead(&pClientContext->ActiveBreakpointListHead);
    pClientContext->NumberOfInactiveBreakpoints = 0;
    InitializeListHead(&pClientContext->InactiveBreakpointListHead);
}


/*++

Description:

    Releases the resources of an EBM client context.

Parameters:

    pClientContext - Pointer to the EBM client context whose resources will be
        released.

Requirements:

    This routine must be invoked in the process context of the EBM client
    process.

Remarks:

    This routine uninstalls all active ept breakpoints and destroys all
    non-root entries and locked page entries.

--*/
_Use_decl_annotations_
static
VOID
EbmpReleaseClientContext(
    PEBM_CLIENT_CONTEXT pClientContext
)
{
    PLIST_ENTRY pNextEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    PEPT_BREAKPOINT pEptBreakpoint = NULL;
    PEBM_LOG_CONTEXT pLogContext = NULL;

    NT_ASSERT(PsGetCurrentProcessId() == pClientContext->ProcessId);
    NT_ASSERT(
        PsGetProcessId(PsGetCurrentProcess()) == pClientContext->ProcessId);

    VERIFY_NTSTATUS(
        SysExecuteProcessorCallback(
            EbmpUninstallAllEptBreakpointsCallback,
            NULL,
            NULL,
            NULL));

    //
    // Destroy the active breakpoint bookkeeping.
    //
    pNextEntry = pClientContext->ActiveBreakpointListHead.Flink;

    while (pNextEntry != &pClientContext->ActiveBreakpointListHead)
    {
        pNonRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.ListEntry);

        pNextEntry = pNonRootEntry->u.Active.ListEntry.Flink;

        pEptBreakpoint = pNonRootEntry->Breakpoint;
        pLogContext = pEptBreakpoint->LogContext;

        EbmpDestroyEptBreakpointNonRootEntry(pNonRootEntry);
        EbmpDestroyEptBreakpoint(pEptBreakpoint);
        EbmpDestroyLogContext(pLogContext);
    }

    VERIFY_BOOLEAN(!pClientContext->NumberOfActiveBreakpoints);
    VERIFY_BOOLEAN(IsListEmpty(&pClientContext->ActiveBreakpointListHead));

    //
    // Destroy the inactive breakpoint bookkeeping.
    //
    pNextEntry = pClientContext->InactiveBreakpointListHead.Flink;

    while (pNextEntry != &pClientContext->InactiveBreakpointListHead)
    {
        pNonRootEntry = CONTAINING_RECORD(
            pNextEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Inactive.ListEntry);

        pNextEntry = pNonRootEntry->u.Inactive.ListEntry.Flink;

        pEptBreakpoint = pNonRootEntry->Breakpoint;
        pLogContext = pEptBreakpoint->LogContext;

        EbmpDestroyEptBreakpointNonRootEntry(pNonRootEntry);
        EbmpDestroyEptBreakpoint(pEptBreakpoint);
        EbmpDestroyLogContext(pLogContext);
    }

    VERIFY_BOOLEAN(!pClientContext->NumberOfInactiveBreakpoints);
    VERIFY_BOOLEAN(IsListEmpty(&pClientContext->InactiveBreakpointListHead));

    VERIFY_BOOLEAN(!g_EbmVmxNonRootContext.Client.NumberOfLockedPages);
    VERIFY_BOOLEAN(IsListEmpty(&pClientContext->LockedPageListHead));
}


/*++

Description:

    Determine if the caller is the registered EBM client.

Return Value:

    Returns TRUE if the caller is the registered EBM client.

    Returns FALSE if the caller is not the registered EBM client.

--*/
_Use_decl_annotations_
static
BOOLEAN
EbmpVerifyClientContext()
{
    BOOLEAN status = TRUE;

    if (!g_EbmVmxNonRootContext.ClientRegistered)
    {
        status = FALSE;
        goto exit;
    }

    if (PsGetCurrentProcessId() != g_EbmVmxNonRootContext.Client.ProcessId)
    {
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


/*++

Description:

    Calculates the size in bytes required to store ept breakpoint information
    for all active and inactive ept breakpoints.

Parameters:

    pcbRequired - Returns the required size in bytes.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmpGetEptBreakpointInformationSize(
    PULONG pcbRequired
)
{
    ULONG nBreakpoints = 0;
    ULONG cbRequired = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *pcbRequired = 0;

    ntstatus = RtlULongAdd(
        g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints,
        g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints,
        &nBreakpoints);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("RtlULongAdd failed: 0x%X", ntstatus);
        goto exit;
    }

    cbRequired = RTL_SIZEOF_THROUGH_FIELD(
        EPT_BREAKPOINT_INFORMATION,
        Elements[nBreakpoints]);

    //
    // Set output parameters.
    //
    *pcbRequired = cbRequired;

exit:
    return ntstatus;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpCalculateLogMaxIndex(
    EPT_BREAKPOINT_LOG_TYPE LogType,
    SIZE_T cbLog,
    PULONG pMaxIndex
)
{
    ULONG MaxIndex = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *pMaxIndex = 0;

    // TODO Review SIZE_T / ULONG edge cases.
    switch (LogType)
    {
        case EptBreakpointLogTypeBasic:
            MaxIndex = (ULONG)(
                (cbLog - FIELD_OFFSET(EPT_BREAKPOINT_LOG, u.Basic.Elements))
                    / (RTL_FIELD_SIZE(EPT_BREAKPOINT_LOG, u.Basic.Elements)));
            break;

        case EptBreakpointLogTypeGeneralRegisterContext:
            MaxIndex = (ULONG)(
                (cbLog -
                    FIELD_OFFSET(
                        EPT_BREAKPOINT_LOG,
                        u.GeneralRegisterContext.Elements))
                    / (RTL_FIELD_SIZE(
                        EPT_BREAKPOINT_LOG,
                        u.GeneralRegisterContext.Elements)));
            break;

        case EptBreakpointLogTypeKeyedRegisterContext:
            MaxIndex = (ULONG)(
                (cbLog -
                    FIELD_OFFSET(
                        EPT_BREAKPOINT_LOG,
                        u.KeyedRegisterContext.Elements))
                    / (RTL_FIELD_SIZE(
                        EPT_BREAKPOINT_LOG,
                        u.KeyedRegisterContext.Elements)));
            break;

        default:
            ntstatus = STATUS_INVALID_PARAMETER_1;
            goto exit;
    }

    //
    // Set output parameters.
    //
    *pMaxIndex = MaxIndex;

exit:
    return ntstatus;
}


/*++

Description:

    Creates a log context bookkeeping object for the specified ept breakpoint
    parameters.

Parameters:

    ProcessId - The target process of the ept breakpoint.

    pVirtualAddress - The target virtual address of the ept breakpoint.

    BreakpointType - The breakpoint type of the ept breakpoint.

    BreakpointSize - The breakpoint size of the ept breakpoint.

    LogType - The log type of the ept breakpoint.

    cbLog - The size in bytes of the ept breakpoint log.

    RegisterKey - If 'LogType' is 'EptBreakpointLogTypeKeyedRegisterContext'
        then this parameter specifies which register is used to determine the
        uniqueness of a guest context when the corresponding ept breakpoint is
        triggered.

    ppLogContext - Returns a pointer to the created log context. (NonPagedPool)

Requirements:

    This routine must be invoked in the EBM client process context.

    On success, the caller must destroy the returned log context by calling
    'EbmpDestroyLogContext'.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmpCreateLogContext(
    HANDLE ProcessId,
    PVOID pVirtualAddress,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    EPT_BREAKPOINT_LOG_TYPE LogType,
    SIZE_T cbLog,
    X64_REGISTER RegisterKey,
    PEBM_LOG_CONTEXT* ppLogContext
)
{
    ULONG MaxIndex = 0;
    PEBM_LOG_CONTEXT pLogContext = NULL;
    PVOID pSectionObject = NULL;
    LARGE_INTEGER cbSection = {};
    BOOLEAN fSectionCreated = FALSE;
    PVOID pKernelBaseAddress = NULL;
    SIZE_T cbView = 0;
    BOOLEAN fKernelViewMapped = FALSE;
    HANDLE SectionHandle = NULL;
    BOOLEAN fSectionHandleOpened = FALSE;
    PVOID pUserBaseAddress = NULL;
    BOOLEAN fUserViewMapped = FALSE;
    HANDLE SecureHandle = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    NT_ASSERT(
        PsGetCurrentProcessId() == g_EbmVmxNonRootContext.Client.ProcessId);

    //
    // Zero output parameters.
    //
    *ppLogContext = NULL;

    //
    // Validate input parameters.
    //
    if (sizeof(*pLogContext) > cbLog)
    {
        ERR_PRINT("Log size is too small. (MinimumSize = 0x%IX bytes)",
            sizeof(*pLogContext));
        ntstatus = STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (CFG_EBM_LOG_SIZE_MAX < cbLog)
    {
        ERR_PRINT("Log size is too large. (MaximumSize = 0x%IX bytes)",
            CFG_EBM_LOG_SIZE_MAX);
        ntstatus = STATUS_BUFFER_OVERFLOW;
        goto exit;
    }

    ntstatus = EbmpCalculateLogMaxIndex(LogType, cbLog, &MaxIndex);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmpCalculateLogMaxIndex failed: 0x%X", ntstatus);
        goto exit;
    }

    pLogContext = (PEBM_LOG_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pLogContext),
        MODULE_TAG);
    if (!pLogContext)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    //
    // Create the section with the SEC_NO_CHANGE flag so that the protection of
    //  the mapped user mode view cannot be changed.
    //
    cbSection.QuadPart = cbLog;

    ntstatus = MmCreateSection(
        &pSectionObject,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        NULL,
        &cbSection,
        PAGE_READWRITE,
        SEC_COMMIT | SEC_NO_CHANGE,
        NULL,
        NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("MmCreateSection failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fSectionCreated = TRUE;

#if !defined(DBG)
    //
    // TODO Research and comment on the benefits of deleting object creation
    //  information here.
    //
    ObDeleteCapturedInsertInfo(pSectionObject);
#endif

    ntstatus =
        MmMapViewInSystemSpace(pSectionObject, &pKernelBaseAddress, &cbView);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("MmMapViewInSystemSpace failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fKernelViewMapped = TRUE;

    //
    // TODO Are sections guaranteed to be zeroed? If yes then remove.
    //
    RtlSecureZeroMemory(pKernelBaseAddress, cbView);

    //
    // Update the breakpoint status before the breakpoint log is mapped for the
    //  client.
    //
    pLog = (PEPT_BREAKPOINT_LOG)pKernelBaseAddress;
    pLog->Header.BreakpointStatus = EptBreakpointStatusInstalling;

    //
    // Map a read-only view of the log section into the EBM client's virtual
    //  address space.
    //
    ntstatus = ObOpenObjectByPointer(
        pSectionObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        SECTION_MAP_READ,
        NULL,
        KernelMode,
        &SectionHandle);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("ObOpenObjectByPointer failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fSectionHandleOpened = TRUE;

    cbView = 0;

    ntstatus = ZwMapViewOfSection(
        SectionHandle,
        ZwCurrentProcess(),
        &pUserBaseAddress,
        0,
        0,
        NULL,
        &cbView,
        ViewUnmap,
        0,
        PAGE_READONLY);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("ZwMapViewOfSection failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fUserViewMapped = TRUE;

    SecureHandle =
        MmSecureVirtualMemory(pUserBaseAddress, cbView, PAGE_READONLY);
    if (!SecureHandle)
    {
        ERR_PRINT("MmSecureVirtualMemory failed: 0x%X", ntstatus);
        goto exit;
    }

    //
    // Initialize the log header.
    //
    pLog->Header.ProcessId = (ULONG_PTR)ProcessId;
    pLog->Header.Address = (ULONG_PTR)pVirtualAddress;
    pLog->Header.BreakpointType = BreakpointType;
    pLog->Header.BreakpointSize = BreakpointSize;
    pLog->Header.LogType = LogType;
    pLog->Header.RegisterKey = RegisterKey;
    pLog->Header.MaxIndex = MaxIndex;
    pLog->Header.NumberOfElements = 0;

    //
    // Initialize the log context.
    //
    pLogContext->SectionObject = pSectionObject;
    pLogContext->SectionHandle = SectionHandle;
    pLogContext->SecureHandle = SecureHandle;
    pLogContext->LogViewSize = cbView;
    KeInitializeSpinLock(&pLogContext->UpdateLock);
    pLogContext->KernelMapping.BaseAddress = pKernelBaseAddress;
    pLogContext->UserMapping.BaseAddress = pUserBaseAddress;

    //
    // Set output parameters.
    //
    *ppLogContext = pLogContext;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (SecureHandle)
        {
            MmUnsecureVirtualMemory(SecureHandle);
        }

        if (fUserViewMapped)
        {
            VERIFY_NTSTATUS(
                ZwUnmapViewOfSection(
                    ZwCurrentProcess(),
                    pUserBaseAddress));
        }

        if (fSectionHandleOpened)
        {
            VERIFY_NTSTATUS(ZwClose(SectionHandle));
        }

        if (fKernelViewMapped)
        {
            VERIFY_NTSTATUS(MmUnmapViewInSystemSpace(pKernelBaseAddress));
        }

        if (fSectionCreated)
        {
            ObfDereferenceObject(pSectionObject);
        }

        if (pLogContext)
        {
            ExFreePoolWithTag(pLogContext, MODULE_TAG);
        }
    }

    return ntstatus;
}


/*++

Description:

    Destroys a log context bookkeeping object.

Parameters:

    pLogContext - The log context to be destroyed.

Requirements:

    This routine must be invoked in the EBM client process context.

Remarks:

    The order of the unwind operations should mirror the order used in
    'EbmpCreateLogContext'.

--*/
_Use_decl_annotations_
static
VOID
EbmpDestroyLogContext(
    PEBM_LOG_CONTEXT pLogContext
)
{
    NT_ASSERT(
        PsGetCurrentProcessId() == g_EbmVmxNonRootContext.Client.ProcessId);

    MmUnsecureVirtualMemory(pLogContext->SecureHandle);

    VERIFY_NTSTATUS(
        ZwUnmapViewOfSection(
            ZwCurrentProcess(),
            pLogContext->UserMapping.BaseAddress));

    VERIFY_NTSTATUS(ZwClose(pLogContext->SectionHandle));

    VERIFY_NTSTATUS(
        MmUnmapViewInSystemSpace(
            pLogContext->KernelMapping.BaseAddress));

    ObfDereferenceObject(pLogContext->SectionObject);

    ExFreePoolWithTag(pLogContext, MODULE_TAG);
}


/*++

Description:

    Creates a locked page entry for the specified virtual address or returns an
    existing entry.

Parameters:

    ProcessId - The process which owns the target virtual page.

    pVirtualAddress - The target virtual address of the ept breakpoint.

    BreakpointSize - The breakpoint size of the ept breakpoint.

    fMakePageResident - If TRUE then the page containing the target virtual
        address is made resident (if it is currently paged out) then locked in
        memory. If FALSE then this routine fails if the target page is not
        resident in memory.

    ppLockedPageEntry - Returns a pointer to an existing locked page entry for
        the target page if it exists. Otherwise, returns a pointer to a new
        entry.

    pfLockedPageEntryCreated - Returns TRUE if the returned locked page entry
        was created.

Requirements:

    This routine must be invoked in the process context of the process
    specified by 'ProcessId'.

    On success, if '*pfLockedPageEntryCreated' is TRUE then the caller must
    destroy the returned locked page entry by calling
    'EbmpDestroyLockedPageEntry'.

Remarks:

    The page that contains the target virtual address is locked in the current
    process context.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmpCreateLockedPageEntry(
    HANDLE ProcessId,
    PVOID pVirtualAddress,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    BOOLEAN fMakePageResident,
    PLOCKED_PAGE_ENTRY* ppLockedPageEntry,
    PBOOLEAN pfLockedPageEntryCreated
)
{
    PMDL pMakeResidentMdl = NULL;
    BOOLEAN fMakeResidentPageLocked = FALSE;
    PLOCKED_PAGE_ENTRY pLockedPageEntry = NULL;
    PMDL pMdl = NULL;
    BOOLEAN fPageLocked = FALSE;
    ULONG64 PhysicalAddress = 0;
    ULONG64 PhysicalPage = 0;
    BOOLEAN fLockedPageEntryCreated = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppLockedPageEntry = NULL;
    *pfLockedPageEntryCreated = FALSE;

    //
    // Verify that we are in the target process context.
    //
    if (PsGetProcessId(PsGetCurrentProcess()) != ProcessId)
    {
        ERR_PRINT("Unexpected process context. (ProcessId = %Iu)", ProcessId);
        ntstatus = STATUS_INVALID_PARAMETER_1;
        goto exit;
    }

    //
    // Lock the target virtual page if requested.
    //
    if (fMakePageResident)
    {
        pMakeResidentMdl =
            IoAllocateMdl(pVirtualAddress, BreakpointSize, FALSE, FALSE, NULL);
        if (!pMakeResidentMdl)
        {
            ntstatus = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        __try
        {
            MmProbeAndLockPages(pMakeResidentMdl, KernelMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ERR_PRINT("MmProbeAndLockPages failed: 0x%X", GetExceptionCode());
            ntstatus = STATUS_UNHANDLED_EXCEPTION;
            goto exit;
        }
        //
        fMakeResidentPageLocked = TRUE;
    }

    //
    // TODO Return a custom ntstatus code if the target physical page is not
    //  resident.
    //
    PhysicalAddress = UtilPaFromVa(pVirtualAddress);
    if (!PhysicalAddress)
    {
        ERR_PRINT("UtilPaFromVa failed. (VA = %p)", pVirtualAddress);
        ntstatus = STATUS_INVALID_ADDRESS;
        goto exit;
    }

    PhysicalPage = (ULONG64)PAGE_ALIGN(PhysicalAddress);

    //
    // Check if we already have a locked page entry for the target physical
    //  page.
    //
    pLockedPageEntry = EbmpLookupLockedPageEntry(ProcessId, PhysicalPage);
    if (!pLockedPageEntry)
    {
        pMdl = IoAllocateMdl(
            pVirtualAddress,
            BreakpointSize,
            FALSE,
            FALSE,
            NULL);
        if (!pMdl)
        {
            ntstatus = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        __try
        {
            MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ERR_PRINT("MmProbeAndLockPages failed: 0x%X",
                GetExceptionCode());
            ntstatus = STATUS_UNSUCCESSFUL;
            goto exit;
        }
        //
        fPageLocked = TRUE;

        //
        // Allocate and initialize a new entry.
        //
        pLockedPageEntry = (PLOCKED_PAGE_ENTRY)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(*pLockedPageEntry),
            MODULE_TAG);
        if (!pLockedPageEntry)
        {
            ntstatus = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }
        //
        pLockedPageEntry->ProcessId = ProcessId;
        pLockedPageEntry->Process = PsGetCurrentProcess();
        pLockedPageEntry->PhysicalPage = PhysicalPage;
        pLockedPageEntry->Mdl = pMdl;
        pLockedPageEntry->NumberOfBreakpoints = 0;
        InitializeListHead(&pLockedPageEntry->BreakpointListHead);

        //
        // Insert the entry into the locked page list.
        //
        InsertTailList(
            &g_EbmVmxNonRootContext.Client.LockedPageListHead,
            &pLockedPageEntry->ListEntry);

        g_EbmVmxNonRootContext.Client.NumberOfLockedPages++;

        fLockedPageEntryCreated = TRUE;

        INF_PRINT_V("Created locked page entry. (PID = %Iu, GPA = %p)",
            pLockedPageEntry->ProcessId,
            pLockedPageEntry->PhysicalPage);
    }
    else
    {
        INF_PRINT_V(
            "Using existing locked page entry. (PID = %Iu, GPA = %p)",
            pLockedPageEntry->ProcessId,
            pLockedPageEntry->PhysicalPage);
    }

    //
    // Set output parameters.
    //
    *ppLockedPageEntry = pLockedPageEntry;
    *pfLockedPageEntryCreated = fLockedPageEntryCreated;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pLockedPageEntry)
        {
            ExFreePoolWithTag(pLockedPageEntry, MODULE_TAG);
        }

        if (fPageLocked)
        {
            MmUnlockPages(pMdl);
        }

        if (pMdl)
        {
            IoFreeMdl(pMdl);
        }
    }

    if (fMakeResidentPageLocked)
    {
        MmUnlockPages(pMakeResidentMdl);
    }

    if (pMakeResidentMdl)
    {
        IoFreeMdl(pMakeResidentMdl);
    }

    return ntstatus;
}


/*++

Description:

    Destroys a locked page entry.

Parameters:

    pLockedPageEntry - The locked page entry to be destroyed.

--*/
_Use_decl_annotations_
static
VOID
EbmpDestroyLockedPageEntry(
    PLOCKED_PAGE_ENTRY pLockedPageEntry
)
{
    KAPC_STATE ApcState = {};
    BOOLEAN fAttached = FALSE;

    NT_ASSERT(!pLockedPageEntry->NumberOfBreakpoints);
    NT_ASSERT(IsListEmpty(&pLockedPageEntry->BreakpointListHead));

    INF_PRINT_V("Destroying locked page entry. (PID = %Iu, GPA = %p)",
        pLockedPageEntry->ProcessId,
        pLockedPageEntry->PhysicalPage);

    //
    // Remove the entry from the locked page list.
    //
    RemoveEntryList(&pLockedPageEntry->ListEntry);

    g_EbmVmxNonRootContext.Client.NumberOfLockedPages--;

    //
    // We must unlock the target page in the owning process context.
    //
    if (PsGetCurrentProcess() != pLockedPageEntry->Process)
    {
        KeStackAttachProcess(pLockedPageEntry->Process, &ApcState);
        fAttached = TRUE;
    }

    MmUnlockPages(pLockedPageEntry->Mdl);

    if (fAttached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    IoFreeMdl(pLockedPageEntry->Mdl);

    ExFreePoolWithTag(pLockedPageEntry, MODULE_TAG);
}


/*++

Description:

    Creates an ept breakpoint object for the specified breakpoint parameters.

Parameters:

    ProcessId - The target process of the ept breakpoint.

    pVirtualAddress - The target virtual address of the ept breakpoint.

    BreakpointType - The breakpoint type of the ept breakpoint.

    BreakpointSize - The breakpoint size of the ept breakpoint.

    pLogContext - The log context for the ept breakpoint.

    ppEptBreakpoint - Returns a pointer to the ept breakpoint object.

Requirements:

    On success, the caller must destroy the returned ept breakpoint object by
    calling 'EbmpDestroyEptBreakpoint'.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmpCreateEptBreakpoint(
    HANDLE ProcessId,
    PVOID pVirtualAddress,
    EPT_BREAKPOINT_TYPE BreakpointType,
    EPT_BREAKPOINT_SIZE BreakpointSize,
    PEBM_LOG_CONTEXT pLogContext,
    PEPT_BREAKPOINT* ppEptBreakpoint
)
{
    ULONG64 PhysicalAddress = 0;
    PEPT_BREAKPOINT pEptBreakpoint = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppEptBreakpoint = NULL;

    if (0 > g_EbmVmxNonRootContext.Client.NextFreeHandle)
    {
        ntstatus = STATUS_IMPLEMENTATION_LIMIT;
        goto exit;
    }

    PhysicalAddress = UtilPaFromVa(pVirtualAddress);
    if (!PhysicalAddress)
    {
        ERR_PRINT("UtilPaFromVa failed. (VA = %p)", pVirtualAddress);
        ntstatus = STATUS_INVALID_ADDRESS;
        goto exit;
    }

    //
    // Allocate and initialize the breakpoint.
    //
    pEptBreakpoint = (PEPT_BREAKPOINT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pEptBreakpoint),
        MODULE_TAG);
    if (!pEptBreakpoint)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pEptBreakpoint->Handle =
        (HANDLE)(++g_EbmVmxNonRootContext.Client.NextFreeHandle);
    pEptBreakpoint->ProcessId = ProcessId;
    pEptBreakpoint->GuestVirtualAddress = pVirtualAddress;
    pEptBreakpoint->GuestPhysicalAddress = PhysicalAddress;
    pEptBreakpoint->BreakpointType = BreakpointType;
    pEptBreakpoint->BreakpointSize = BreakpointSize;
    pEptBreakpoint->LogContext = pLogContext;

    //
    // Set output parameters.
    //
    *ppEptBreakpoint = pEptBreakpoint;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pEptBreakpoint)
        {
            ExFreePoolWithTag(pEptBreakpoint, MODULE_TAG);
        }
    }

    return ntstatus;
}


/*++

Description:

    Destroys an ept breakpoint object.

Parameters:

    pEptBreakpoint - The ept breakpoint object to be destroyed.

--*/
_Use_decl_annotations_
static
VOID
EbmpDestroyEptBreakpoint(
    PEPT_BREAKPOINT pEptBreakpoint
)
{
    ExFreePoolWithTag(pEptBreakpoint, MODULE_TAG);
}


/*++

Description:

    Creates an ept breakpoint non-root entry for the specified ept breakpoint
    object and inserts it into the EBM client context bookkeeping.

Parameters:

    pLockedPageEntry - The locked page which will contain the non-root entry.

    pEptBreakpoint - The ept breakpoint object for the non-root entry.

    ppNonRootEntry - Returns a pointer to the created non-root entry.

Requirements:

    On success, the caller must destroy the returned non-root entry by
    calling 'EbmpDestroyEptBreakpointNonRootEntry'.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmpCreateEptBreakpointNonRootEntry(
    PLOCKED_PAGE_ENTRY pLockedPageEntry,
    PEPT_BREAKPOINT pEptBreakpoint,
    PEPT_BREAKPOINT_NON_ROOT_ENTRY* ppNonRootEntry
)
{
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppNonRootEntry = NULL;

    //
    // Allocate and initialize a new non-root entry.
    //
    pNonRootEntry = (PEPT_BREAKPOINT_NON_ROOT_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pNonRootEntry),
        MODULE_TAG);
    if (!pNonRootEntry)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pNonRootEntry->Breakpoint = pEptBreakpoint;
    pNonRootEntry->IsActive = TRUE;
    pNonRootEntry->u.Active.LockedPage = pLockedPageEntry;

    //
    // Insert the breakpoint into the vmx non-root context breakpoint list.
    //
    InsertTailList(
        &g_EbmVmxNonRootContext.Client.ActiveBreakpointListHead,
        &pNonRootEntry->u.Active.ListEntry);

    g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints++;

    //
    // Insert the breakpoint into the locked page breakpoint list.
    //
    InsertTailList(
        &pLockedPageEntry->BreakpointListHead,
        &pNonRootEntry->u.Active.LockedPageListEntry);

    pLockedPageEntry->NumberOfBreakpoints++;

    //
    // Set out parameters.
    //
    *ppNonRootEntry = pNonRootEntry;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pNonRootEntry)
        {
            ExFreePoolWithTag(pNonRootEntry, MODULE_TAG);
        }
    }

    return ntstatus;
}


/*++

Description:

    Destroys an ept breakpoint non-root entry.

Parameters:

    pNonRootEntry - The non-root entry to be destroyed.

Return Value:

    Returns TRUE if the specified non-root entry's locked page entry was
        destroyed.

    Returns FALSE if the specified non-root entry's locked page entry has
        active ept breakpoints after the specified non-root entry was
        destroyed.

--*/
_Use_decl_annotations_
static
BOOLEAN
EbmpDestroyEptBreakpointNonRootEntry(
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry
)
{
    BOOLEAN fLockedPageEntryDestroyed = FALSE;

    NT_ASSERT(pNonRootEntry->Breakpoint);
    NT_ASSERT(pNonRootEntry->Breakpoint->LogContext);

    INF_PRINT_V(
        "Destroying ept breakpoint non-root entry."
        " (H = %Iu, GVA = %p, GPA = %p, Active = %s)",
        pNonRootEntry->Breakpoint->Handle,
        pNonRootEntry->Breakpoint->GuestVirtualAddress,
        pNonRootEntry->Breakpoint->GuestPhysicalAddress,
        pNonRootEntry->IsActive ? "TRUE" : "FALSE");

    if (pNonRootEntry->IsActive)
    {
        RemoveEntryList(&pNonRootEntry->u.Active.ListEntry);

        g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints--;

        pNonRootEntry->u.Active.LockedPage->NumberOfBreakpoints--;

        if (RemoveEntryList(&pNonRootEntry->u.Active.LockedPageListEntry))
        {
            EbmpDestroyLockedPageEntry(pNonRootEntry->u.Active.LockedPage);

            fLockedPageEntryDestroyed = TRUE;
        }
    }
    else
    {
        RemoveEntryList(&pNonRootEntry->u.Inactive.ListEntry);

        g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints--;
    }

    ExFreePoolWithTag(pNonRootEntry, MODULE_TAG);

    return fLockedPageEntryDestroyed;
}


/*++

Description:

    Search the specified locked page for conflicting ept breakpoints.

Parameters:

    pLockedPageEntry - The locked page entry to search.

    pEptBreakpoint - The ept breakpoint to verify.

Return Value:

    Returns TRUE if the specified ept breakpoint does not overlap any ept
        breakpoints in the breakpoint list of the locked page.

    Returns FALSE if the specified ept breakpoint overlaps an ept breakpoint in
        the breakpoint list of the locked page.

--*/
_Use_decl_annotations_
static
BOOLEAN
EbmpVerifyEptBreakpointAddressSpanInLockedPage(
    PLOCKED_PAGE_ENTRY pLockedPageEntry,
    PEPT_BREAKPOINT pEptBreakpoint
)
{
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pEntry = NULL;
    ULONG64 PhysicalAddressMinimum = 0;
    ULONG64 PhysicalAddressMaximum = 0;
    BOOLEAN status = TRUE;

    //
    // Calculate the span of the provided ept breakpoint.
    //
    PhysicalAddressMinimum = pEptBreakpoint->GuestPhysicalAddress;
    PhysicalAddressMaximum =
        pEptBreakpoint->GuestPhysicalAddress + pEptBreakpoint->BreakpointSize;

    for (pListEntry = pLockedPageEntry->BreakpointListHead.Flink;
        pListEntry != &pLockedPageEntry->BreakpointListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.LockedPageListEntry);

        //
        // Fail if we find an entry with an overlapping address span.
        //
        if (pEntry->Breakpoint->GuestPhysicalAddress <
                PhysicalAddressMaximum &&
            PhysicalAddressMinimum <
                pEntry->Breakpoint->GuestPhysicalAddress +
                pEntry->Breakpoint->BreakpointSize)
        {
            status = FALSE;
            goto exit;
        }
    }

exit:
    return status;
}


/*++

Description:

    Make an ept breakpoint inactive and update vmx non-root bookkeeping to
    reflect this change.

Parameters:

    pNonRootEntry - The ept breakpoint non-root entry to be made inactive.

    fDestroyLockedPage - If TRUE then the corresponding locked page entry is
        destroyed if 'pNonRootEntry' was the last active ept breakpoint in the
        locked page.

--*/
_Use_decl_annotations_
static
VOID
EbmpMakeEptBreakpointInactive(
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry,
    BOOLEAN fDestroyLockedPage
)
{
    NT_ASSERT(pNonRootEntry->IsActive);

    INF_PRINT_V("Disabling ept breakpoint. (# inactive: %u)",
        g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints);

    //
    // Remove the entry from the locked page breakpoint list.
    //
    pNonRootEntry->u.Active.LockedPage->NumberOfBreakpoints--;

    if (RemoveEntryList(&pNonRootEntry->u.Active.LockedPageListEntry))
    {
        if (fDestroyLockedPage)
        {
            EbmpDestroyLockedPageEntry(pNonRootEntry->u.Active.LockedPage);
        }
    }

    InitializeListHead(&pNonRootEntry->u.Active.LockedPageListEntry);

    pNonRootEntry->u.Active.LockedPage = NULL;

    //
    // Remove the entry from the active breakpoint list.
    //
    RemoveEntryList(&pNonRootEntry->u.Active.ListEntry);
    g_EbmVmxNonRootContext.Client.NumberOfActiveBreakpoints--;
    InitializeListHead(&pNonRootEntry->u.Active.ListEntry);

    //
    // Insert the entry into the inactive breakpoint list.
    //
    InsertTailList(
        &g_EbmVmxNonRootContext.Client.InactiveBreakpointListHead,
        &pNonRootEntry->u.Inactive.ListEntry);

    g_EbmVmxNonRootContext.Client.NumberOfInactiveBreakpoints++;

    //
    // Update the breakpoint status.
    //
    pNonRootEntry->IsActive = FALSE;
    pNonRootEntry->Breakpoint->LogContext->KernelMapping.Log->Header.BreakpointStatus =
        EptBreakpointStatusInactive;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpUninstallEptBreakpointsByProcessId(
    HANDLE ProcessId
)
{
    PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT pCallbackContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    INF_PRINT_V("Uninstalling all ept breakpoints for process. (PID = %Iu)",
        ProcessId);

    pCallbackContext = (PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT)
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(*pCallbackContext),
            MODULE_TAG);
    if (!pCallbackContext)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pCallbackContext->NtStatus = STATUS_SUCCESS;
    pCallbackContext->ProcessId = ProcessId;

    ntstatus = SysExecuteProcessorCallback(
        EbmpUninstallEptBreakpointsByProcessIdCallback,
        pCallbackContext,
        NULL,
        NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "EbmpUninstallEptBreakpointsByProcessIdCallback failed: 0x%X",
            ntstatus);
        DEBUG_BREAK();
        goto exit;
    }

exit:
    if (pCallbackContext)
    {
        ExFreePoolWithTag(pCallbackContext, MODULE_TAG);
    }

    return ntstatus;
}


_Use_decl_annotations_
static
PLOCKED_PAGE_ENTRY
EbmpLookupLockedPageEntry(
    HANDLE ProcessId,
    ULONG64 PhysicalPage
)
{
    PLIST_ENTRY pListEntry = NULL;
    PLOCKED_PAGE_ENTRY pEntry = NULL;
    PLOCKED_PAGE_ENTRY pLockedPageEntry = NULL;

    for (pListEntry =
            g_EbmVmxNonRootContext.Client.LockedPageListHead.Flink;
        pListEntry != &g_EbmVmxNonRootContext.Client.LockedPageListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(pListEntry, LOCKED_PAGE_ENTRY, ListEntry);

        if (pEntry->ProcessId == ProcessId &&
            pEntry->PhysicalPage == PhysicalPage)
        {
            pLockedPageEntry = pEntry;
            break;
        }
    }

    return pLockedPageEntry;
}


_Use_decl_annotations_
static
PEPT_BREAKPOINT_NON_ROOT_ENTRY
EbmpLookupEptBreakpointNonRootEntry(
    HANDLE Handle,
    PBOOLEAN pfInactive
)
{
    PEBM_CLIENT_CONTEXT pClientContext = NULL;
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pEntry = NULL;
    PEPT_BREAKPOINT_NON_ROOT_ENTRY pNonRootEntry = NULL;
    BOOLEAN fInactive = FALSE;

    //
    // Zero output parameters.
    //
    *pfInactive = FALSE;

    pClientContext = &g_EbmVmxNonRootContext.Client;

    //
    // Search the active breakpoint list.
    //
    for (pListEntry = pClientContext->ActiveBreakpointListHead.Flink;
        pListEntry != &pClientContext->ActiveBreakpointListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_NON_ROOT_ENTRY,
            u.Active.ListEntry);

        if (pEntry->Breakpoint->Handle == Handle)
        {
            pNonRootEntry = pEntry;
            fInactive = FALSE;
            break;
        }
    }

    if (!pNonRootEntry)
    {
        //
        // Search the inactive breakpoint list.
        //
        for (pListEntry = pClientContext->InactiveBreakpointListHead.Flink;
            pListEntry != &pClientContext->InactiveBreakpointListHead;
            pListEntry = pListEntry->Flink)
        {
            pEntry = CONTAINING_RECORD(
                pListEntry,
                EPT_BREAKPOINT_NON_ROOT_ENTRY,
                u.Inactive.ListEntry);

            if (pEntry->Breakpoint->Handle == Handle)
            {
                pNonRootEntry = pEntry;
                fInactive = TRUE;
                break;
            }
        }
    }

    if (!pNonRootEntry)
    {
        goto exit;
    }

    //
    // Set output parameters.
    //
    *pfInactive = fInactive;

exit:
    return pNonRootEntry;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpInstallEptBreakpointCallback(
    PVOID pContext
)
{
    PINSTALL_EPT_BREAKPOINT_CONTEXT pCallbackContext = NULL;
    KAPC_STATE ApcState = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pCallbackContext = (PINSTALL_EPT_BREAKPOINT_CONTEXT)pContext;

    KeStackAttachProcess(pCallbackContext->Process, &ApcState);

    ntstatus =
        UtilVmCall(HypercallNumber::kInstallEptBreakpoint, pCallbackContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("UtilVmCall failed: 0x%X (kInstallEptBreakpoint)", ntstatus);
        goto exit;
    }

    ntstatus = pCallbackContext->NtStatus;
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmxInstallEptBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    KeUnstackDetachProcess(&ApcState);

    return ntstatus;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpUninstallEptBreakpointCallback(
    PVOID pContext
)
{
    PUNINSTALL_EPT_BREAKPOINT_CONTEXT pCallbackContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pCallbackContext = (PUNINSTALL_EPT_BREAKPOINT_CONTEXT)pContext;

    ntstatus =
        UtilVmCall(HypercallNumber::kUninstallEptBreakpoint, pCallbackContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("UtilVmCall failed: 0x%X (kUninstallEptBreakpoint)",
            ntstatus);
        goto exit;
    }

    ntstatus = pCallbackContext->NtStatus;
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmxUninstallEptBreakpoint failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    return ntstatus;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpUninstallEptBreakpointsByProcessIdCallback(
    PVOID pContext
)
{
    PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT pCallbackContext = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pCallbackContext =
        (PUNINSTALL_EPT_BREAKPOINTS_BY_PROCESS_ID_CONTEXT)pContext;

    ntstatus = UtilVmCall(
        HypercallNumber::kUninstallEptBreakpointsByProcessId,
        pCallbackContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "UtilVmCall failed: 0x%X (kUninstallEptBreakpointsByProcessId)",
            ntstatus);
        goto exit;
    }

    ntstatus = pCallbackContext->NtStatus;
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("EbmxUninstallEptBreakpointsByProcessId failed: 0x%X", ntstatus);
        goto exit;
    }

exit:
    return ntstatus;
}


_Use_decl_annotations_
static
NTSTATUS
EbmpUninstallAllEptBreakpointsCallback(
    PVOID pContext
)
{
    return UtilVmCall(HypercallNumber::kUninstallAllEptBreakpoints, pContext);
}


//=============================================================================
// Private Vmx Root Interface
//=============================================================================
FORCEINLINE
static
PEBM_PROCESSOR_CONTEXT
EbmxpGetCurrentProcessorContext()
{
    return
        &g_EbmVmxRootContext.Processors[KeGetCurrentProcessorNumberEx(NULL)];
}


_Use_decl_annotations_
static
NTSTATUS
EbmxpValidateEptBreakpoint(
    EptData* pEptData,
    PEPT_BREAKPOINT pEptBreakpoint,
    EptCommonEntry** ppEptEntry
)
{
    EptCommonEntry* pEptEntry = NULL;
    ULONG_PTR PreviousCr3 = 0;
    BOOLEAN fCr3Modified = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppEptEntry = NULL;

    //
    // Validate target address.
    //
    if (!IS_ALIGNED(
            pEptBreakpoint->GuestPhysicalAddress,
            pEptBreakpoint->BreakpointSize))
    {
        ntstatus = STATUS_DATATYPE_MISALIGNMENT_ERROR;
        goto exit;
    }

    if (1 != ADDRESS_AND_SIZE_TO_SPAN_PAGES(
            pEptBreakpoint->GuestPhysicalAddress,
            pEptBreakpoint->BreakpointSize))
    {
        ntstatus = STATUS_INVALID_PARAMETER_4;
        goto exit;
    }

    //
    // Validate breakpoint semantics.
    //
    if (EptBreakpointTypeExecute == pEptBreakpoint->BreakpointType &&
        EptBreakpointSizeByte != pEptBreakpoint->BreakpointSize)
    {
        ntstatus = STATUS_INSTRUCTION_MISALIGNMENT;
        goto exit;
    }

    //
    // Validate ept breakpoint fields.
    //
    if (0 >= pEptBreakpoint->Handle)
    {
        ntstatus = STATUS_INVALID_PARAMETER_1;
        goto exit;
    }

#pragma warning(suppress : 28121) // Current IRQL level is too high.
    if (PsGetProcessId(PsGetCurrentProcess()) != pEptBreakpoint->ProcessId)
    {
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

    pEptEntry =
        EptGetEptPtEntry(pEptData, pEptBreakpoint->GuestPhysicalAddress);
    if (!pEptEntry)
    {
        ntstatus = STATUS_INVALID_PARAMETER_3;
        goto exit;
    }

    //
    // TODO Determine if it is safe to update the host cr3 to perform this
    //  check.
    //
    PreviousCr3 = __readcr3();
    __writecr3(UtilVmRead(VmcsField::kGuestCr3));
    fCr3Modified = TRUE;

    if (UtilPaFromVa(pEptBreakpoint->GuestVirtualAddress) !=
        pEptBreakpoint->GuestPhysicalAddress)
    {
        ntstatus = STATUS_INVALID_PARAMETER_4;
        goto exit;
    }

    if (EptBreakpointTypeRead != pEptBreakpoint->BreakpointType &&
        EptBreakpointTypeWrite != pEptBreakpoint->BreakpointType &&
        EptBreakpointTypeExecute != pEptBreakpoint->BreakpointType)
    {
        ntstatus = STATUS_INVALID_PARAMETER_5;
        goto exit;
    }

    if (EptBreakpointSizeByte != pEptBreakpoint->BreakpointSize &&
        EptBreakpointSizeWord != pEptBreakpoint->BreakpointSize &&
        EptBreakpointSizeDword != pEptBreakpoint->BreakpointSize &&
        EptBreakpointSizeQword != pEptBreakpoint->BreakpointSize)
    {
        ntstatus = STATUS_INVALID_PARAMETER_6;
        goto exit;
    }

    //
    // Set output parameters.
    //
    *ppEptEntry = pEptEntry;

exit:
    if (fCr3Modified)
    {
        __writecr3(PreviousCr3);
    }

    return ntstatus;
}


/*++

Description:

    Creates a hooked page entry for the specified guest physical page or
    returns an existing entry.

Parameters:

    pProcessorContext - The processor context in which the hooked page is
        created or returned from.

    pEptEntry - The ept entry for the 'GuestPhysicalPage'.

    ppHookedPageEntry - Returns a pointer to an existing hooked page entry for
        the target page if it exists. Otherwise, returns a pointer to a new
        entry.

Requirements:

    This routine must be invoked in the process context of the process
    specified by 'ProcessId'.

    On success, the caller must destroy the returned hooked page entry by
    calling 'EbmxpDestroyHookedPageEntry'.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmxpCreateHookedPageEntry(
    PEBM_PROCESSOR_CONTEXT pProcessorContext,
    EptCommonEntry* pEptEntry,
    ULONG64 GuestPhysicalPage,
    PHOOKED_PAGE_ENTRY* ppHookedPageEntry
)
{
    PHOOKED_PAGE_ENTRY pHookedPageEntry = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppHookedPageEntry = NULL;

    //
    // Allocate and initialize a new hooked page entry.
    //
#pragma warning(suppress : 28121) // Current IRQL level is too high.
    pHookedPageEntry = (PHOOKED_PAGE_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pHookedPageEntry),
        MODULE_TAG);
    if (!pHookedPageEntry)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    pHookedPageEntry->GuestPhysicalPage = GuestPhysicalPage;
    pHookedPageEntry->EptEntry = pEptEntry;
    pHookedPageEntry->ReadBreakpointCount = 0;
    pHookedPageEntry->WriteBreakpointCount = 0;
    pHookedPageEntry->ExecuteBreakpointCount = 0;
    pHookedPageEntry->NumberOfBreakpoints = 0;
    InitializeListHead(&pHookedPageEntry->BreakpointListHead);

    //
    // Insert the hooked page entry into the processor context hooked page
    //  list.
    //
    InsertTailList(
        &pProcessorContext->HookedPageListHead,
        &pHookedPageEntry->ListEntry);

    pProcessorContext->NumberOfHookedPages++;
    pProcessorContext->Statistics.HookedPageEntries++;

    //
    // Set output parameters.
    //
    *ppHookedPageEntry = pHookedPageEntry;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pHookedPageEntry)
        {
            ExFreePoolWithTag(pHookedPageEntry, MODULE_TAG);
        }
    }

    return ntstatus;
}


_Use_decl_annotations_
static
VOID
EbmxpDestroyHookedPageEntry(
    PHOOKED_PAGE_ENTRY pHookedPageEntry
)
{
    NT_ASSERT(IsListEmpty(&pHookedPageEntry->BreakpointListHead));
    NT_ASSERT(pHookedPageEntry->EptEntry->fields.read_access);
    NT_ASSERT(pHookedPageEntry->EptEntry->fields.write_access);
    NT_ASSERT(pHookedPageEntry->EptEntry->fields.execute_access);
    NT_ASSERT(!pHookedPageEntry->ReadBreakpointCount);
    NT_ASSERT(!pHookedPageEntry->WriteBreakpointCount);
    NT_ASSERT(!pHookedPageEntry->ExecuteBreakpointCount);
    NT_ASSERT(!pHookedPageEntry->NumberOfBreakpoints);

    RemoveEntryList(&pHookedPageEntry->ListEntry);

    EbmxpGetCurrentProcessorContext()->NumberOfHookedPages--;

#pragma warning(suppress : 28121) // Current IRQL level is too high.
    ExFreePoolWithTag(pHookedPageEntry, MODULE_TAG);
}


/*++

Description:

    Creates an ept breakpoint root entry for the specified ept breakpoint
    object, updates the access bits of the target physical page, and inserts
    the new entry into the EBM processor context bookkeeping.

Parameters:

    pProcessorContext - The processor context to receive the new entry.

    pEptBreakpoint - The ept breakpoint object for the non-root entry.

    pHookedPageEntry - The hooked page which contains the breakpoint.

    ppRootEntry - Returns a pointer to the created root entry.

Requirements:

    On success, the caller must destroy the returned root entry by
    calling 'EbmxpDestroyEptBreakpointRootEntry'.

--*/
_Use_decl_annotations_
static
NTSTATUS
EbmxpCreateEptBreakpointRootEntry(
    PEBM_PROCESSOR_CONTEXT pProcessorContext,
    PEPT_BREAKPOINT pEptBreakpoint,
    PHOOKED_PAGE_ENTRY pHookedPageEntry,
    PEPT_BREAKPOINT_ROOT_ENTRY* ppRootEntry
)
{
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;
    BOOLEAN fEptCacheInvalid = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    *ppRootEntry = NULL;

    //
    // Allocate and initialize a new root entry.
    //
    // TODO Use a lookaside list.
    //
#pragma warning(suppress : 28121) // Current IRQL level is too high.
    pRootEntry = (PEPT_BREAKPOINT_ROOT_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pRootEntry),
        MODULE_TAG);
    if (!pRootEntry)
    {
        ntstatus = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    //
    RtlCopyMemory(
        &pRootEntry->Breakpoint,
        pEptBreakpoint,
        sizeof(EPT_BREAKPOINT));
    pRootEntry->HookedPage = pHookedPageEntry;

    //
    // Update the ept entry access permissions if necessary.
    //
    switch (pEptBreakpoint->BreakpointType)
    {
        case EptBreakpointTypeRead:
            //
            // We must disallow read and write access for 'read' breakpoints.
            //  (28.2.3.1 EPT Misconfigurations)
            //
            if (++pHookedPageEntry->ReadBreakpointCount == 1)
            {
                VERIFY_BOOLEAN(pHookedPageEntry->EptEntry->fields.read_access);
                pHookedPageEntry->EptEntry->fields.read_access = FALSE;
                fEptCacheInvalid = TRUE;
            }

            if (++pHookedPageEntry->WriteBreakpointCount == 1)
            {
                VERIFY_BOOLEAN(
                    pHookedPageEntry->EptEntry->fields.write_access);
                pHookedPageEntry->EptEntry->fields.write_access = FALSE;
                fEptCacheInvalid = TRUE;
            }

            break;

        case EptBreakpointTypeWrite:
            if (++pHookedPageEntry->WriteBreakpointCount == 1)
            {
                VERIFY_BOOLEAN(
                    pHookedPageEntry->EptEntry->fields.write_access);
                pHookedPageEntry->EptEntry->fields.write_access = FALSE;
                fEptCacheInvalid = TRUE;
            }

            break;

        case EptBreakpointTypeExecute:
            if (++pHookedPageEntry->ExecuteBreakpointCount == 1)
            {
                VERIFY_BOOLEAN(
                    pHookedPageEntry->EptEntry->fields.execute_access);
                pHookedPageEntry->EptEntry->fields.execute_access = FALSE;
                fEptCacheInvalid = TRUE;
            }

            break;

        default:
            //
            // This should never happen because we validated the breakpoint.
            //
            EbmpBugCheckEx(
                (ULONG_PTR)EbmxInstallEptBreakpoint,
                0,
                0,
                pEptBreakpoint->BreakpointType);
    }

    //
    // Insert the breakpoint into the processor context breakpoint list.
    //
    InsertTailList(
        &pProcessorContext->BreakpointListHead,
        &pRootEntry->ListEntry);

    pProcessorContext->NumberOfBreakpoints++;

    //
    // Insert the breakpoint into the hooked page breakpoint list.
    //
    InsertTailList(
        &pHookedPageEntry->BreakpointListHead,
        &pRootEntry->HookedPageListEntry);

    pHookedPageEntry->NumberOfBreakpoints++;

    //
    // Invalidate the ept cache if necessary.
    //
    if (fEptCacheInvalid)
    {
        VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
    }

    //
    // Set output parameters.
    //
    *ppRootEntry = pRootEntry;

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pRootEntry)
        {
            ExFreePoolWithTag(pRootEntry, MODULE_TAG);
        }
    }

    return ntstatus;
}


_Use_decl_annotations_
static
BOOLEAN
EbmxpDestroyEptBreakpointRootEntry(
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry,
    BOOLEAN fInvalidateEptCache
)
{
    PHOOKED_PAGE_ENTRY pHookedPageEntry = NULL;
    BOOLEAN fEptCacheInvalid = FALSE;
    BOOLEAN fHookedPageEntryDestroyed = FALSE;

    pHookedPageEntry = pRootEntry->HookedPage;

    //
    // Revert ept access permissions if necessary.
    //
    switch (pRootEntry->Breakpoint.BreakpointType)
    {
        case EptBreakpointTypeRead:
            VERIFY_BOOLEAN(!pHookedPageEntry->EptEntry->fields.read_access);

            if (--pHookedPageEntry->ReadBreakpointCount == 0)
            {
                pHookedPageEntry->EptEntry->fields.read_access = TRUE;
                fEptCacheInvalid = TRUE;
            }

            VERIFY_BOOLEAN(!pHookedPageEntry->EptEntry->fields.write_access);

            if (--pHookedPageEntry->WriteBreakpointCount == 0)
            {
                pHookedPageEntry->EptEntry->fields.write_access = TRUE;
                fEptCacheInvalid = TRUE;
            }

            break;

        case EptBreakpointTypeWrite:
            VERIFY_BOOLEAN(!pHookedPageEntry->EptEntry->fields.write_access);

            if (--pHookedPageEntry->WriteBreakpointCount == 0)
            {
                pHookedPageEntry->EptEntry->fields.write_access = TRUE;
                fEptCacheInvalid = TRUE;
            }

            break;

        case EptBreakpointTypeExecute:
            if (!EbmxpGetCurrentProcessorContext()->NumberOfPendingSingleSteps)
            {
                VERIFY_BOOLEAN(
                    !pHookedPageEntry->EptEntry->fields.execute_access);
            }

            if (--pHookedPageEntry->ExecuteBreakpointCount == 0)
            {
                pHookedPageEntry->EptEntry->fields.execute_access = TRUE;
                fEptCacheInvalid = TRUE;
            }

            break;

        default:
            EbmpBugCheckEx(
                (ULONG_PTR)EbmxpDestroyEptBreakpointRootEntry,
                0,
                (ULONG_PTR)pRootEntry,
                pRootEntry->Breakpoint.BreakpointType);
    }

    //
    // Remove the entry from the processor breakpoint list.
    //
    RemoveEntryList(&pRootEntry->ListEntry);

    EbmxpGetCurrentProcessorContext()->NumberOfBreakpoints--;

    //
    // Remove the entry from the hooked page breakpoint list.
    //
    pRootEntry->HookedPage->NumberOfBreakpoints--;

    if (RemoveEntryList(&pRootEntry->HookedPageListEntry))
    {
        //
        // We removed the last breakpoint in the hooked page.
        //
        EbmxpDestroyHookedPageEntry(pRootEntry->HookedPage);

        fHookedPageEntryDestroyed = TRUE;
    }

#pragma warning(suppress : 28121) // Current IRQL level is too high.
    ExFreePoolWithTag(pRootEntry, MODULE_TAG);

    //
    // Invalidate the ept cache if necessary.
    //
    if (fEptCacheInvalid && fInvalidateEptCache)
    {
        VERIFY_BOOLEAN(VmxStatus::kOk == UtilInveptGlobal());
    }

    return fHookedPageEntryDestroyed;
}


/*++

Description:

    Search the specified hooked page for conflicting ept breakpoints.

Parameters:

    pHookedPageEntry - The hooked page entry to search.

    pEptBreakpoint - The ept breakpoint to verify.

Return Value:

    Returns TRUE if the specified ept breakpoint does not overlap any ept
        breakpoints in the breakpoint list of the hooked page.

    Returns FALSE if the specified ept breakpoint overlaps an ept breakpoint in
        the breakpoint list of the hooked page.

--*/
_Use_decl_annotations_
static
BOOLEAN
EbmxpVerifyEptBreakpointAddressSpanInHookedPage(
    PHOOKED_PAGE_ENTRY pHookedPageEntry,
    PEPT_BREAKPOINT pEptBreakpoint
)
{
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pEntry = NULL;
    ULONG64 PhysicalAddressMinimum = 0;
    ULONG64 PhysicalAddressMaximum = 0;
    BOOLEAN status = TRUE;

    //
    // Calculate the span of the provided ept breakpoint.
    //
    PhysicalAddressMinimum = pEptBreakpoint->GuestPhysicalAddress;
    PhysicalAddressMaximum =
        pEptBreakpoint->GuestPhysicalAddress + pEptBreakpoint->BreakpointSize;

    for (pListEntry = pHookedPageEntry->BreakpointListHead.Flink;
        pListEntry != &pHookedPageEntry->BreakpointListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_ROOT_ENTRY,
            HookedPageListEntry);

        //
        // Allow overlapping breakpoints if they are in different processes.
        //
        if (pEntry->Breakpoint.ProcessId != pEptBreakpoint->ProcessId)
        {
            continue;
        }

        //
        // Fail if we find an entry with an overlapping address span.
        //
        if (pEntry->Breakpoint.GuestPhysicalAddress <
                PhysicalAddressMaximum &&
            PhysicalAddressMinimum <
                pEntry->Breakpoint.GuestPhysicalAddress +
                pEntry->Breakpoint.BreakpointSize)
        {
            status = FALSE;
            goto exit;
        }
    }

exit:
    return status;
}


_Use_decl_annotations_
static
VOID
EbmxpInsertEptRestorationEntry(
    PEBM_PROCESSOR_CONTEXT pProcessorContext,
    EptCommonEntry* pEptEntry
)
{
    PEPT_RESTORATION_ENTRY pRestorationEntry = NULL;

    //
    // TODO Use a lookaside list.
    //
#pragma warning(suppress : 28121) // Current IRQL level is too high.
    pRestorationEntry = (PEPT_RESTORATION_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(*pRestorationEntry),
        MODULE_TAG);
    if (!pRestorationEntry)
    {
        EbmpBugCheckEx(
            (ULONG_PTR)EbmxpInsertEptRestorationEntry,
            0,
            sizeof(*pRestorationEntry),
            0);
    }

    pRestorationEntry->EptEntry = pEptEntry;
    pRestorationEntry->PreviousEptEntry = *pEptEntry;
    InsertHeadList(
        &pProcessorContext->EptRestorationListHead,
        &pRestorationEntry->ListEntry);

    pProcessorContext->NumberOfEptRestorations++;
}


_Use_decl_annotations_
static
PHOOKED_PAGE_ENTRY
EbmxpLookupHookedPageEntry(
    PLIST_ENTRY pHookedPageListHead,
    ULONG64 GuestPhysicalPage
)
{
    PLIST_ENTRY pListEntry = NULL;
    PHOOKED_PAGE_ENTRY pEntry = NULL;
    PHOOKED_PAGE_ENTRY pHookedPageEntry = NULL;

    for (pListEntry = pHookedPageListHead->Flink;
        pListEntry != pHookedPageListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(pListEntry, HOOKED_PAGE_ENTRY, ListEntry);

        if (pEntry->GuestPhysicalPage == GuestPhysicalPage)
        {
            pHookedPageEntry = pEntry;
            break;
        }
    }

    return pHookedPageEntry;
}


_Use_decl_annotations_
static
PEPT_BREAKPOINT_ROOT_ENTRY
EbmxpLookupEptBreakpointRootEntryByHandle(
    PLIST_ENTRY pBreakpointListHead,
    HANDLE Handle
)
{
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;

    for (pListEntry = pBreakpointListHead->Flink;
        pListEntry != pBreakpointListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_ROOT_ENTRY,
            ListEntry);

        if (pEntry->Breakpoint.Handle == Handle)
        {
            pRootEntry = pEntry;
            break;
        }
    }

    return pRootEntry;
}


_Use_decl_annotations_
static
PEPT_BREAKPOINT_ROOT_ENTRY
EbmxpFindEptBreakpointRootEntryForEptViolation(
    PHOOKED_PAGE_ENTRY pHookedPageEntry,
    ULONG64 GuestPhysicalAddress,
    EptViolationQualification ExitQualification
)
{
    HANDLE CurrentProcessId = NULL;
    BOOLEAN fReadViolation = FALSE;
    BOOLEAN fWriteViolation = FALSE;
    BOOLEAN fExecuteViolation = FALSE;
    PLIST_ENTRY pListEntry = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pEntry = NULL;
    PEPT_BREAKPOINT pBreakpoint = NULL;
    PEPT_BREAKPOINT_ROOT_ENTRY pRootEntry = NULL;

    //
    // NOTE We must use 'PsGetCurrentProcess' so that the APC state of the
    //  current thread is considered.
    //
#pragma warning(suppress : 28121) // Current IRQL level is too high.
    CurrentProcessId = PsGetProcessId(PsGetCurrentProcess());

    //
    // Determine the access violation cause.
    //
    fReadViolation =
        ExitQualification.fields.read_access &&
        !ExitQualification.fields.ept_readable;

    fWriteViolation =
        ExitQualification.fields.write_access &&
        !ExitQualification.fields.ept_writeable;

    fExecuteViolation =
        ExitQualification.fields.execute_access &&
        !ExitQualification.fields.ept_executable;

    NT_ASSERT(fReadViolation || fWriteViolation || fExecuteViolation);

    for (pListEntry = pHookedPageEntry->BreakpointListHead.Flink;
        pListEntry != &pHookedPageEntry->BreakpointListHead;
        pListEntry = pListEntry->Flink)
    {
        pEntry = CONTAINING_RECORD(
            pListEntry,
            EPT_BREAKPOINT_ROOT_ENTRY,
            HookedPageListEntry);

        pBreakpoint = &pEntry->Breakpoint;

        //
        // Filter irrelevant process contexts.
        //
        if (pBreakpoint->ProcessId != CurrentProcessId)
        {
            continue;
        }

        //
        // Check for execute breakpoints before read or write breakpoints
        //  because read and write breakpoints have address ranges.
        //
        if (fExecuteViolation)
        {
            if (pBreakpoint->BreakpointType == EptBreakpointTypeExecute &&
                pBreakpoint->GuestPhysicalAddress == GuestPhysicalAddress)
            {
                pRootEntry = pEntry;
                break;
            }

            continue;
        }

        //
        // Filter entries whose breakpoints are out of range.
        //
        if (GuestPhysicalAddress < pBreakpoint->GuestPhysicalAddress ||
            GuestPhysicalAddress >=
                pBreakpoint->GuestPhysicalAddress +
                pBreakpoint->BreakpointSize)
        {
            continue;
        }

        if ((pBreakpoint->BreakpointType == EptBreakpointTypeRead &&
                fReadViolation) ||
            (pBreakpoint->BreakpointType == EptBreakpointTypeWrite &&
                fWriteViolation))
        {
            pRootEntry = pEntry;
            break;
        }
    }

    return pRootEntry;
}


_Use_decl_annotations_
static
VOID
EbmxpLogEptBreakpointHit(
    PEBM_LOG_CONTEXT pLogContext,
    GpRegisters* pGuestRegisters,
    FlagRegister GuestFlags,
    ULONG_PTR GuestIp
)
{
    PLOG_EPT_BREAKPOINT_HIT_ROUTINE pLogRoutine = NULL;

    switch (pLogContext->KernelMapping.Log->Header.LogType)
    {
        case EptBreakpointLogTypeBasic:
            pLogRoutine = EbmxpLogEptBreakpointHitBasic;
            break;

        case EptBreakpointLogTypeGeneralRegisterContext:
            pLogRoutine = EbmxpLogEptBreakpointHitGeneralRegisterContext;
            break;

        case EptBreakpointLogTypeKeyedRegisterContext:
            pLogRoutine = EbmxpLogEptBreakpointHitKeyedRegisterContext;
            break;
 
        default:
            EbmpBugCheckEx(
                (ULONG_PTR)EbmxpLogEptBreakpointHit,
                0,
                (ULONG_PTR)pLogContext->KernelMapping.Log->Header.LogType,
                0);
    }

#pragma warning(suppress : 28121) // Current IRQL level is too high.
    KeAcquireSpinLockAtDpcLevel(&pLogContext->UpdateLock);

    pLogRoutine(pLogContext, pGuestRegisters, GuestFlags, GuestIp);

#pragma warning(suppress : 28121) // Current IRQL level is too high.
    KeReleaseSpinLockFromDpcLevel(&pLogContext->UpdateLock);
}


_Use_decl_annotations_
static
VOID
EbmxpLogEptBreakpointHitBasic(
    PEBM_LOG_CONTEXT pLogContext,
    GpRegisters* pGuestRegisters,
    FlagRegister GuestFlags,
    ULONG_PTR GuestIp
)
{
    PEPT_BREAKPOINT_LOG pLog = NULL;
    ULONG i = 0;
    BOOLEAN fMatched = FALSE;
    PEBLE_BASIC pElement = NULL;

    UNREFERENCED_PARAMETER(pGuestRegisters);
    UNREFERENCED_PARAMETER(GuestFlags);

    pLog = pLogContext->KernelMapping.Log;

    if (pLog->Header.NumberOfElements >= pLog->Header.MaxIndex)
    {
        goto exit;
    }

    //
    // Search for an element with a matching trigger address.
    //
    for (i = 0; i < pLog->Header.NumberOfElements; i++)
    {
        pElement = &pLog->u.Basic.Elements[i];

        if (pElement->TriggerAddress == GuestIp)
        {
            pElement->HitCount++;
            fMatched = TRUE;
            break;
        }
    }

    if (!fMatched)
    {
        NT_ASSERT(i == pLog->Header.NumberOfElements);

        //
        // We did not find a match so insert a new element.
        //
        pElement = &pLog->u.Basic.Elements[i];

        pElement->TriggerAddress = GuestIp;
        pElement->HitCount++;

        pLog->Header.NumberOfElements++;
    }

exit:
    return;
}


_Use_decl_annotations_
static
VOID
EbmxpLogEptBreakpointHitGeneralRegisterContext(
    PEBM_LOG_CONTEXT pLogContext,
    GpRegisters* pGuestRegisters,
    FlagRegister GuestFlags,
    ULONG_PTR GuestIp
)
{
    PEPT_BREAKPOINT_LOG pLog = NULL;
    PEBLE_GENERAL_REGISTER_CONTEXT pElement = NULL;

    pLog = pLogContext->KernelMapping.Log;

    if (pLog->Header.NumberOfElements >= pLog->Header.MaxIndex)
    {
        goto exit;
    }

    pElement =
        &pLog->u.GeneralRegisterContext.Elements[pLog->Header.NumberOfElements];

    pElement->TriggerAddress = GuestIp;
    RtlCopyMemory(
        &pElement->Registers,
        pGuestRegisters,
        sizeof(GENERAL_PURPOSE_REGISTERS));
    pElement->Flags = GuestFlags.all;

    pLog->Header.NumberOfElements++;

exit:
    return;
}


_Use_decl_annotations_
static
VOID
EbmxpLogEptBreakpointHitKeyedRegisterContext(
    PEBM_LOG_CONTEXT pLogContext,
    GpRegisters* pGuestRegisters,
    FlagRegister GuestFlags,
    ULONG_PTR GuestIp
)
{
    PEPT_BREAKPOINT_LOG pLog = NULL;
    ULONG i = 0;
    PEBLE_KEYED_REGISTER_CONTEXT pElement = NULL;
    ULONG_PTR KeyValue = 0;
    BOOLEAN fMatched = FALSE;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    pLog = pLogContext->KernelMapping.Log;

    if (pLog->Header.NumberOfElements >= pLog->Header.MaxIndex)
    {
        goto exit;
    }

    ntstatus = ReadGuestGpRegisterValue(
        pLog->Header.RegisterKey,
        pGuestRegisters,
        GuestIp,
        &KeyValue);
    if (!NT_SUCCESS(ntstatus))
    {
        EbmpBugCheckEx(
            (ULONG_PTR)EbmxpLogEptBreakpointHitKeyedRegisterContext,
            (ULONG_PTR)ReadGuestGpRegisterValue,
            (ULONG_PTR)ntstatus,
            (ULONG_PTR)pLog->Header.RegisterKey);
    }

    //
    // Search for an element with a matching key.
    //
    for (i = 0; i < pLog->Header.NumberOfElements; i++)
    {
        pElement = &pLog->u.KeyedRegisterContext.Elements[i];

        if (pElement->KeyValue == KeyValue)
        {
            pElement->HitCount++;
            fMatched = TRUE;
            break;
        }
    }

    if (!fMatched)
    {
        NT_ASSERT(i == pLog->Header.NumberOfElements);

        //
        // We did not find a match so insert a new element.
        //
        pElement = &pLog->u.KeyedRegisterContext.Elements[i];

        pElement->KeyValue = KeyValue;
        pElement->TriggerAddress = GuestIp;
        pElement->HitCount++;
        RtlCopyMemory(
            &pElement->Registers,
            pGuestRegisters,
            sizeof(GENERAL_PURPOSE_REGISTERS));
        pElement->Flags = GuestFlags.all;

        pLog->Header.NumberOfElements++;
    }

exit:
    return;
}


_Use_decl_annotations_
NTSTATUS
EbmxpSetMonitorTrapFlag(
    BOOLEAN fEnable
)
{
    VmxProcessorBasedControls ProcessorBasedControls = {};
    VmxStatus vmxstatus = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ProcessorBasedControls.all =
        (unsigned int)UtilVmRead(VmcsField::kCpuBasedVmExecControl);

    ProcessorBasedControls.fields.monitor_trap_flag = fEnable;

    vmxstatus = UtilVmWrite(
        VmcsField::kCpuBasedVmExecControl,
        ProcessorBasedControls.all);
    if (VmxStatus::kOk != vmxstatus)
    {
        ntstatus = STATUS_UNSUCCESSFUL;
        DEBUG_BREAK();
    }

    return ntstatus;
}
