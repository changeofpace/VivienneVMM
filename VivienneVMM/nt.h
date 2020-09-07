#pragma once

#include <ntddk.h>

#define SEC_NO_CHANGE      0x400000

#define IS_ALIGNED(_pointer, _alignment) \
    ((((ULONG_PTR) (_pointer)) & ((_alignment) - 1)) == 0)

#pragma warning(push)
#pragma warning(disable : 4201) // Nonstandard extension: nameless struct/union
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
#pragma warning(pop)

FORCEINLINE
LOGICAL
NTAPI
MI_RESERVED_BITS_CANONICAL(
    _In_ PVOID VirtualAddress
)
{
    return ((ULONG64)(((LONG64)VirtualAddress >> 48) + 1) <= 1);
}

//
// NOTE The type of the 'Process' parameter is changed from PRKPROCESS to fix
//  redefinition issues from the fltKernel.h -> ntddk.h change.
//
_IRQL_requires_max_(APC_LEVEL)
EXTERN_C
VOID
NTAPI
KeStackAttachProcess (
    //_Inout_ PRKPROCESS Process,
    _Inout_ PEPROCESS Process,
    _Out_ PRKAPC_STATE ApcState
);

_IRQL_requires_max_(APC_LEVEL)
EXTERN_C
VOID
NTAPI
KeUnstackDetachProcess (
    _In_ PRKAPC_STATE ApcState
);

EXTERN_C
NTSTATUS
NTAPI
MmCreateSection(
    _Outptr_ PVOID* SectionObject,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PLARGE_INTEGER InputMaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _In_opt_ PFILE_OBJECT FileObject
);

EXTERN_C
NTSTATUS
NTAPI
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
);

EXTERN_C
VOID
NTAPI
ObDeleteCapturedInsertInfo(
    _In_ PVOID Object
);

EXTERN_C
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
    _In_ PEPROCESS Process
);

EXTERN_C
VOID
NTAPI
PsReleaseProcessExitSynchronization(
    _In_ PEPROCESS Process
);

EXTERN_C
PVOID
NTAPI
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS Process
);

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
EXTERN_C
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
);

EXTERN_C POBJECT_TYPE* MmSectionObjectType;
