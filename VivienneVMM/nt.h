#pragma once

#include <fltKernel.h>

#define SEC_NO_CHANGE      0x400000

FORCEINLINE
LOGICAL
MI_RESERVED_BITS_CANONICAL(
    _In_ PVOID VirtualAddress
)
{
    return ((ULONG64)(((LONG64)VirtualAddress >> 48) + 1) <= 1);
}

EXTERN_C
NTSTATUS
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
VOID
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
