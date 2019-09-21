#include "process.h"

#include <cstdio>

#include "..\VivienneCL\ntdll.h"


//=============================================================================
// Client Interface
//=============================================================================

//
// PsLookupProcessIdByName
//
// Returns a list of process ids for all active processes whose name matches
//  'pszProcessName'.
//
// NOTE Case-insensitive comparison against a process image file name.
//
_Use_decl_annotations_
BOOL
PsLookupProcessIdByName(
    PCSTR pszProcessName,
    std::vector<ULONG_PTR>& ProcessIds
)
{
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInfo = NULL;
    ULONG cbSystemProcessInfo = NULL;
    ULONG cbReturnLength = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    ANSI_STRING asProcessName = {};
    UNICODE_STRING usProcessName = {};
    BOOLEAN fAllocatedString = FALSE;
    BOOL status = TRUE;

    // Zero out parameters.
    ProcessIds.clear();

    // Initial allocation size.
    cbSystemProcessInfo = sizeof(*pSystemProcessInfo);

    for (;;)
    {
        pSystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            cbSystemProcessInfo);
        if (!pSystemProcessInfo)
        {
            status = FALSE;
            goto exit;
        }

        ntstatus = NtQuerySystemInformation(
            SystemProcessInformation,
            pSystemProcessInfo,
            cbSystemProcessInfo,
            &cbReturnLength);
        if (NT_SUCCESS(ntstatus))
        {
            break;
        }
        else if (STATUS_INFO_LENGTH_MISMATCH != ntstatus)
        {
            printf("NtQuerySystemInformation failed: 0x%X\n", ntstatus);
            status = FALSE;
            goto exit;
        }

        // Update the allocation size to the last required size.
        cbSystemProcessInfo = cbReturnLength;

        // Release the inadequate buffer.
        status = HeapFree(GetProcessHeap(), 0, pSystemProcessInfo);
        if (!status)
        {
            printf("HeapFree failed: %u\n", GetLastError());
            goto exit;
        }

        pSystemProcessInfo = NULL;
    }

    // Initialize a unicode string from the process name parameter.
    RtlInitAnsiString(&asProcessName, pszProcessName);

    ntstatus = RtlAnsiStringToUnicodeString(
        &usProcessName,
        &asProcessName,
        TRUE);
    if (!NT_SUCCESS(ntstatus))
    {
        printf("RtlAnsiStringToUnicodeString failed: 0x%X\n", ntstatus);
        status = FALSE;
        goto exit;
    }

    fAllocatedString = TRUE;

    // Search the process list for matching process names.
    for (PSYSTEM_PROCESS_INFORMATION pEntry = pSystemProcessInfo;;
        pEntry = OFFSET_POINTER(
            pEntry,
            pEntry->NextEntryOffset,
            SYSTEM_PROCESS_INFORMATION))
    {
        if (RtlEqualUnicodeString(&usProcessName, &pEntry->ImageName, TRUE))
        {
            ProcessIds.emplace_back((ULONG_PTR)pEntry->UniqueProcessId);
        }

        if (!pEntry->NextEntryOffset)
        {
            break;
        }
    }

exit:
    if (fAllocatedString)
    {
        RtlFreeUnicodeString(&usProcessName);
    }

    if (pSystemProcessInfo)
    {
        if (!HeapFree(GetProcessHeap(), 0, pSystemProcessInfo))
        {
            printf("HeapFree failed: %u\n", GetLastError());
        }
    }

    return status;
}
