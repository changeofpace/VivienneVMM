/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    process_util.cpp

Abstract:

    This module implements the process utility interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "process_util.h"

#include "log.h"
#include "nt.h"


_Use_decl_annotations_
NTSTATUS
PsuGetProcessInformation(
    HANDLE ProcessId,
    PVIVIENNE_PROCESS_INFORMATION pProcessInfo
)
{
    PEPROCESS pProcess = NULL;
    BOOLEAN fProcessReferenced = FALSE;
    PVOID pSectionBase = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Zero output parameters.
    //
    RtlSecureZeroMemory(pProcessInfo, sizeof(*pProcessInfo));

    ntstatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("PsLookupProcessByProcessId failed: 0x%X", ntstatus);
        goto exit;
    }
    //
    fProcessReferenced = TRUE;

    pSectionBase = PsGetProcessSectionBaseAddress(pProcess);
    if (!pSectionBase)
    {
        ERR_PRINT("PsGetProcessSectionBaseAddress failed.");
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    //
    // Set out parameters.
    //
    pProcessInfo->BaseAddress = pSectionBase;

exit:
    if (fProcessReferenced)
    {
        ObDereferenceObject(pProcess);
    }

    return ntstatus;
}
