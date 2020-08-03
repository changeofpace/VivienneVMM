/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "debug.h"

#include "log.h"
#include "ntdll.h"


_Use_decl_annotations_
BOOL
IsKernelDebuggerAttached(
    PBOOL pfDebuggerAttached
)
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemKernelDebuggerInfo = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    //
    // Zero output parameters.
    //
    *pfDebuggerAttached = FALSE;

    ntstatus = NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        &SystemKernelDebuggerInfo,
        sizeof(SystemKernelDebuggerInfo),
        NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("NtQuerySystemInformation failed: 0x%X", ntstatus);
        status = FALSE;
        goto exit;
    }

    //
    // Set output parameters.
    //
    if (SystemKernelDebuggerInfo.KernelDebuggerEnabled &&
        !SystemKernelDebuggerInfo.KernelDebuggerNotPresent)
    {
        *pfDebuggerAttached = TRUE;
    }

exit:
    return status;
}
