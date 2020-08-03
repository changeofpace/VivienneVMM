/*++

Copyright (c) 2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    system_util.h

Abstract:

    This header implements system utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "system_util.h"

#include "debug.h"
#include "log.h"


//
// See: HyperPlatform/util!UtilForEachProcessor
//
_IRQL_requires_max_(APC_LEVEL)
_Check_return_
NTSTATUS
SyspExecuteProcessorCallback(
    _In_ ULONG ProcessorIndex,
    _In_ PSYSTEM_PROCESSOR_CALLBACK_ROUTINE pCallbackRoutine,
    _In_ PVOID pCallbackContext
)
{
    PROCESSOR_NUMBER ProcessorNumber = {};
    GROUP_AFFINITY Affinity = {};
    GROUP_AFFINITY PreviousAffinity = {};
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ntstatus = KeGetProcessorNumberFromIndex(ProcessorIndex, &ProcessorNumber);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("KeGetProcessorNumberFromIndex failed: 0x%X", ntstatus);
        goto exit;
    }

    Affinity.Group = ProcessorNumber.Group;
    Affinity.Mask = 1ull << ProcessorNumber.Number;

    KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

    ntstatus = pCallbackRoutine(pCallbackContext);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("Processor callback failed: 0x%X", ntstatus);
    }

    KeRevertToUserGroupAffinityThread(&PreviousAffinity);

exit:
    return ntstatus;
}


_Use_decl_annotations_
NTSTATUS
SysExecuteProcessorCallback(
    PSYSTEM_PROCESSOR_CALLBACK_ROUTINE pCallbackRoutine,
    PVOID pCallbackContext,
    PSYSTEM_PROCESSOR_CALLBACK_ROUTINE pUnwindRoutine,
    PVOID pUnwindContext
)
{
    ULONG nProcessors = 0;
    ULONG i = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;

    nProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (i = 0; i < nProcessors; i++)
    {
        ntstatus = SyspExecuteProcessorCallback(
            i,
            pCallbackRoutine,
            pCallbackContext);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT("SyspExecuteProcessorCallback failed: 0x%X", ntstatus);
            goto exit;
        }
    }

exit:
    if (!NT_SUCCESS(ntstatus))
    {
        if (pUnwindRoutine)
        {
            NT_ASSERT(i < nProcessors);

            //
            // This loop assumes that the failing callback successfully unwound
            //  itself.
            //
            while (i--)
            {
                ERR_PRINT("Executing unwind routine: %u", i);

                VERIFY_NTSTATUS(
                    SyspExecuteProcessorCallback(
                        i,
                        pUnwindRoutine,
                        pUnwindContext));
            }
        }
    }

    return ntstatus;
}
