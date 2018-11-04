#include "memory.h"

#include <Psapi.h>

#include <cstdio>


//
// IsVirtualAddressValid
//
// Determine if the PTE for the specified address is valid.
//
_Use_decl_annotations_
BOOL
IsVirtualAddressValid(
    PVOID pAddress,
    PBOOL pValid
)
{
    PSAPI_WORKING_SET_EX_INFORMATION WorkingSetInfo = {};
    BOOL status = TRUE;

    // Zero out parameters.
    *pValid = FALSE;

    //
    // Initialize the target virtual address for the working set query.
    //
    WorkingSetInfo.VirtualAddress = pAddress;

    status = QueryWorkingSetEx(
        GetCurrentProcess(),
        &WorkingSetInfo,
        sizeof(WorkingSetInfo));
    if (!status)
    {
        printf("QueryWorkingSetEx failed: %u\n", GetLastError());
        goto exit;
    }

    // Set out parameters.
    if (WorkingSetInfo.VirtualAttributes.Valid)
    {
        *pValid = TRUE;
    }

exit:
    return status;
}
