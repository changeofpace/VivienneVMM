#include "affinity.h"

#include "log.h"

#include "memory_util.h"


//
// From MSDN: Helper function to count set bits in the processor mask.
//
_Check_return_
static
DWORD
AfnpCountSetBits(
    _In_ ULONG_PTR BitMask
)
{
    DWORD LSHIFT = sizeof(ULONG_PTR) * 8 - 1;
    DWORD bitSetCount = 0;
    ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;
    DWORD i = 0;

    for (i = 0; i <= LSHIFT; ++i)
    {
        bitSetCount += ((BitMask & bitTest) ? 1 : 0);
        bitTest /= 2;
    }

    return bitSetCount;
}


_Use_decl_annotations_
DWORD
AfnGetLogicalProcessorCount()
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION pProcessorInfo = NULL;
    SIZE_T cbProcessorInfo = 0;
    DWORD cbReturnLength = 0;
    SIZE_T i = 0;
    DWORD cProcessors = 0;

    //
    // Initial allocation size.
    //
    cbProcessorInfo = sizeof(*pProcessorInfo);

    for (;;)
    {
        pProcessorInfo =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)MemAllocateHeap(
                cbProcessorInfo);
        if (!pProcessorInfo)
        {
            ERR_PRINT("MemAllocateHeap failed.");
            goto exit;
        }

        if (GetLogicalProcessorInformation(pProcessorInfo, &cbReturnLength))
        {
            break;
        }
        else if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
        {
            ERR_PRINT("GetLogicalProcessorInformation failed: %u",
                GetLastError());
            goto exit;
        }

        //
        // Update the allocation size to the last required size.
        //
        cbProcessorInfo = cbReturnLength;

        //
        // Release the insufficient buffer.
        //
        if (!MemFreeHeap(pProcessorInfo))
        {
            ERR_PRINT("MemFreeHeap failed: %u", GetLastError());
            goto exit;
        }
    }

    for (i = 0; i < cbReturnLength / sizeof(*pProcessorInfo); ++i)
    {
        if (RelationProcessorCore == pProcessorInfo[i].Relationship)
        {
            cProcessors += AfnpCountSetBits(pProcessorInfo[i].ProcessorMask);
        }
    }

exit:
    if (pProcessorInfo)
    {
        if (!MemFreeHeap(pProcessorInfo))
        {
            ERR_PRINT("HeapFree failed: %u", GetLastError());
            goto exit;
        }
    }

    return cProcessors;
}


_Use_decl_annotations_
BOOL
AfnSetProcessAffinityAllProcessors(
    HANDLE hProcess,
    DWORD cProcessors
)
{
    DWORD_PTR ProcessAffinityMask = 0;
    DWORD i = 0;
    BOOL status = TRUE;

    for (i = 0; i < cProcessors; ++i)
    {
        ProcessAffinityMask |= (1ull << i);
    }

    status = SetProcessAffinityMask(hProcess, ProcessAffinityMask);
    if (!status)
    {
        ERR_PRINT("SetProcessAffinityMask failed: %u", GetLastError());
        goto exit;
    }

exit:
    return status;
}
