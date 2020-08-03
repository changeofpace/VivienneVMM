/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "memory_util.h"


_Use_decl_annotations_
PVOID
MemAllocateHeap(
    SIZE_T cbSize
)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize);
}


_Use_decl_annotations_
BOOL
MemFreeHeap(
    PVOID pBuffer
)
{
    return HeapFree(GetProcessHeap(), 0, pBuffer);
}
