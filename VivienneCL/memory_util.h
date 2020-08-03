/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

_Check_return_
_Ret_maybenull_
_Post_writable_byte_size_(cbSize)
DECLSPEC_ALLOCATOR
PVOID
MemAllocateHeap(
    _In_ SIZE_T cbSize
);

_Success_(return != FALSE)
_Check_return_
BOOL
MemFreeHeap(
    __drv_freesMem(Mem) PVOID pBuffer
);
