/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    vivienne.h

Abstract:

    This header defines the VivienneVMM interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

//=============================================================================
// Meta Interface
//=============================================================================
DRIVER_INITIALIZE
VivienneVmmDriverEntry;

DRIVER_UNLOAD
VivienneVmmDriverUnload;
