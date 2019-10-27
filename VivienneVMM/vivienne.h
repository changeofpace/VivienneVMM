/*++

Copyright (c) 2019 changeofpace. All rights reserved.

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
EXTERN_C
DRIVER_INITIALIZE
VivienneVmmDriverEntry;

EXTERN_C
DRIVER_UNLOAD
VivienneVmmDriverUnload;

//=============================================================================
// Public Interface
//=============================================================================
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH
VivienneVmmDispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH
VivienneVmmDispatchClose;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH
VivienneVmmDispatchCleanup;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH
VivienneVmmDispatchDeviceControl;
