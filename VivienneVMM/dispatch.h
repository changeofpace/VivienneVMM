/*++

Module Name:
    
    dispatch.h

Abstract:

    This header defines IRP_MJ handlers.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

//=============================================================================
// Dispatch Interface
//=============================================================================
_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH DispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DispatchClose;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH DispatchCleanup;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DispatchDeviceControl;