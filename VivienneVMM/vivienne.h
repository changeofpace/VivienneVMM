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
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C
NTSTATUS
VivienneDriverEntry(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath
);

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
EXTERN_C
VOID
VivienneDriverUnload(
    _In_ PDRIVER_OBJECT pDriverObject
);

//=============================================================================
// Public Interface
//=============================================================================
_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CREATE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
EXTERN_C
NTSTATUS
VivienneDispatchCreate(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _Inout_ PIRP pIrp
);

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CLOSE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
EXTERN_C
NTSTATUS
VivienneDispatchClose(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _Inout_ PIRP pIrp
);

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
EXTERN_C
NTSTATUS
VivienneDispatchDeviceControl(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _Inout_ PIRP pIrp
);
