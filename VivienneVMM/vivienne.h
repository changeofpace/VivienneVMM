/*++

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
_Check_return_
NTSTATUS
VvmmInitialization(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath
);

_Check_return_
NTSTATUS
VvmmTermination(
    _In_ PDRIVER_OBJECT pDriverObject
);
