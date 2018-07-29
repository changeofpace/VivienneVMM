/*++

Module Name:
    
    debug_register_facade.h

Abstract:

    This header defines the debug register facade interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "HyperPlatform\ia32_type.h"

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
NTSTATUS
FcdInitialization();

_Check_return_
NTSTATUS
FcdTermination();

_IRQL_requires_(HIGH_LEVEL)
VOID
FcdVmxInitialization();

_IRQL_requires_(HIGH_LEVEL)
VOID
FcdVmxTermination();

//=============================================================================
// Vmx Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
_Check_return_
NTSTATUS
FcdVmxProcessMovDrEvent(
    _In_ MovDrQualification ExitQualification,
    _Inout_ PULONG_PTR pRegisterUsed
);