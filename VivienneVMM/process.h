/*++

Module Name:
    
    process.h

Abstract:

    This header defines process query functions which can safely be used in VMX
     root mode.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

//=============================================================================
// Vmx Interface
//=============================================================================
_IRQL_requires_(HIGH_LEVEL)
_Check_return_
ULONG_PTR
PsVmxGetCurrentProcessId();