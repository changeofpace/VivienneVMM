/*++

Module Name:

    process.cpp

Abstract:

    This module implements process query functions which can safely be used in
     VMX root mode.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#include "process.h"


//=============================================================================
// Vmx Interface
//=============================================================================

//
// PsVmxGetCurrentProcessId
//
// See: tandasat's comment in HyperPlatform!LogpMakePrefix.
//
_Use_decl_annotations_
ULONG_PTR
PsVmxGetCurrentProcessId()
{
#pragma warning(suppress : 28121) // IRQL level is too high.
    return (ULONG_PTR)PsGetProcessId(PsGetCurrentProcess());
}