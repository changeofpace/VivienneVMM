/*++

Module Name:
    
    register_util.h

Abstract:

    This header defines register utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include "HyperPlatform\ia32_type.h"

//=============================================================================
// Client Interface
//=============================================================================
_Check_return_
NTSTATUS
ReadGuestRegisterValue(
    _In_ ULONG Register,
    _In_ GpRegisters* pGuestRegisters,
    _In_ ULONG_PTR GuestIp,
    _Out_ PULONG_PTR pValue
);