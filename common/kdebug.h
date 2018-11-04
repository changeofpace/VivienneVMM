/*++

Module Name:
    
    kdebug.h

Abstract:

    This header defines debugging utilities.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include <fltKernel.h>

#include <intrin.h>

#ifdef DBG
#define DEBUGBREAK              \
if (!KD_DEBUGGER_NOT_PRESENT)   \
{                               \
    __debugbreak();             \
}
#else
#define DEBUGBREAK ((void)0)
#endif
