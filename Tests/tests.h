#pragma once

#include <Windows.h>

#include "..\VivienneVMM\config.h"

//=============================================================================
// Test Interface
//=============================================================================
VOID
TestSetClearHardwareBreakpoint();

VOID
TestDuplicateHardwareBreakpoints();

VOID
TestHardwareBreakpointStress();

VOID
TestCaptureUniqueRegisterValues();

VOID
TestCaptureUniqueRegisterValuesEdgeCases();

VOID
TestHardwareBreakpointRanges();

#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
VOID
TestDebugRegisterFacade();

VOID
TestDebugRegisterFacadeStress();
#else
VOID
TestProcessUnownedHardwareBreakpoint();
#endif

VOID
TestAntiDebugSingleStep();