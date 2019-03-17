#pragma once

#include <Windows.h>

#include "..\VivienneVMM\config.h"

//
// TODO Add a test which executes an 'int 1' instruction.
//

//=============================================================================
// Parser
//=============================================================================
VOID
TestTokenParser();

//=============================================================================
// BPM
//=============================================================================
VOID
TestReadDebugRegister();

VOID
TestSetClearHardwareBreakpoint();

VOID
TestHardwareBreakpointStress();

VOID
TestHardwareBreakpointRanges();

VOID
TestDuplicateHardwareBreakpoints();

//=============================================================================
// CECR
//=============================================================================
VOID
TestCaptureRegisterValues();

VOID
TestCaptureRegisterValuesEdgeCases();

//=============================================================================
// CECM
//=============================================================================
VOID
TestCaptureMemoryValues();

VOID
TestCaptureMemoryValuesFpuState();

VOID
TestAntiDebugCecmTrapPage();

VOID
TestAntiDebugCecmSpanningPage();

#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
//=============================================================================
// FCD
//=============================================================================
VOID
TestDebugRegisterFacade();

VOID
TestDebugRegisterFacadeStress();
#else
VOID
TestProcessUnownedHardwareBreakpoint();
#endif

//=============================================================================
// General Anti-Debug
//=============================================================================
VOID
TestAntiDebugSingleStep();
