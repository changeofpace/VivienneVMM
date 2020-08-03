#pragma once

#include <Windows.h>

#include "..\common\config.h"

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
#include "test_ept_breakpoint_manager.h"
#endif

//
// TODO Add a test which executes an 'int 1' instruction.
//

//=============================================================================
// Parser
//=============================================================================
VOID
TestTokenParser();

//=============================================================================
// General Anti-Debug
//=============================================================================
VOID
TestAntiDebugSingleStep();


#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
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

#if defined(CFG_HBM_ENABLE_DEBUG_REGISTER_FACADE)
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
#endif
