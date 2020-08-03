#pragma once

#include <Windows.h>

#include "../common/arch_x64.h"

//=============================================================================
// Globals
//=============================================================================
EXTERN_C ULONG_PTR g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location;
EXTERN_C ULONG_PTR g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_1;
EXTERN_C ULONG_PTR g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_2;
EXTERN_C ULONG_PTR g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_3;
EXTERN_C ULONG_PTR g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_LastAddress;
EXTERN_C SIZE_T g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count;

EXTERN_C ULONG_PTR g_Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint_Location;

EXTERN_C ULONG_PTR g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute;
EXTERN_C ULONG_PTR g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read;
EXTERN_C ULONG_PTR g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return;
EXTERN_C WORD g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read;
EXTERN_C ULONG g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1;
EXTERN_C ULONG g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2;


//=============================================================================
// Test Interface
//=============================================================================
VOID
TestEptBreakpointManager();

//=============================================================================
// Assembly Code Interface
//=============================================================================
EXTERN_C
BYTE
NTAPI
Test_Ebm_ReadByte(
    _In_ PBYTE pByte
);

EXTERN_C
WORD
NTAPI
Test_Ebm_ReadWord(
    _In_ PWORD pWord
);

EXTERN_C
DWORD
NTAPI
Test_Ebm_ReadDword(
    _In_ PDWORD pDword
);

EXTERN_C
DWORD64
NTAPI
Test_Ebm_ReadQword(
    _In_ PDWORD64 pQword
);

EXTERN_C
VOID
NTAPI
Test_Ebm_WriteByte(
    _Out_ PBYTE pByte,
    _In_ BYTE Value
);

EXTERN_C
VOID
NTAPI
Test_Ebm_WriteWord(
    _Out_ PWORD pWord,
    _In_ WORD Value
);

EXTERN_C
VOID
NTAPI
Test_Ebm_WriteDword(
    _Out_ PDWORD pDword,
    _In_ DWORD Value
);

EXTERN_C
VOID
NTAPI
Test_Ebm_WriteQword(
    _Out_ PDWORD64 pQword,
    _In_ DWORD64 Value
);

EXTERN_C
VOID
NTAPI
Test_Ebm_ExecuteBasic();

EXTERN_C
VOID
NTAPI
Test_Ebm_VmCall(
    _In_ ULONG_PTR HypercallNumber,
    _In_ ULONG_PTR Context
);

EXTERN_C
VOID
NTAPI
Test_Ebm_SetTrapFlag();

EXTERN_C
VOID
NTAPI
Test_Ebm_SetTrapFlag_ReturnExceptionAddress(
    _Out_ PVOID* ppExceptionAddress
);

EXTERN_C
VOID
NTAPI
Test_Ebm_SetTrapFlag_StaticExceptionAddress();

EXTERN_C
VOID
NTAPI
Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint(
    _In_ PGENERAL_PURPOSE_REGISTERS pContext
);

EXTERN_C
VOID
NTAPI
Test_Ebm_Stress_DebugExceptions_Asm(
    _In_ BOOL fSingleStep
);
