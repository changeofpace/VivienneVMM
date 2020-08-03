;==============================================================================
; Types
;==============================================================================
;
; NOTE This struct must match 'GENERAL_PURPOSE_REGISTERS' defined in
; arch_x64.h.
;
GENERAL_PURPOSE_REGISTERS struct
    gp_r15      qword       0
    gp_r14      qword       0
    gp_r13      qword       0
    gp_r12      qword       0
    gp_r11      qword       0
    gp_r10      qword       0
    gp_r9       qword       0
    gp_r8       qword       0
    gp_rdi      qword       0
    gp_rsi      qword       0
    gp_rbp      qword       0
    gp_rsp      qword       0
    gp_rbx      qword       0
    gp_rdx      qword       0
    gp_rcx      qword       0
    gp_rax      qword       0
GENERAL_PURPOSE_REGISTERS ends


;==============================================================================
; Macros
;==============================================================================
LOAD_GENERAL_PURPOSE_REGISTERS macro
    mov     r15, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r15
    mov     r14, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r14
    mov     r13, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r13
    mov     r12, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r12
    mov     r11, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r11
    mov     r10, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r10
    mov     r9,  (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r9
    mov     r8,  (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_r8
    mov     rdi, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rdi
    mov     rsi, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rsi
    mov     rbp, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rbp
    ;mov     rsp, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rsp
    mov     rbx, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rbx
    mov     rdx, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rdx
    mov     rcx, (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rcx
    push    (GENERAL_PURPOSE_REGISTERS ptr [rax]).gp_rax
    pop     rax
endm


;==============================================================================
; Globals
;==============================================================================
.data

public Test_Ebm_ReadByte
public Test_Ebm_ReadWord
public Test_Ebm_ReadDword
public Test_Ebm_ReadQword
public Test_Ebm_WriteByte
public Test_Ebm_WriteWord
public Test_Ebm_WriteDword
public Test_Ebm_WriteQword
public Test_Ebm_ExecuteBasic
public Test_Ebm_VmCall
public Test_Ebm_SetTrapFlag

public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location
public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_1
public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_2
public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_3
public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_LastAddress
public g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count

public Test_Ebm_SetTrapFlag_ReturnExceptionAddress

public Test_Ebm_SetTrapFlag_StaticExceptionAddress

public g_Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint_Location
public Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint

g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count         qword   0

public Test_Ebm_Stress_DebugExceptions_Asm
public g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute
public g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read
public g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return
public g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read
public g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1
public g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2

g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read         word        0
g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1               dword       0
g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2               dword       0


;==============================================================================
; Assembly Code Interface
;==============================================================================
_ASM_C$1 segment align(4096) 'CODE'

;
; BYTE
; NTAPI
; Test_Ebm_ReadByte(
;    _In_ PBYTE pByte
; );
;
Test_Ebm_ReadByte:
    mov     al, byte ptr [rcx]
    ret


;
; WORD
; NTAPI
; Test_Ebm_ReadWord(
;    _In_ PWORD pWord
; );
;
Test_Ebm_ReadWord:
    mov     ax, word ptr [rcx]
    ret


;
; DWORD
; NTAPI
; Test_Ebm_ReadDword(
;    _In_ PDWORD pDword
; );
;
Test_Ebm_ReadDword:
    mov     eax, dword ptr [rcx]
    ret


;
; NTAPI
; Test_Ebm_ReadQword(
;    _In_ PDWORD64 pQword
; );
;
Test_Ebm_ReadQword:
    mov     rax, qword ptr [rcx]
    ret


;
; VOID
; NTAPI
; Test_Ebm_WriteByte(
;     PBYTE pByte,
;     BYTE Value
; );
;
Test_Ebm_WriteByte:
    mov     byte ptr [rcx], dl
    ret


;
; VOID
; NTAPI
; Test_Ebm_WriteWord(
;     PWORD pWord,
;     WORD Value
; );
;
Test_Ebm_WriteWord:
    mov     word ptr [rcx], dx
    ret


;
; VOID
; NTAPI
; Test_Ebm_WriteDword(
;     PDWORD pDword,
;     DWORD Value
; );
;
Test_Ebm_WriteDword:
    mov     dword ptr [rcx], edx
    ret


;
; VOID
; NTAPI
; Test_Ebm_WriteQword(
;     PDWORD64 pQword,
;     DWORD64 Value
; );
;
Test_Ebm_WriteQword:
    mov     qword ptr [rcx], rdx
    ret


;
; VOID
; NTAPI
; Test_Ebm_ExecuteBasic();
;
Test_Ebm_ExecuteBasic:
    ret


;
; ULONG_PTR
; NTAPI
; Test_Ebm_VmCall(
;     _In_ ULONG_PTR HypercallNumber,
;     _In_ ULONG_PTR Context
; );
;
Test_Ebm_VmCall:
    vmcall
    ret


;
; VOID
; NTAPI
; Test_Ebm_SetTrapFlag();
;
Test_Ebm_SetTrapFlag:
    pushfq
    or      qword ptr [rsp], 100h
    popfq
    ret


;
; VOID
; NTAPI
; Test_Ebm_SetTrapFlag_ReturnExceptionAddress(
;     _Out_ PVOID* ppExceptionAddress
; );
;
; On return, a single-step exception is generated and '*ppExceptionAddress' is
;   set to the exception address.
;
Test_Ebm_SetTrapFlag_ReturnExceptionAddress:
    ;
    ; Store the return address in the output parameter.
    ;
    mov     rax, qword ptr [rsp]
    mov     [rcx], rax

    ;
    ; Push the current EFLAGS value to the stack, set the trap flag, pop the
    ;   modified EFLAGS value into the EFLAGS register. The trap flag will take
    ;   effect after the return instruction is executed.
    ;
    pushfq
    or      qword ptr [rsp], 100h
    popfq
    ret


;
; VOID
; NTAPI
; Test_Ebm_SetTrapFlag_StaticExceptionAddress_Helper();
;
; Recreation of 'Test_Ebm_SetTrapFlag' with labels for ept breakpoints.
;
Test_Ebm_SetTrapFlag_StaticExceptionAddress_Helper:
    pushfq
    or      qword ptr [rsp], 100h
    popfq
g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_1:
    ret


;
; VOID
; NTAPI
; Test_Ebm_SetTrapFlag_StaticExceptionAddress();
;
; Trigger a single-step exception where the exception address is the address
;   of the 'g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location' variable.
;
Test_Ebm_SetTrapFlag_StaticExceptionAddress:
    call Test_Ebm_SetTrapFlag_StaticExceptionAddress_Helper

g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Location:
g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_2:
    inc g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_Count
g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_EptBreakpointTarget_3:
g_Test_Ebm_SetTrapFlag_StaticExceptionAddress_LastAddress:
    ret


;
; VOID
; NTAPI
; Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint(
;     _In_ PGENERAL_PURPOSE_REGISTERS pContext
; );
;
Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint:
    ;
    ; Save non-volatile registers.
    ;
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ;
    ; Load the expected register context.
    ;
    mov     rax, rcx
    LOAD_GENERAL_PURPOSE_REGISTERS

    ;
    ; Trigger the ept breakpoint.
    ;
g_Test_Ebm_SetRegisterContextTriggerExecutionBreakpoint_Location:
    nop

    ;
    ; Restore non-volatile registers.
    ;
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    rsi
    pop    rdi
    pop    rbp
    pop    rbx

    ret


;
; VOID
; NTAPI
; Test_Ebm_Stress_DebugExceptions_Asm(
;     _In_ BOOL fSingleStep
; );
;
Test_Ebm_Stress_DebugExceptions_Asm:
    cmp         ecx, 0
    jz          g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute

    ;
    ; Single-step through this routine. 'Test_Ebm_Stress_DebugExceptions_VEH'
    ; will set the trap flag until we get to
    ; 'g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return'.
    ;
    call        Test_Ebm_SetTrapFlag

g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Execute:
    inc         g_Test_Ebm_Stress_DebugExceptions_Asm_Count_1

    ;
    ; NOTE Data hardware breakpoints are trap exceptions so the exception
    ; address is the address of the instruction after the access.
    ;
    mov         ax, g_Test_Ebm_Stress_DebugExceptions_Asm_Variable_Read
g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Read:

    inc         g_Test_Ebm_Stress_DebugExceptions_Asm_Count_2

g_Test_Ebm_Stress_DebugExceptions_Asm_Location_Return:
    ret


_ASM_C$1 ends


end
