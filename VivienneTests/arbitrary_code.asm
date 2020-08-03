;
; The implementations do not use the PROC directive so that labels contained by
;  functions can be properly exported.
;

;==============================================================================
; Constants
;==============================================================================
.CONST

;
; This value must be synchronized with test_cecm_fpu_state!SENTINEL_FLOAT_VALUE.
;
g_CecmFpuStateSentinel             DWORD   77777.75


;==============================================================================
; Globals
;==============================================================================
.DATA

;
; AcCaptureRegister
;
PUBLIC AcCaptureRegister
PUBLIC g_AcCecrCaptureAddress

;
; AcCaptureMemoryDouble
;
PUBLIC AcCaptureMemoryDouble
PUBLIC g_AcCecrDoubleCaptureAddress

;
; AcCaptureMemoryFpuState
;
PUBLIC AcCaptureMemoryFpuState
PUBLIC g_AcCecmFpuStateCaptureAddress1
PUBLIC g_AcCecmFpuStateCaptureAddress2
PUBLIC g_AcCecmFpuStateCaptureAddress3

;
; AcExerciseUnownedHardwareBreakpoints
;
PUBLIC AcExerciseUnownedHardwareBreakpoints
PUBLIC g_AcUnownedHwBpAccessAddress1
PUBLIC g_AcUnownedHwBpAccessAddress2
PUBLIC g_AcUnownedHwBpAccessTarget
PUBLIC g_AcUnownedHwBpWriteAddress1
PUBLIC g_AcUnownedHwBpWriteAddress2
PUBLIC g_AcUnownedHwBpWriteAddress3
PUBLIC g_AcUnownedHwBpWriteTarget

g_AcUnownedHwBpAccessTarget     QWORD   0
g_AcUnownedHwBpWriteTarget      QWORD   0


;==============================================================================
; Client Interface
;==============================================================================
.CODE

;
; VOID
; AcCaptureRegister(
;     _In_ ULONG_PTR Value
; );
;
AcCaptureRegister:
    push    r12
    mov     r12, rcx
g_AcCecrCaptureAddress:     ; Read the contents of R12 after it has been
    xchg    eax, eax        ;   written to.
    pop     r12
    ret


;
; DOUBLE
; AcCaptureMemoryDouble(
;     _In_count_(cValues) DOUBLE pValues[],
;     _In_ SIZE_T cValues,
;     _In_ SIZE_T Index
; );
;
AcCaptureMemoryDouble:
    cmp     r8d, edx
    jge     AcCaptureMemoryDoubleFail
    mov     eax, r8d

g_AcCecrDoubleCaptureAddress:
    movsd   xmm0, qword ptr [rcx + rax * 8] ; test_cecm!ADDRESS_EXPRESSION
    ret

AcCaptureMemoryDoubleFail:
    xorpd   xmm0, xmm0
    ret


;
; FLOAT
; AcCaptureMemoryFpuState(
;     _In_count_(cValues) FLOAT pValues[],
;     _In_ SIZE_T cValues,
;     _In_ SIZE_T Index
; );
;
AcCaptureMemoryFpuState:
    cmp     r8d, edx
    jge     AcCaptureMemoryFpuStateFail
    mov     eax, r8d

;
; The following sequence of instructions are used to verify that our
;  breakpoints are not corrupting xmm registers during VM transitions. The
;  return value should be checked by the caller to verify that it equals the
;  sentinel float value.
;
g_AcCecmFpuStateCaptureAddress1:
    movss   xmm1, [g_CecmFpuStateSentinel]
g_AcCecmFpuStateCaptureAddress2:
    movss   xmm2, dword ptr [rcx + rax * 4] ; test_cecm_fpu_state!CECM_TARGET_TEXT
g_AcCecmFpuStateCaptureAddress3:
    movss   xmm0, xmm1
    ret

AcCaptureMemoryFpuStateFail:
    xorps   xmm0, xmm0
    ret


;
; VOID
; AcExerciseUnownedHardwareBreakpoints(
;     _In_ ULONG_PTR Value
; );
;
AcExerciseUnownedHardwareBreakpoints:
    nop
    mov     rax, g_AcUnownedHwBpAccessTarget ; Trigger the access breakpoint.
g_AcUnownedHwBpAccessAddress1:               ; Access bp exception address 1.
    add     rax, rcx
    mov     rax, g_AcUnownedHwBpAccessTarget ; Trigger the access breakpoint.
g_AcUnownedHwBpAccessAddress2:               ; Access bp exception address 2.
    add     rax, rcx
    mov     g_AcUnownedHwBpWriteTarget, rax  ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress1:                ; Write bp exception address 1.
    add     rax, rcx
    mov     g_AcUnownedHwBpWriteTarget, rax  ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress2:                ; Write bp exception address 2.
    add     rax, rcx
    mov     g_AcUnownedHwBpWriteTarget, rax  ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress3:                ; Write bp exception address 3.
    nop
    ret

END
