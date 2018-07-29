;
; The implementations do not use the PROC directive so that labels contained by
;  functions can be properly exported.
;

;==============================================================================
; Globals
;==============================================================================
PUBLIC g_AcCaptureTargetR12CaptureAddress
PUBLIC g_AcUnownedHwBpAccessAddress1
PUBLIC g_AcUnownedHwBpAccessAddress2
PUBLIC g_UnownedHwBpAccessTarget
PUBLIC g_AcUnownedHwBpWriteAddress1
PUBLIC g_AcUnownedHwBpWriteAddress2
PUBLIC g_AcUnownedHwBpWriteAddress3
PUBLIC g_UnownedHwBpWriteTarget
PUBLIC AcCaptureTargetR12
PUBLIC AcExerciseUnownedHardwareBreakpoints

.DATA

g_UnownedHwBpAccessTarget   QWORD   0
g_UnownedHwBpWriteTarget    QWORD   0

;==============================================================================
; Client Interface
;==============================================================================
.CODE

;
; VOID
; AcCaptureTargetR12(
;     _In_ ULONG_PTR Value
; );
;
AcCaptureTargetR12:
    push    r12
    mov     r12, rcx
g_AcCaptureTargetR12CaptureAddress:         ; Read the contents of R12 after
    xchg    eax, eax                        ;  it has been written to.
    pop     r12
    ret


;
; VOID
; AcExerciseUnownedHardwareBreakpoints(
;     _In_ ULONG_PTR Value
; );
;
AcExerciseUnownedHardwareBreakpoints:
    nop
    mov     rax, g_UnownedHwBpAccessTarget  ; Trigger the access breakpoint.
g_AcUnownedHwBpAccessAddress1:              ; Access bp exception address 1.
    add     rax, rcx
    mov     rax, g_UnownedHwBpAccessTarget  ; Trigger the access breakpoint.
g_AcUnownedHwBpAccessAddress2:              ; Access bp exception address 2.
    add     rax, rcx
    mov     g_UnownedHwBpWriteTarget, rax   ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress1:               ; Write bp exception address 1.
    add     rax, rcx
    mov     g_UnownedHwBpWriteTarget, rax   ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress2:               ; Write bp exception address 2.
    add     rax, rcx
    mov     g_UnownedHwBpWriteTarget, rax   ; Trigger the write breakpoint.
g_AcUnownedHwBpWriteAddress3:               ; Write bp exception address 3.
    nop
    ret

END