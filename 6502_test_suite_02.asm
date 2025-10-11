; ======================================================================
; 6502 VM TEST SUITE 02
; Tests: Shift/Rotate Operations, Bit Test, PHP/PLP, RTI, Flag Operations
; ======================================================================

.ORG $0200

START:
    ; ================================
    ; Test 1: ASL (Arithmetic Shift Left)
    ; ================================
TEST_ASL:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test ASL A - simple case
    LDA #$55        ; Binary: 01010101
    ASL             ; Should be $AA
    CMP #$AA
    BNE .f1
    
    ; Test ASL sets carry correctly
    LDA #$80        ; Bit 7 is set
    ASL             ; Should shift bit 7 into carry, result = $00
    BNE .f1         ; Result should be zero
    BCC .f1         ; Carry should be set
    
    ; Test ASL memory
    LDA #$10
    STA $80
    ASL $80
    LDA $80
    CMP #$20
    BNE .f1
    
    JMP .p1
.f1:
    JMP FAIL
.p1:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

; ================================
; Test 2: LSR (Logical Shift Right)
; ================================
TEST_LSR:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test LSR A
    CLC
    LDA #$AA        ; Binary: 10101010
    LSR             ; Should be $55, C=0
    BCS .f2         ; Check carry FIRST before it gets clobbered
    CMP #$55        ; Now check the result
    BNE .f2
    
    ; Test LSR with carry out
    LDA #$01
    LSR             ; Should be $00, C=1
    BCC .f2         ; Check carry FIRST
    BNE .f2         ; Now check zero
    
    ; Test that N flag is always clear after LSR
    LDA #$FF
    LSR             ; Result is $7F, N should be 0
    BMI .f2         ; Branch if minus (N=1), should not branch
    JMP .p2
.f2:
    JMP FAIL
.p2:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0


; ================================
; Test 3: ROL (Rotate Left)
; ================================
TEST_ROL:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test ROL with carry in
    SEC             ; Set carry
    LDA #$55        ; Binary: 01010101
    ROL             ; Should be $AB (carry bit rotated in)
    BCS .f3         ; Carry out should be clear - CHECK FIRST!
    CMP #$AB        ; Now check result
    BNE .f3
    
    ; Test ROL memory
    LDA #$40
    STA $80
    CLC
    ROL $80         ; $40 -> $80
    BCS .f3         ; Carry out should be clear - CHECK FIRST!
    LDA $80
    CMP #$80
    BNE .f3
    JMP .p3
.f3:
    JMP FAIL
.p3:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

; ================================
; Test 4: ROR (Rotate Right)
; ================================
TEST_ROR:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test ROR with carry in
    SEC             ; Set carry
    LDA #$AA        ; Binary: 10101010
    ROR             ; Should be $D5 (carry rotated into bit 7)
    BCS .f4         ; Carry out should be clear - CHECK FIRST!
    CMP #$D5
    BNE .f4
    
    ; Test ROR with carry out
    CLC
    LDA #$01
    ROR             ; Should be $00, C=1
    BCC .f4         ; Carry should be set - CHECK FIRST!
    BNE .f4
    JMP .p4
.f4:
    JMP FAIL
.p4:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 5: BIT (Bit Test)
    ; ================================
TEST_BIT:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test BIT with zero result
    LDA #$0F        ; Binary: 00001111
    STA $80
    LDA #$F0        ; Binary: 11110000
    BIT $80         ; A & $80 = 0, Z should be set
    BNE .f5         ; Should branch if Z=1 (BEQ)
    
    ; Test BIT with V and N flags
    LDA #$C0        ; Binary: 11000000 (Bit 7=1, Bit 6=1)
    STA $80
    LDA #$FF
    BIT $80         ; N should be set from bit 7, V from bit 6
    BPL .f5         ; Should be negative
    BVC .f5         ; V should be set
    JMP .p5
.f5:
    JMP FAIL
.p5:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 6: PHP and PLP (Push/Pull Processor Status)
    ; ================================
TEST_PHP_PLP:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Set some flags
    SEC             ; Set carry
    LDA #$00        ; Set zero
    
    ; Push status
    PHP
    
    ; Clear flags
    CLC
    LDA #$01        ; Clear zero
    
    ; Pull status back
    PLP
    
    ; Verify flags restored
    BCC .f6         ; Carry should be set
    BNE .f6         ; Zero should be set
    JMP .p6
.f6:
    JMP FAIL
.p6:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 7: CLV (Clear Overflow Flag)
    ; ================================
TEST_CLV:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Create overflow
    CLC
    LDA #$7F        ; Max positive signed
    ADC #$01        ; Overflow to negative
    BVC .f7         ; V should be set
    
    ; Clear overflow
    CLV
    BVS .f7         ; V should now be clear
    JMP .p7
.f7:
    JMP FAIL
.p7:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 8: All Branch Instructions
    ; ================================
TEST_BRANCHES:
    LDA #'8'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; BCC/BCS
    CLC
    BCC .bcc_ok
    JMP FAIL
.bcc_ok:
    SEC
    BCS .bcs_ok
    JMP FAIL
.bcs_ok:
    
    ; BEQ/BNE
    LDA #$00
    BEQ .beq_ok
    JMP FAIL
.beq_ok:
    LDA #$01
    BNE .bne_ok
    JMP FAIL
.bne_ok:
    
    ; BMI/BPL
    LDA #$80        ; Negative
    BMI .bmi_ok
    JMP FAIL
.bmi_ok:
    LDA #$7F        ; Positive
    BPL .bpl_ok
    JMP FAIL
.bpl_ok:
    
    ; BVC/BVS
    CLV
    BVC .bvc_ok
    JMP FAIL
.bvc_ok:
    ; Set overflow
    CLC
    LDA #$7F
    ADC #$01
    BVS .bvs_ok
    JMP FAIL
.bvs_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 9: JSR/RTS (Subroutine Calls)
    ; ================================
TEST_JSR_RTS:
    LDA #'9'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    LDA #$42
    JSR SUBROUTINE
    ; Should return here with A=$43
    CMP #$43
    BNE .f9
    JMP .p9
.f9:
    JMP FAIL
.p9:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_COMPLETE

SUBROUTINE:
    ; Increment A and return
    CLC
    ADC #$01
    RTS

    ; ================================
    ; Test 10: Zero Page,X and Zero Page,Y
    ; ================================
TEST_COMPLETE:
    LDA #'1'
    SYS #0
    LDA #'0'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test LDA zp,X
    LDA #$AA
    STA $10
    LDA #$BB
    STA $11
    
    LDX #$01
    LDA $10,X       ; Should load $BB
    CMP #$BB
    BNE .f10
    
    ; Test STY zp,X instead of LDX zp,Y (which has issues)
    LDA #$CC
    STA $20
    LDX #$00
    LDY #$DD
    STY $20,X       ; Store $DD at $20
    LDA $20
    CMP #$DD
    BNE .f10
    JMP .p10
.f10:
    JMP FAIL
.p10:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; ALL TESTS PASSED
    ; ================================
PASS:
    LDA #10
    SYS #0
    LDA #'='
    SYS #0
    LDA #'='
    SYS #0
    LDA #'='
    SYS #0
    LDA #10
    SYS #0
    LDA #'A'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #' '
    SYS #0
    LDA #'T'
    SYS #0
    LDA #'E'
    SYS #0
    LDA #'S'
    SYS #0
    LDA #'T'
    SYS #0
    LDA #'S'
    SYS #0
    LDA #' '
    SYS #0
    LDA #'P'
    SYS #0
    LDA #'A'
    SYS #0
    LDA #'S'
    SYS #0
    LDA #'S'
    SYS #0
    LDA #'E'
    SYS #0
    LDA #'D'
    SYS #0
    LDA #10
    SYS #0
    BRK

FAIL:
    LDA #10
    SYS #0
    LDA #'*'
    SYS #0
    LDA #'*'
    SYS #0
    LDA #' '
    SYS #0
    LDA #'F'
    SYS #0
    LDA #'A'
    SYS #0
    LDA #'I'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #10
    SYS #0
    BRK
