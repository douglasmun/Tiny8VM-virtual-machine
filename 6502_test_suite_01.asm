; ======================================================================
; COMPREHENSIVE 6502 VM TEST SUITE
; Tests: Basic I/O, Arithmetic, Logic, Branches, Stack, New Addressing Modes
; ======================================================================

.ORG $0200

START:
    ; ================================
    ; Test 1: Basic Output (SYS #0 PUTCHAR)
    ; ================================
TEST_OUTPUT:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 2: Numeric Output (SYS #4 PUTNUM)
    ; ================================
TEST_PUTNUM:
    LDA #'2'
    SYS #0
    LDA #$3A        ; ':'
    SYS #0
    LDA #$20        ; ' ' (space)
    SYS #0
    
    LDA #$58        ; Load 88 decimal as hex 0x58
    SYS #4
    LDA #$20        ; space
    SYS #0
    LDA #10
    SYS #0
    
    ; ================================
    ; Test 3: ADC/SBC with Carry
    ; ================================
TEST_ADC_SBC:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test ADC
    CLC
    LDA #$05
    ADC #$03        ; Should be 8
    CMP #$08
    BEQ .adc_ok
    JMP FAIL
.adc_ok:
    
    ; Test SBC
    SEC
    LDA #$50
    SBC #$30        ; Should be $20
    CMP #$20
    BEQ .sbc_ok
    JMP FAIL
.sbc_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 4: CPX and CPY
    ; ================================
TEST_CPX_CPY:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test CPX with equality
    LDX #$10
    CPX #$10
    BEQ .cpx_eq_ok
    JMP FAIL
.cpx_eq_ok:
    
    ; Test CPX with greater than
    CPX #$05        ; X=16, comparing with 5, should set C
    BCS .cpx_gt_ok
    JMP FAIL
.cpx_gt_ok:
    
    ; Test CPY
    LDY #$20
    CPY #$20
    BEQ .cpy_ok
    JMP FAIL
.cpy_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 5: INC and DEC
    ; ================================
TEST_INC_DEC:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Test INC
    LDA #$42
    STA $80
    INC $80
    LDA $80
    CMP #$43
    BEQ .inc_ok
    JMP FAIL
.inc_ok:
    
    ; Test DEC
    DEC $80
    LDA $80
    CMP #$42
    BEQ .dec_ok
    JMP FAIL
.dec_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 6: EOR (Exclusive OR)
    ; ================================
TEST_EOR:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    LDA #$FF
    EOR #$0F        ; Should be $F0
    CMP #$F0
    BEQ .eor_ok
    JMP FAIL
.eor_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 7: TSX and TXS
    ; ================================
TEST_TSX_TXS:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    TSX
    CPX #$FF        ; SP should start at $FF
    BEQ .tsx_ok
    JMP FAIL
.tsx_ok:
    
    LDX #$80
    TXS
    TSX
    CPX #$80
    BEQ .txs_ok
    JMP FAIL
.txs_ok:
    
    ; Restore SP
    LDX #$FF
    TXS
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 8: Absolute,Y addressing
    ; ================================
TEST_ABS_Y:
    LDA #'8'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Set up table
    LDA #$AA
    STA $0300
    LDA #$BB
    STA $0301
    
    ; Test LDA abs,Y
    LDY #$01
    LDA $0300,Y     ; Should load $BB
    CMP #$BB
    BEQ .absy_ok
    JMP FAIL
.absy_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 9: Indexed Indirect (zp,X)
    ; ================================
TEST_INDX_ZP:
    LDA #'9'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Set up pointer at $20 -> $0400
    LDA #$00
    STA $20
    LDA #$04
    STA $21
    
    ; Store test value
    LDA #$55
    STA $0400
    
    ; Test LDA (zp,X)
    LDX #$00
    LDA ($20,X)
    CMP #$55
    BEQ .indx_ok
    JMP FAIL
.indx_ok:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 10: Stack Operations
    ; ================================
TEST_STACK:
    LDA #'1'
    SYS #0
    LDA #'0'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    LDA #$42
    PHA
    LDA #$00
    PLA
    CMP #$42
    BEQ .stack_ok
    JMP FAIL
.stack_ok:
    
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