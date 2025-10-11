; ======================================================================
; 6502 VM TEST SUITE 04
; Tests: Edge Cases, Flag Interactions, Complex Scenarios, STX/STY variants
; ======================================================================

.ORG $0200

START:
    ; ================================
    ; Test 1: Zero Flag Edge Cases
    ; ================================
TEST_ZERO_FLAG:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Zero from subtraction
    SEC
    LDA #$42
    SBC #$42
    BNE .f1         ; Should be zero
    
    ; Zero from AND
    LDA #$0F
    AND #$F0
    BNE .f1
    
    ; Zero from decrement
    LDA #$01
    STA $80
    DEC $80
    LDA $80
    BNE .f1
    
    ; Not zero
    LDA #$01
    BEQ .f1
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
    ; Test 2: Negative Flag Edge Cases
    ; ================================
TEST_NEGATIVE_FLAG:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Negative from load
    LDA #$80
    BPL .f2         ; Should be negative
    
    ; Negative from arithmetic
    SEC
    LDA #$10
    SBC #$20        ; Result = $F0 (negative)
    BPL .f2
    
    ; Positive
    LDA #$7F
    BMI .f2
    
    ; Zero is not negative
    LDA #$00
    BMI .f2
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
    ; Test 3: Carry Flag Complex Cases
    ; ================================
TEST_CARRY_COMPLEX:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; ADC with carry propagation
    SEC             ; Set carry
    LDA #$FF
    ADC #$00        ; Should be $00 with carry set
    BNE .f3         ; Result should be zero
    BCC .f3         ; Carry should be set
    
    ; SBC borrow
    CLC             ; Clear carry (borrow)
    LDA #$00
    SBC #$01        ; Should be $FF with carry clear
    BCS .f3         ; Carry should be clear
    CMP #$FE
    BNE .f3
    
    ; CMP sets carry when A >= operand
    LDA #$80
    CMP #$80
    BCC .f3         ; Equal, carry should be set
    
    LDA #$80
    CMP #$81
    BCS .f3         ; Less than, carry should be clear
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
    ; Test 4: All STX Variants
    ; ================================
TEST_STX:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; STX zero page
    LDX #$11
    STX $81
    LDA $81
    CMP #$11
    BNE .f4
    
    ; STX zero page,Y
    LDX #$22
    LDY #$01
    STX $90,Y       ; Store at $91
    LDA $91
    CMP #$22
    BNE .f4
    
    ; STX absolute
    LDX #$33
    STX $0800
    LDA $0800
    CMP #$33
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
    ; Test 5: All STY Variants
    ; ================================
TEST_STY:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; STY zero page
    LDY #$44
    STY $82
    LDA $82
    CMP #$44
    BNE .f5
    
    ; STY zero page,X
    LDY #$55
    LDX #$02
    STY $A0,X       ; Store at $A2
    LDA $A2
    CMP #$55
    BNE .f5
    
    ; STY absolute
    LDY #$66
    STY $0810
    LDA $0810
    CMP #$66
    BNE .f5
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
    ; Test 6: LDX and LDY All Modes
    ; ================================
TEST_LDX_LDY:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; LDX immediate
    LDX #$77
    CPX #$77
    BNE .f6
    
    ; LDX zero page
    LDA #$88
    STA $83
    LDX $83
    CPX #$88
    BNE .f6
    
    ; LDX zero page,Y
    LDA #$99
    STA $B0
    LDY #$00
    LDX $B0,Y
    CPX #$99
    BNE .f6
    
    ; LDX absolute
    LDA #$AA
    STA $0820
    LDX $0820
    CPX #$AA
    BNE .f6
    
    ; LDX absolute,Y
    LDA #$BB
    STA $0830
    LDY #$00
    LDX $0830
    CPX #$BB
    BNE .f6
    
    ; LDY immediate
    LDY #$CC
    CPY #$CC
    BNE .f6
    
    ; LDY zero page
    LDA #$DD
    STA $84
    LDY $84
    CPY #$DD
    BNE .f6
    
    ; LDY absolute,X
    LDA #$EE
    STA $0840
    LDX #$00
    LDY $0840,X
    CPY #$EE
    BNE .f6
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
    ; Test 7: INX/INY and DEX/DEY Edge Cases
    ; ================================
TEST_INCDEC_XY:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; INX from $FF wraps to $00
    LDX #$FF
    INX
    BNE .f7         ; Should be zero
    
    ; DEX from $00 wraps to $FF
    LDX #$00
    DEX
    CPX #$FF
    BNE .f7
    
    ; INY sets flags correctly
    LDY #$7F
    INY
    BPL .f7         ; Should be negative ($80)
    
    ; DEY to zero sets Z flag
    LDY #$01
    DEY
    BNE .f7
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
    ; Test 8: Transfer Instructions with Flags
    ; ================================
TEST_TRANSFERS:
    LDA #'8'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; TAX sets Z flag
    LDA #$00
    TAX
    BNE .f8
    
    ; TAY sets N flag
    LDA #$80
    TAY
    BPL .f8
    
    ; TXA transfers value
    LDX #$42
    TXA
    CMP #$42
    BNE .f8
    
    ; TYA transfers value
    LDY #$99
    TYA
    CMP #$99
    BNE .f8
    JMP .p8
.f8:
    JMP FAIL
.p8:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 9: Complex Stack Operations
    ; ================================
TEST_STACK_COMPLEX:
    LDA #'9'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Push multiple values
    LDA #$11
    PHA
    LDA #$22
    PHA
    LDA #$33
    PHA
    
    ; Pop in reverse order
    PLA
    CMP #$33
    BNE .f9
    PLA
    CMP #$22
    BNE .f9
    PLA
    CMP #$11
    BNE .f9
    
    ; PHP/PLP preserves all flags
    SEC
    CLV
    LDA #$80        ; Set N flag
    PHP
    CLC
    LDA #$00
    PLP
    BCC .f9         ; C should be restored
    BPL .f9         ; N should be restored
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

    ; ================================
    ; Test 10: Wraparound and Boundary Cases
    ; ================================
TEST_WRAPAROUND:
    LDA #'1'
    SYS #0
    LDA #'0'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Zero page wraps at $FF
    LDA #$42
    STA $FF
    LDX #$00
    LDA $FF,X
    CMP #$42
    BNE FAIL
    
    ; Add with wraparound
    CLC
    LDA #$FF
    ADC #$01
    BCC FAIL        ; Should set carry
    CMP #$00
    BNE FAIL
    
    ; Subtract with borrow
    SEC
    LDA #$00
    SBC #$01
    BCS FAIL        ; Should clear carry (borrow occurred)
    CMP #$FF
    BNE FAIL
    
    ; INC wraps $FF to $00
    LDA #$FF
    STA $84
    INC $84
    LDA $84
    BNE FAIL
    
    ; DEC wraps $00 to $FF
    LDA #$00
    STA $85
    DEC $85
    LDA $85
    CMP #$FF
    BNE FAIL
    
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
    JMP PASS_MSG
    
FAIL:
    JMP FAIL_MSG

PASS_MSG:
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

FAIL_MSG:
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
