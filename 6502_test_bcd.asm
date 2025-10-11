; ======================================================================
; BCD (Binary Coded Decimal) MODE TEST SUITE
; Tests SED/CLD and BCD arithmetic
; ======================================================================

.ORG $0200

START:
    LDA #'B'
    SYS #0
    LDA #'C'
    SYS #0
    LDA #'D'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 1: SED/CLD Instructions
    ; ================================
TEST_FLAGS:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    CLD             ; Clear decimal mode
    SED             ; Set decimal mode
    CLD             ; Clear it again
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 2: BCD Addition
    ; ================================
TEST_BCD_ADD:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    SED             ; Enable BCD mode
    CLC
    LDA #$09        ; 9 in BCD
    ADC #$01        ; + 1 in BCD
    CMP #$10        ; Should be 10 in BCD (0x10)
    BNE .f2
    
    CLC
    LDA #$15        ; 15 in BCD
    ADC #$27        ; + 27 in BCD
    CMP #$42        ; Should be 42 in BCD (0x42)
    BNE .f2
    
    CLC
    LDA #$99        ; 99 in BCD
    ADC #$01        ; + 1 in BCD
    CMP #$00        ; Should be 00 with carry
    BNE .f2
    BCC .f2         ; Carry should be set
    
    CLD             ; Back to binary mode
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_BCD_SUB
.f2:
    JMP FAIL

    ; ================================
    ; Test 3: BCD Subtraction
    ; ================================
TEST_BCD_SUB:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    SED             ; Enable BCD mode
    SEC             ; Set carry (no borrow)
    LDA #$50        ; 50 in BCD
    SBC #$25        ; - 25 in BCD
    CMP #$25        ; Should be 25 in BCD (0x25)
    BNE .f3
    
    SEC
    LDA #$12        ; 12 in BCD
    SBC #$08        ; - 8 in BCD
    CMP #$04        ; Should be 4 in BCD (0x04)
    BNE .f3
    
    CLD             ; Back to binary mode
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_BINARY_STILL_WORKS
.f3:
    JMP FAIL

    ; ================================
    ; Test 4: Binary Mode Still Works
    ; ================================
TEST_BINARY_STILL_WORKS:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    CLD             ; Ensure binary mode
    CLC
    LDA #$09
    ADC #$01
    CMP #$0A        ; Should be 0x0A (10 in binary)
    BNE .f4
    
    CLC
    LDA #$99
    ADC #$01
    CMP #$9A        ; Should be 0x9A (154 in binary)
    BNE .f4
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP PASS
.f4:
    JMP FAIL

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
    LDA #'B'
    SYS #0
    LDA #'C'
    SYS #0
    LDA #'D'
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
    LDA #10
    SYS #0
.halt:
    JMP .halt

FAIL:
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
.halt:
    JMP .halt
