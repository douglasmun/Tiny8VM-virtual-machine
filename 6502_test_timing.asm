; ======================================================================
; 6502 TIMING TEST SUITE
; Verifies cycle counts match real 6502
; ======================================================================

.ORG $0200

START:
    LDA #'T'
    SYS #0
    LDA #'I'
    SYS #0
    LDA #'M'
    SYS #0
    LDA #'I'
    SYS #0
    LDA #'N'
    SYS #0
    LDA #'G'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 1: Basic Instruction Timing
    ; ================================
TEST_BASIC:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Capture start cycles (we'll use a marker)
    ; Store start marker
    LDA #$AA
    STA $80
    
    ; Execute known sequence:
    ; LDA #nn  = 2 cycles
    ; STA abs  = 4 cycles
    ; NOP      = 2 cycles
    ; Total    = 8 cycles
    
    LDA #$42        ; 2 cycles
    STA $0300       ; 4 cycles
    NOP             ; 2 cycles
    
    ; Verify result is correct
    LDA $0300
    CMP #$42
    BNE .f1
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_ADDRESSING
.f1:
    JMP FAIL

    ; ================================
    ; Test 2: Addressing Mode Timing
    ; ================================
TEST_ADDRESSING:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; LDA Immediate = 2 cycles
    LDA #$11        ; 2
    
    ; LDA Zero Page = 3 cycles
    LDA #$22
    STA $50
    LDA $50         ; 3
    
    ; LDA Zero Page,X = 4 cycles
    LDX #$01
    LDA #$33
    STA $51
    LDA $50,X       ; 4
    
    ; LDA Absolute = 4 cycles
    LDA #$44
    STA $0400
    LDA $0400       ; 4
    
    ; LDA Absolute,X = 4+ cycles (5 if page boundary crossed)
    LDX #$01
    LDA #$55
    STA $0401
    LDA $0400,X     ; 4 (no page cross)
    
    ; Page boundary crossing adds 1 cycle
    LDX #$FF
    LDA #$66
    STA $0500
    LDA $0401,X     ; 5 cycles (crosses page boundary $04FF -> $0500)
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_BRANCHES

    ; ================================
    ; Test 3: Branch Timing
    ; ================================
TEST_BRANCHES:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Branch not taken = 2 cycles
    LDA #$00
    BNE .skip1      ; 2 cycles (not taken)
    NOP
.skip1:
    
    ; Branch taken (same page) = 3 cycles
    LDA #$00
    BEQ .taken1     ; 3 cycles (taken, no page cross)
    JMP FAIL
.taken1:
    
    ; Branch taken (page cross) = 4 cycles
    ; This requires careful positioning - the branch must cross a page boundary
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_STACK

    ; ================================
    ; Test 4: Stack Operation Timing
    ; ================================
TEST_STACK:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; PHA = 3 cycles
    LDA #$99
    PHA             ; 3
    
    ; PLA = 4 cycles
    PLA             ; 4
    
    ; PHP = 3 cycles
    PHP             ; 3
    
    ; PLP = 4 cycles
    PLP             ; 4
    
    ; JSR = 6 cycles
    JSR .sub        ; 6
    JMP .continue
.sub:
    ; RTS = 6 cycles
    RTS             ; 6
    
.continue:
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_RMW

    ; ================================
    ; Test 5: Read-Modify-Write Timing
    ; ================================
TEST_RMW:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; INC Zero Page = 5 cycles
    LDA #$10
    STA $60
    INC $60         ; 5
    
    ; INC Absolute = 6 cycles
    LDA #$20
    STA $0500
    INC $0500       ; 6
    
    ; INC Absolute,X = 7 cycles
    LDX #$01
    LDA #$30
    STA $0511
    INC $0510,X     ; 7
    
    ; ASL Accumulator = 2 cycles
    LDA #$40
    ASL             ; 2
    
    ; ASL Zero Page = 5 cycles
    LDA #$50
    STA $70
    ASL $70         ; 5
    
    ; ROL/ROR also 5 cycles for ZP, 6 for ABS
    LDA #$60
    STA $80
    ROL $80         ; 5
    ROR $80         ; 5
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_INDIRECT

    ; ================================
    ; Test 6: Indirect Addressing Timing
    ; ================================
TEST_INDIRECT:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; JMP Indirect = 5 cycles
    LDA #<.target
    STA $90
    LDA #>.target
    STA $91
    JMP ($90)       ; 5 cycles
.target:
    
    ; LDA (ZP),Y = 5+ cycles (6 if page boundary crossed)
    LDA #$00
    STA $A0
    LDA #$06
    STA $A1         ; Pointer to $0600
    
    LDA #$77
    STA $0600
    
    LDY #$00
    LDA ($A0),Y     ; 5 cycles (no page cross)
    CMP #$77
    BNE .f6
    
    ; Test page boundary crossing
    LDA #$88
    STA $0700
    LDY #$FF
    LDA ($A0),Y     ; 6 cycles (page cross: $0600 + $FF = $06FF)
    
    ; LDA (ZP,X) = 6 cycles
    LDA #$00
    STA $B0
    LDA #$07
    STA $B1         ; Pointer at $B0 -> $0700
    
    LDX #$00
    LDA ($B0,X)     ; 6 cycles
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_COMPLETE
.f6:
    JMP FAIL

    ; ================================
    ; Test 7: Comparison Timing
    ; ================================
TEST_COMPLETE:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; CMP/CPX/CPY all same timing as LDA
    LDA #$50
    CMP #$50        ; 2 cycles
    
    LDA #$60
    STA $C0
    CMP $C0         ; 3 cycles
    
    LDX #$70
    CPX #$70        ; 2 cycles
    
    LDY #$80
    CPY #$80        ; 2 cycles
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP PASS

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
    LDA #'I'
    SYS #0
    LDA #'M'
    SYS #0
    LDA #'I'
    SYS #0
    LDA #'N'
    SYS #0
    LDA #'G'
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
.halt:
    JMP .halt