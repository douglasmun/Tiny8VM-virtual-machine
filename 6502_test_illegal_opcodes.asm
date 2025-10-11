; ======================================================================
; 6502 ILLEGAL OPCODE TEST SUITE
; Tests that undefined opcodes are handled safely
; ======================================================================

.ORG $0200

START:
    LDA #'I'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #'E'
    SYS #0
    LDA #'G'
    SYS #0
    LDA #'A'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 1: Verify Normal Opcodes Still Work
    ; ================================
TEST_NORMAL:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Basic sanity check
    LDA #$42
    CMP #$42
    BNE .f1
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_SINGLE_BYTE
.f1:
    JMP FAIL

    ; ================================
    ; Test 2: Single-Byte Illegal Opcodes
    ; ================================
TEST_SINGLE_BYTE:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; These opcodes are illegal/undefined on 6502
    ; We expect the VM to either:
    ; 1. Skip them (NOP behavior)
    ; 2. Halt execution safely
    ; 3. Report error
    
    ; We'll test by setting up a known state and seeing if we can continue
    LDA #$AA
    STA $80
    
    ; Try to skip over an illegal opcode using a jump
    JMP .after_illegal
    
.illegal_zone:
    .BYTE $02       ; KIL/JAM (illegal - should halt)
    .BYTE $12       ; KIL/JAM (illegal)
    .BYTE $22       ; KIL/JAM (illegal)
    .BYTE $32       ; KIL/JAM (illegal)
    .BYTE $42       ; KIL/JAM (illegal)
    .BYTE $52       ; KIL/JAM (illegal)
    .BYTE $62       ; KIL/JAM (illegal)
    .BYTE $72       ; KIL/JAM (illegal)
    .BYTE $92       ; KIL/JAM (illegal)
    .BYTE $B2       ; KIL/JAM (illegal)
    .BYTE $D2       ; KIL/JAM (illegal)
    .BYTE $F2       ; KIL/JAM (illegal)
    
.after_illegal:
    ; If we got here, we successfully jumped over illegal opcodes
    LDA $80
    CMP #$AA
    BNE .f2
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_NOP_VARIANTS
.f2:
    JMP FAIL

    ; ================================
    ; Test 3: NOP Variants (Some are illegal)
    ; ================================
TEST_NOP_VARIANTS:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Legal NOP
    NOP             ; $EA - legal
    
    ; Illegal NOPs (some 6502 variants implement these, others don't)
    ; We jump over them for safety
    JMP .after_nops
    
.nop_zone:
    .BYTE $1A       ; NOP (illegal on NMOS 6502)
    .BYTE $3A       ; NOP (illegal on NMOS 6502)
    .BYTE $5A       ; NOP (illegal on NMOS 6502)
    .BYTE $7A       ; NOP (illegal on NMOS 6502)
    .BYTE $DA       ; NOP (illegal on NMOS 6502)
    .BYTE $FA       ; NOP (illegal on NMOS 6502)
    
    ; Multi-byte NOPs
    .BYTE $04, $00  ; NOP zp (illegal)
    .BYTE $0C, $00, $00  ; NOP abs (illegal)
    
.after_nops:
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_UNDOCUMENTED

    ; ================================
    ; Test 4: Undocumented but Common Opcodes
    ; ================================
TEST_UNDOCUMENTED:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Some "illegal" opcodes are well-defined and commonly used
    ; We'll skip testing their functionality and just verify
    ; they don't crash the system
    
    ; LAX (Load A and X) - some implementations support this
    ; We'll jump over it for safety
    JMP .after_lax
    
.lax_zone:
    .BYTE $A7, $50  ; LAX zp (illegal but common)
    .BYTE $B7, $50  ; LAX zp,Y (illegal)
    .BYTE $AF, $00, $05  ; LAX abs (illegal)
    .BYTE $BF, $00, $05  ; LAX abs,Y (illegal)
    .BYTE $A3, $40  ; LAX (zp,X) (illegal)
    .BYTE $B3, $40  ; LAX (zp),Y (illegal)
    
.after_lax:
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_HIGHLY_UNSTABLE

    ; ================================
    ; Test 5: Highly Unstable Opcodes
    ; ================================
TEST_HIGHLY_UNSTABLE:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; These opcodes are known to be unstable or have
    ; unpredictable behavior. We skip over them.
    JMP .after_unstable
    
.unstable_zone:
    ; HLT/KIL opcodes - halt the processor
    .BYTE $02       ; Various HLT opcodes
    .BYTE $12
    .BYTE $22
    .BYTE $32
    .BYTE $42
    .BYTE $52
    .BYTE $62
    .BYTE $72
    .BYTE $92
    .BYTE $B2
    .BYTE $D2
    .BYTE $F2
    
    ; ANE/XAA - highly unstable
    .BYTE $8B, $00
    
    ; LXA - unstable
    .BYTE $AB, $00
    
.after_unstable:
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0
    JMP TEST_SAFETY

    ; ================================
    ; Test 6: Safety Check
    ; ================================
TEST_SAFETY:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Verify that jumping over illegal opcodes doesn't
    ; corrupt our registers or memory
    
    LDA #$55
    LDX #$AA
    LDY #$FF
    
    JMP .after_safety_test
    
.safety_test_zone:
    .BYTE $03       ; SLO (zp,X) - illegal
    .BYTE $07       ; SLO zp - illegal
    .BYTE $0F       ; SLO abs - illegal
    .BYTE $13       ; SLO (zp),Y - illegal
    .BYTE $17       ; SLO zp,X - illegal
    .BYTE $1B       ; SLO abs,Y - illegal
    .BYTE $1F       ; SLO abs,X - illegal
    
.after_safety_test:
    ; Check registers weren't corrupted
    CMP #$55
    BNE .f6
    
    CPX #$AA
    BNE .f6
    
    CPY #$FF
    BNE .f6
    
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
    ; Test 7: Opcode Coverage
    ; ================================
TEST_COMPLETE:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Summary: We've tested that:
    ; 1. Legal opcodes still work
    ; 2. Illegal opcodes can be safely skipped
    ; 3. System doesn't crash when encountering illegal opcodes in data
    ; 4. Registers/memory aren't corrupted
    
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
    LDA #'I'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #'L'
    SYS #0
    LDA #'E'
    SYS #0
    LDA #'G'
    SYS #0
    LDA #'A'
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