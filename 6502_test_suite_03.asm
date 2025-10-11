; ======================================================================
; 6502 VM TEST SUITE 03
; Tests: Indirect Addressing, All Addressing Modes, Edge Cases
; ======================================================================

.ORG $0200

START:
    ; ================================
    ; Test 1: Indirect Indexed (zp),Y - LDA
    ; ================================
TEST_INDZP_Y_LDA:
    LDA #'1'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Set up pointer at $30 -> $0500
    LDA #$00
    STA $30
    LDA #$05
    STA $31
    
    ; Store test values
    LDA #$11
    STA $0500
    LDA #$22
    STA $0501
    LDA #$33
    STA $0502
    
    ; Test LDA ($30),Y with Y=0,1,2
    LDY #$00
    LDA ($30),Y
    CMP #$11
    BNE .fail1
    
    LDY #$01
    LDA ($30),Y
    CMP #$22
    BNE .fail1
    
    LDY #$02
    LDA ($30),Y
    CMP #$33
    BNE .fail1
    JMP .pass1
.fail1:
    JMP FAIL
.pass1:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 2: Indexed Indirect (zp,X) - STA
    ; ================================
TEST_INDX_ZP_STA:
    LDA #'2'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Set up pointer at $40 -> $0600
    LDA #$00
    STA $40
    LDA #$06
    STA $41
    
    ; Test STA ($40,X)
    LDX #$00
    LDA #$99
    STA ($40,X)
    
    ; Verify
    LDA $0600
    CMP #$99
    BNE .fail2
    JMP .pass2
.fail2:
    JMP FAIL
.pass2:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 3: All ADC Addressing Modes
    ; ================================
TEST_ADC_MODES:
    LDA #'3'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; ADC immediate
    CLC
    LDA #$10
    ADC #$05
    CMP #$15
    BNE .fail3
    
    ; ADC zero page
    LDA #$20
    STA $50
    CLC
    LDA #$10
    ADC $50
    CMP #$30
    BNE .fail3
    
    ; ADC zero page,X
    LDA #$15
    STA $60
    LDX #$00
    CLC
    LDA #$10
    ADC $60,X
    CMP #$25
    BNE .fail3
    
    ; ADC absolute
    LDA #$30
    STA $0700
    CLC
    LDA #$20
    ADC $0700
    CMP #$50
    BNE .fail3
    
    ; ADC absolute,X
    LDA #$40
    STA $0710
    LDX #$10
    CLC
    LDA #$30
    ADC $0700,X
    CMP #$70
    BNE .fail3
    
    ; ADC absolute,Y
    LDA #$50
    STA $0720
    LDY #$20
    CLC
    LDA #$40
    ADC $0700,Y
    CMP #$90
    BNE .fail3
    JMP .pass3
.fail3:
    JMP FAIL
.pass3:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 4: All SBC Addressing Modes
    ; ================================
TEST_SBC_MODES:
    LDA #'4'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; SBC immediate
    SEC
    LDA #$50
    SBC #$30
    CMP #$20
    BNE .fail4
    
    ; SBC zero page
    LDA #$25
    STA $51
    SEC
    LDA #$50
    SBC $51
    CMP #$2B
    BNE .fail4
    
    ; SBC absolute
    LDA #$30
    STA $0730
    SEC
    LDA #$80
    SBC $0730
    CMP #$50
    BNE .fail4
    JMP .pass4
.fail4:
    JMP FAIL
.pass4:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 5: All CMP Addressing Modes
    ; ================================
TEST_CMP_MODES:
    LDA #'5'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; CMP immediate - equal
    LDA #$42
    CMP #$42
    BNE .fail5
    BCC .fail5      ; Should set carry when A >= operand
    
    ; CMP zero page - greater
    LDA #$20
    STA $52
    LDA #$30
    CMP $52
    BCC .fail5      ; A > mem, carry should be set
    
    ; CMP absolute,X - less than
    LDA #$15
    STA $0740
    LDX #$00
    LDA #$10
    CMP $0740,X
    BCS .fail5      ; A < mem, carry should be clear
    JMP .pass5
.fail5:
    JMP FAIL
.pass5:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 6: All AND Addressing Modes
    ; ================================
TEST_AND_MODES:
    LDA #'6'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; AND immediate
    LDA #$FF
    AND #$0F
    CMP #$0F
    BNE .fail6
    
    ; AND zero page
    LDA #$AA
    STA $53
    LDA #$FF
    AND $53
    CMP #$AA
    BNE .fail6
    
    ; AND absolute,Y
    LDA #$F0
    STA $0750
    LDY #$00
    LDA #$FF
    AND $0750,Y
    CMP #$F0
    BNE .fail6
    JMP .pass6
.fail6:
    JMP FAIL
.pass6:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 7: All ORA Addressing Modes
    ; ================================
TEST_ORA_MODES:
    LDA #'7'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; ORA immediate
    LDA #$0F
    ORA #$F0
    CMP #$FF
    BNE .fail7
    
    ; ORA zero page,X
    LDA #$AA
    STA $60
    LDX #$00
    LDA #$55
    ORA $60,X
    CMP #$FF
    BNE .fail7
    JMP .pass7
.fail7:
    JMP FAIL
.pass7:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 8: All EOR Addressing Modes
    ; ================================
TEST_EOR_MODES:
    LDA #'8'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; EOR immediate
    LDA #$FF
    EOR #$FF
    BNE .fail8      ; Should be zero
    
    ; EOR zero page
    LDA #$AA
    STA $54
    LDA #$FF
    EOR $54
    CMP #$55
    BNE .fail8
    
    ; EOR absolute
    LDA #$F0
    STA $0760
    LDA #$0F
    EOR $0760
    CMP #$FF
    BNE .fail8
    JMP .pass8
.fail8:
    JMP FAIL
.pass8:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 9: Memory Modification with Indexing
    ; ================================
TEST_MEM_INDEX:
    LDA #'9'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; INC absolute,X
    LDA #$10
    STA $0770
    LDX #$00
    INC $0770,X
    LDA $0770
    CMP #$11
    BNE .fail9
    
    ; DEC zero page,X
    LDA #$20
    STA $70
    LDX #$00
    DEC $70,X
    LDA $70
    CMP #$1F
    BNE .fail9
    
    ; ASL zero page,X
    LDA #$02
    STA $71
    LDX #$00
    ASL $71,X
    LDA $71
    CMP #$04
    BNE .fail9
    JMP .pass9
.fail9:
    JMP FAIL
.pass9:
    
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #10
    SYS #0

    ; ================================
    ; Test 10: Overflow Flag Edge Cases
    ; ================================
TEST_OVERFLOW:
    LDA #'1'
    SYS #0
    LDA #'0'
    SYS #0
    LDA #':'
    SYS #0
    LDA #' '
    SYS #0
    
    ; Positive + Positive = Negative (overflow)
    CLC
    LDA #$7F        ; +127
    ADC #$01        ; +1 = -128 (overflow)
    BVC .fail10     ; V should be set
    
    ; Negative + Negative = Positive (overflow)
    CLC
    LDA #$80        ; -128
    ADC #$80        ; -128 = 0 (overflow)
    BVC .fail10     ; V should be set
    
    ; Positive + Negative = no overflow
    CLV
    CLC
    LDA #$7F        ; +127
    ADC #$80        ; -128 = -1 (no overflow)
    BVS .fail10     ; V should be clear
    JMP .pass10
.fail10:
    JMP FAIL
.pass10:
    
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
