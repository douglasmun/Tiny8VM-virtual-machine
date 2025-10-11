; Simple IRQ test - FIXED with proper halt
.ORG $0200

MAIN:
    ; Setup IRQ vector
    LDA #<IRQ_HANDLER
    STA $FFFE
    LDA #>IRQ_HANDLER
    STA $FFFF
    
    ; Initialize counter and flag
    LDA #0
    STA $80
    STA $81
    
    CLI
    
    ; Enable timer
    LDA #1
    STA $8010
    
    ; Wait for IRQ
    LDX #0
    LDY #0
.wait:
    LDA $81
    BNE .got_irq
    INX
    BNE .wait
    INY
    CPY #20
    BNE .wait
    
    JMP FAIL

.got_irq:
    LDA #'O'
    SYS #0
    LDA #'K'
    SYS #0
    LDA #' '
    SYS #0
    LDA $80
    SYS #4
    LDA #10
    SYS #0
    
HALT_OK:
    JMP HALT_OK      ; Infinite loop - not BRK

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
    
HALT_FAIL:
    JMP HALT_FAIL    ; Infinite loop - not BRK

IRQ_HANDLER:
    PHA
    
    ; Disable timer immediately
    LDA #0
    STA $8010
    
    ; Set flag
    LDA #1
    STA $81
    
    ; Increment counter
    INC $80
    
    PLA
    RTI