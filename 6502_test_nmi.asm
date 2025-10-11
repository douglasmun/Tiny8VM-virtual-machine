; Test program for NMI functionality - test_nmi.asm
.ORG $0200

MAIN:
    SEI              ; Disable IRQ (NMI should still work)
    
    ; Set NMI vector to handler at $0300
    LDA #$00
    STA $FFFA
    LDA #$03
    STA $FFFB
    
    ; Initialize counter
    LDA #0
    STA $80
    
    ; Trigger NMI by writing to $8020
    LDA #1
    STA $8020        ; First write (0→1 edge triggers NMI)
    
    ; NMI should have fired here
    ; Counter should now be 1
    
    LDA $80
    CMP #1
    JZ SUCCESS1
    LDA #'F'         ; Failed
    SYS #0
    BRK

SUCCESS1:
    LDA #'1'         ; First NMI worked
    SYS #0
    
    ; Trigger second NMI (need 1→0→1 edge)
    LDA #0
    STA $8020        ; Reset to 0
    LDA #1
    STA $8020        ; Trigger again
    
    ; Counter should now be 2
    LDA $80
    CMP #2
    JZ SUCCESS2
    LDA #'F'
    SYS #0
    BRK

SUCCESS2:
    LDA #'2'         ; Second NMI worked
    SYS #0
    LDA #10
    SYS #0
    
    BRK

; NMI Handler at $0300
.ORG $0300
NMI_HANDLER:
    PHA
    
    ; Increment counter
    LDA $80
    CLC
    ADC #1
    STA $80
    
    ; Print 'N' to show NMI fired
    LDA #'N'
    SYS #0
    
    PLA
    RTI