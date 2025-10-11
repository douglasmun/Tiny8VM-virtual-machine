; Print "HELLO WORLD" followed by newline
.org $0200
start:
        LDA #$48    ; H
        SYS #$00
        LDA #$45    ; E
        SYS #$00
        LDA #$4C    ; L
        SYS #$00
        LDA #$4C    ; L
        SYS #$00
        LDA #$4F    ; O
        SYS #$00
        LDA #$20    ; space
        SYS #$00
        LDA #$57    ; W
        SYS #$00
        LDA #$4F    ; O
        SYS #$00
        LDA #$52    ; R
        SYS #$00
        LDA #$4C    ; L
        SYS #$00
        LDA #$44    ; D
        SYS #$00
        LDA #$0A    ; newline
        SYS #$00
        BRK
