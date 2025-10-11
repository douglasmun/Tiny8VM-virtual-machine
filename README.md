# **Tiny8VM \- an 8-Bit Virtual Machine**

## **Executive Summary**

**Tiny8VM** is a compact, high-fidelity **8-bit virtual machine**, inspired by the original MOS 6502 microprocessor that powered systems like the Commodore 64, Apple II, and NES. **Written entirely in modern C**, Tiny8VM serves as both an educational tool and a test-bed for system programmers, emulator developers, and enthusiasts studying classic CPU architecture.

The project combines an **assembler**, **disassembler**, **trace**, and **ROM loading** framework in a single executable. The VM supports most 6502 addressing modes, accurate CPU flag behaviour, **memory-mapped I/O registers**, and system call hooks (e.g., SYS \#0 for output). It has been verified using a comprehensive multi-phase test suite covering ALU, logic, branch, and stack operations.

The code emphasises clarity over complexity, showcasing best practices in virtual machine design—clean abstractions, modular instruction decoding, and platform-independent I/O simulation. Tiny8VM demonstrates that a faithful CPU emulator can remain approachable and elegant, without external libraries or toolchain dependencies.

## **Technical Summary**

### **Architecture Overview**

Tiny8VM implements a 6502-like CPU core, memory subsystem, and I/O bus, featuring:

* **Registers**: A, X, Y, SP, P (status), PC (program counter).  
* **Memory map**:  
  * $0000–$7FFF → RAM  
  * $8000–$BFFF → I/O region (REG\_OUT, REG\_IN, REG\_TMR\_CTL, REG\_NMI\_TRG)  
  * $C000–$FFFF → ROM space (loadable binary)  
* **Interrupt vectors**: $FFFA (NMI), $FFFC (RESET), $FFFE (IRQ).

The CPU flags (C, Z, I, D, B, V, N) are emulated per instruction semantics. The VM maintains precise cycle tracking and handles NMIs, IRQs, and memory-mapped triggers.

### 

### **Instruction Set Completeness**

Tiny8VM implements the **full official 6502 instruction set**, including:

| Category | Instructions |
| :---- | :---- |
| **Arithmetic & Logic** | ADC, SBC, AND, EOR, ORA, BIT |
| **Increment/Decrement** | INC, DEC, INX, INY, DEX, DEY |
| **Load/Store** | LDA, LDX, LDY, STA, STX, STY |
| **Compare** | CMP, CPX, CPY |
| **Shift/Rotate** | ASL, LSR, ROL, ROR |
| **Stack** | PHA, PLA, PHP, PLP, TSX, TXS |
| **Control Flow** | JMP, JSR, RTS, RTI, and conditional branches (BEQ, BNE, BCS, BCC, etc.) |
| **Flag operations** | SEC, CLC, SED, CLD, SEI, CLI |
| **System Call** | SYS \#n — a pseudo-instruction for VM I/O. |

Unimplemented or undocumented opcodes cleanly report errors, preserving assembler safety.

### 

### **Addressing Modes**

The assembler and disassembler support **all standard addressing modes**:

| Mode | Example | Description |
| :---- | :---- | :---- |
| **Immediate** | LDA \#$42 | Value is part of the instruction. |
| **Absolute** | STA $1234 | Direct address in 16-bit space. |
| **Zero Page** | INC $80 | Direct address in 8-bit $00XX space. |
| **Indexed** | LDA $80,X / LDA $1234,Y | Address offset by register X or Y. |
| **Indirect** | JMP ($FFFC) | Address fetched from a memory location. |
| **Indexed Indirect** | LDA ($20,X) | Zero page address indexed by X, then content is fetched as an effective address. |
| **Indirect Indexed** | LDA ($20),Y | Zero page content is fetched as a base address, then indexed by Y. |

Indirect zero-page indexing and local label scoping are also supported.

### 

### **Assembler & Disassembler**

Tiny8VM includes a **two-pass assembler** that handles:

* Global and local labels (.label syntax).  
* .FILL, .DS, and \* (current address) directives.  
* Macros with parameter substitution.  
* Conditional assembly via .IF/.ELSE/.ENDIF.  
* Expression evaluation with full operator precedence (+, \-, &, |, \<\<, \>\>, etc.).  
* Binary/hex/decimal literals and character constants ('A', \#10, %101010).

Error reporting displays line context with precise diagnostics. A simple built-in disassembler and trace logger provide instruction-by-instruction visibility during execution.

### **ROM Loading and I/O**

ROM binaries are loaded into $C000–$FFFF, with the **RESET vector auto-set to $C000**.  
Memory-mapped registers enable host I/O:

* REG\_OUT ($8000) — print output to stdout.  
* REG\_IN ($8001) — reserved for input.  
* REG\_TMR\_CTL / CNT — timer control registers.  
* REG\_NMI\_TRG — triggers software NMI for testing.

The VM supports reading, writing, and saving ROM images for persistence.

###

## **Sample Usages**

USAGE:  
  ./tiny8vm \<command\> \[options\]

COMMANDS:

  Assembly and Execution:  
    ./tiny8vm \<program.asm\> \[options\]  
        Assemble and run a program from source  
        Options: \--trace  \--disasm  \--debug  \--stats

  ROM Operations:  
    ./tiny8vm \--makerom \<input.asm\> \<output.rom\> \[start\] \[end\]  
        Assemble source and create ROM image  
        Defaults: start=$C000, end=$FFEF  
        Example: ./tiny8vm\_r26 \--makerom kernel.asm kernel.rom  
    ./tiny8vm \--rom \<rom.bin\> \[options\]  
        Load and execute a ROM image  
        Options: \--trace  \--stats

  Help:  
    ./tiny8vm \--help  
    ./tiny8vm \-h  
        Display this help message

OPTIONS:  
  \--trace      Show instruction trace during execution  
  \--disasm     Disassemble only (don't execute)  
  \--debug      Enable debug output  
  \--stats      Show execution statistics after completion

MEMORY MAP:  
  $0000-$7FFF  RAM (32KB)  
  $8000-$BFFF  Memory-mapped I/O (16KB)  
  $C000-$FFEF  ROM (16KB \- 16 bytes)  
  $FFFA-$FFFB  NMI vector  
  $FFFC-$FFFD  RESET vector  
  $FFFE-$FFFF  IRQ/BRK vector

I/O REGISTERS:  
  $8000  Output register (write only)  
  $8001  Input register (read only)  
  $8010  Timer control  
  $8011  Timer counter  
  $8020  NMI trigger

SYSCALLS (SYS \#n):  
  0  PUTCHAR  \- Output character in A  
  1  GETCHAR  \- Read character into A  
  2  PRINT    \- Print null-terminated string at (X,Y)  
  3  READLN   \- Read line into buffer at (X,Y), max length in A  
  4  PUTNUM   \- Print decimal number in A  
  5  GETNUM   \- Read decimal number into A

ASSEMBLER DIRECTIVES:  
  .ORG addr        Set assembly address  
  .EQU name, val   Define constant  
  .BYTE values     Define byte(s)  
  .WORD values     Define word(s)  
  .ASCIIZ "text"   Define null-terminated string  
  .FILL n, val     Fill n bytes with value  
  .DS n            Define n bytes of storage (zeros)  
  .ALIGN n         Align to n-byte boundary  
  .INCLUDE "file"  Include another file  
  .MACRO name      Define macro (end with .ENDMACRO)  
  .IF expr         Conditional assembly (.ELSE, .ENDIF)  
  .IFDEF symbol    Assemble if symbol defined  
  .IFNDEF symbol   Assemble if symbol not defined

EXPRESSION OPERATORS:  
  Arithmetic: \+ \- \* / %  
  Bitwise:    & | ^ \<\< \>\>  
  Comparison: \== \!= \< \> \<= \>=  
  Logical:    && ||  
  Special:    \< (low byte)  \> (high byte)  \* (current address)

NUMBER FORMATS:  
  Decimal:     42 or 255  
  Hexadecimal: $FF or 0xFF  
  Binary:      %11110000  
  Character:   'A' or '\\n'

EXAMPLES:  
  \# Run a program  
  ./tiny8vm hello.asm

  \# Disassemble without executing  
  ./tiny8vm program.asm \--disasm

  \# Run with trace and statistics  
  ./tiny8vm test.asm \--trace \--stats

  \# Create ROM image  
  ./tiny8vm \--makerom kernel.asm kernel.rom

  \# Execute ROM  
  ./tiny8vm \--rom kernel.rom

ROM REQUIREMENTS:  
  ROM images MUST define interrupt vectors at $FFFA-$FFFF:  
    .ORG $FFFA  
    .WORD nmi\_handler    ; NMI vector  
    .WORD reset\_handler  ; RESET vector (entry point)  
    .WORD irq\_handler    ; IRQ/BRK vector

For more information, see the documentation.

### 

## **Validation Test Suites**

The repository includes **four structured test suites**:

| Test Suite | Focus Areas | Coverage Highlights |
| :---- | :---- | :---- |
| **01** | Core ALU, stack, branches | ADC, SBC, CMP, INC/DEC, I/O (SYS) |
| **02** | Shift/rotate, flags, stack ops | ASL, LSR, ROL, ROR, BIT, PHP/PLP |
| **03** | Addressing modes, indirect ops | (zp),Y, (zp,X), ADC/SBC/AND variants |
| **04** | Flag edge cases, STX/STY | Zero/negative flag, carry logic, STX, STY, LDX/LDY |

Each test prints progress markers (1: OK, 2: OK, …) to confirm successful emulation.

###

## **Sample Assembly**

Code snippet

; helloworld.asm  
; Print "HELLO WORLD" followed by newline  
.org $0200  
start:  
        LDA \#$48    ; H  
        SYS \#$00  
        LDA \#$45    ; E  
        SYS \#$00  
        LDA \#$4C    ; L  
        SYS \#$00  
        LDA \#$4C    ; L  
        SYS \#$00  
        LDA \#$4F    ; O  
        SYS \#$00  
        LDA \#$20    ; space  
        SYS \#$00  
        LDA \#$57    ; W  
        SYS \#$00  
        LDA \#$4F    ; O  
        SYS \#$00  
        LDA \#$52    ; R  
        SYS \#$00  
        LDA \#$4C    ; L  
        SYS \#$00  
        LDA \#$44    ; D  
        SYS \#$00  
        LDA \#$0A    ; newline  
        SYS \#$00  
        BRK

###

## **Example Build & Run**

Bash

cc \-std=c11 \-O2 \-Wall \-Wextra \-Wpedantic \-Werror tiny8vm.c \-o tiny8vm

./tiny8vm helloworld.asm

###

## **License

This project is released under the **MIT License**.  
