/*
 * tiny8vm.c – Enhanced Educational 8-bit Virtual Machine
 *
 * New assembler features:
 *   - Local labels (.label syntax)
 *   - .FILL and .DS directives
 *   - Current address symbol (*)
 *   - Better error reporting with line context
 *
 * Build:
 *   cc -std=c11 -O2 -Wall -Wextra -Werror=implicit-function-declaration tiny8vm.c -o tiny8vm
 */

#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#if defined(__GNUC__) || defined(__clang__)
#  define UNUSED_FN __attribute__((unused))
#else
#  define UNUSED_FN
#endif

/* Portable fallbacks */
#ifndef HAVE_STRCASECMP
#if !defined(__APPLE__) && !defined(__linux__) && !defined(__unix__)
static int strcasecmp(const char* a, const char* b) {
    unsigned char ca, cb;
    while (*a && *b) {
        ca = (unsigned char)tolower((unsigned char)*a++);
        cb = (unsigned char)tolower((unsigned char)*b++);
        if (ca != cb) return (int)ca - (int)cb;
    }
    return (int)(unsigned char)tolower((unsigned char)*a) -
           (int)(unsigned char)tolower((unsigned char)*b);
}

static int strncasecmp(const char* a, const char* b, size_t n) {
    while (n-- && *a && *b) {
        int d = tolower((unsigned char)*a++) - tolower((unsigned char)*b++);
        if (d) return d;
    }
    return 0;
}
#endif
#endif


/* ======================================================= */
/* ======================= VM CORE ======================= */
/* ======================================================= */
#define RAM_SIZE 0x10000u
#define IO_START 0x8000u
#define IO_END   0xBFFFu
#define ROM_START 0xC000u

/* SECURITY: Resource limits to prevent DoS attacks */
#define MAX_EXECUTION_CYCLES 100000000ULL  /* 100 million cycles max */
#define MAX_MACRO_DEPTH 100                /* Maximum macro nesting depth */
#define MIN_STACK_POINTER 0x10             /* Stack overflow threshold */

typedef struct {
    uint8_t A, X, Y, SP, P;
    uint16_t PC;
    uint64_t cycles;
} CPU;

typedef struct {
    uint8_t mem[RAM_SIZE];
    int trace, disasm_only, debug, stats;
    CPU cpu;
    int irq_pending, nmi_pending, nmi_prev;
    uint64_t last_timer_cycle;
    uint16_t code_end;
} VM;

enum {
    FLAG_C = 1<<0, FLAG_Z = 1<<1, FLAG_I = 1<<2, FLAG_D = 1<<3,
    FLAG_B = 1<<4, FLAG_U = 1<<5, FLAG_V = 1<<6, FLAG_N = 1<<7
};

typedef enum {
    OP_NONE, OP_IMM, OP_ABS, OP_ABS_X, OP_ABS_Y, OP_ZP, OP_ZP_X, OP_ZP_Y, OP_INDZP_Y, OP_INDX_ZP
} Mode;

/* I/O registers */
#define REG_OUT     0x8000u
#define REG_IN      0x8001u
#define REG_TMR_CTL 0x8010u
#define REG_TMR_CNT 0x8011u
#define REG_NMI_TRG 0x8020u

/* Interrupt vectors */
#define VEC_NMI   0xFFFAu
#define VEC_RESET 0xFFFCu
#define VEC_IRQ   0xFFFEu

/* Syscalls */
enum {
    SYS_PUTCHAR = 0, SYS_GETCHAR = 1, SYS_PRINT = 2,
    SYS_READLN = 3, SYS_PUTNUM = 4, SYS_GETNUM = 5
};

/* Enhanced Label structure - now tracks scope */
typedef struct {
    char name[64];
    uint16_t addr;
    int is_local;           /* NEW: Is this a local label? */
    char scope[64];         /* NEW: Parent global label for locals */
} Label;

/* New Macro structure */
typedef struct {
    char name[64];
    char* body;           /* Macro body text */
    char params[8][32];   /* Parameter names */
    int param_count;
} Macro;

/* Add conditional assembly state tracking */
typedef struct {
    int active;      /* Is this block being assembled? */
    int has_else;    /* Has an .ELSE been seen? */
} CondState;


typedef struct {
    const char* mnem;
    uint8_t op_imm, op_abs, op_abs_x, op_abs_y, op_zp, op_zp_x, op_zp_y, op_indzp_y, op_indx_zp;
} Spec;

/* ISA Spec Table */
static const Spec SPECS[] = {
    /*         imm    abs    abs,X  abs,Y  zp     zp,X   zp,Y   (zp),Y (zp,X) */
    {"ADC",  0x69, 0x6D, 0x7D, 0x79, 0x65, 0x75, 0x00, 0x71, 0x61},
    {"AND",  0x29, 0x2D, 0x3D, 0x39, 0x25, 0x35, 0x00, 0x31, 0x21},
    {"ASL",  0x00, 0x0E, 0x1E, 0x00, 0x06, 0x16, 0x00, 0x00, 0x00},
    {"BIT",  0x00, 0x2C, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00},
    {"CLC",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"CLD",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  /* ADD THIS */    
    {"CLI",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"CMP",  0xC9, 0xCD, 0xDD, 0xD9, 0xC5, 0xD5, 0x00, 0xD1, 0xC1},
    {"CPX",  0xE0, 0xEC, 0x00, 0x00, 0xE4, 0x00, 0x00, 0x00, 0x00},
    {"CPY",  0xC0, 0xCC, 0x00, 0x00, 0xC4, 0x00, 0x00, 0x00, 0x00},
    {"DEC",  0x00, 0xCE, 0xDE, 0x00, 0xC6, 0xD6, 0x00, 0x00, 0x00},
    {"DEX",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"DEY",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"EOR",  0x49, 0x4D, 0x5D, 0x59, 0x45, 0x55, 0x00, 0x51, 0x41},
    {"INC",  0x00, 0xEE, 0xFE, 0x00, 0xE6, 0xF6, 0x00, 0x00, 0x00},
    {"INX",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"INY",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"JMP",  0x00, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"JNZ",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"JSR",  0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"JZ",   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"LDA",  0xA9, 0xAD, 0xBD, 0xB9, 0xA5, 0xB5, 0x00, 0xB1, 0xA1},
    {"LDX",  0xA2, 0xAE, 0xBE, 0x00, 0xA6, 0x00, 0xB6, 0x00, 0x00},
    {"LDY",  0xA0, 0xAC, 0xBC, 0x00, 0xA4, 0xB4, 0x00, 0x00, 0x00},
    {"LSR",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"NOP",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"ORA",  0x09, 0x0D, 0x1D, 0x19, 0x05, 0x15, 0x00, 0x11, 0x01},
    {"PHA",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"PHP",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"PLA",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"PLP",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"ROL",  0x00, 0x2E, 0x3E, 0x00, 0x26, 0x36, 0x00, 0x00, 0x00},
    {"ROR",  0x00, 0x6E, 0x7E, 0x00, 0x66, 0x76, 0x00, 0x00, 0x00},
    {"RTI",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"RTS",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"SBC",  0xE9, 0xED, 0xFD, 0xF9, 0xE5, 0xF5, 0x00, 0xF1, 0xE1},
    {"SEC",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"SED",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  /* ADD THIS */    
    {"SEI",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"STA",  0x00, 0x8D, 0x9D, 0x99, 0x85, 0x95, 0x00, 0x91, 0x81},
    {"STX",  0x00, 0x8E, 0x00, 0x00, 0x86, 0x00, 0x96, 0x00, 0x00},
    {"STY",  0x00, 0x8C, 0x00, 0x00, 0x84, 0x94, 0x00, 0x00, 0x00},
    {"SYS",  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TAX",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TAY",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TSX",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TXA",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TXS",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {"TYA",  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {NULL,   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};


/* Forward Declarations */
static void vm_reset(VM* vm, uint16_t entry);
static void vm_timer_tick(VM* vm);
static int validate_vm_state(VM* vm);
static void cpu_execute(VM* vm);
static int assemble(VM* vm, const char* src, uint16_t default_org);

static uint8_t r8(VM* vm, uint16_t a);
static void w8(VM* vm, uint16_t a, uint8_t v);
static void w8_raw(VM* vm, uint16_t a, uint8_t v);
static int eval_expr(const char* s, uint32_t* result, Label* labels, int nl, 
                     int line_num, char* err, uint16_t current_pc, const char* current_scope);
static int parse_imm8_ex(const char* s, uint8_t* out, Label* labels, int nl, 
                         int line_num, char* err, uint16_t current_pc, const char* current_scope);
static int parse_imm16(const char* s, uint16_t* out, Label* labels, int nl, 
                       char* err, uint16_t current_pc, const char* current_scope);

static int is_indzp_y(const char* s, uint8_t* zp, char* err, Label* labels, int nl, uint16_t current_pc, const char* current_scope);

static Mode detect_mode(const Spec* sp, const char* operand, char* err, Label* labels, int nl, uint16_t current_pc, const char* current_scope);
static void add_label(Label* labels, int* nl, const char* name, uint16_t addr, const char* current_scope);
// UNUSED static int resolve_label(const char* name, Label* labels, int nl, const char* current_scope, uint16_t* addr);
static Macro* find_macro(Macro* macros, int count, const char* name);
static char* expand_macro(Macro* macro, const char* args, int* expanded_lines_count);
// UNUSED static int eval_condition(const char* expr, Label* labels, int nl, uint16_t pc, const char* scope);
static char* read_include_file(const char* filename, char* err);

static char* slurp_file(const char* path);
static int load_rom(VM* vm, const char* path);
static int save_rom(VM* vm, const char* path, uint16_t start, uint16_t end);
static int load_and_run(VM* vm, const char* asm_src, int trace, int disasm_only, int debug, int stats);
static void print_help(const char* program_name);

/* Enhanced error reporting */
static void report_error(const char** lines, int line_num, const char* message) {
    fprintf(stderr, "\n*** Assembly Error at line %d ***\n", line_num);
    fprintf(stderr, "  %s\n", lines[line_num - 1]);
    fprintf(stderr, "  Error: %s\n\n", message);
}

/* Utility Functions */
static void trim(char* s) {
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i) memmove(s, s + i, n - i + 1);
}

static int parse_hex(const char* s, uint32_t* out) {
    char* end = NULL;
    if (s[0] == '$') {
        *out = (uint32_t)strtoul(s + 1, &end, 16);
        return end && *end == '\0';
    } else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        *out = (uint32_t)strtoul(s + 2, &end, 16);
        return end && *end == '\0';
    }
    return 0;  // Not a hex literal - let decimal parser handle it
}

static void strtoupper(char* s) {
    for (; *s; ++s) *s = (char)toupper((unsigned char)*s);
}

/* SECURITY FIX: Safe stack operations with overflow/underflow detection */
static inline int stack_push(VM* vm, uint8_t value) {
    CPU* cpu = &vm->cpu;
    /* Check for stack underflow (wrapping below page 1) */
    if (cpu->SP < MIN_STACK_POINTER) {
        fprintf(stderr, "\n*** SECURITY: Stack underflow detected ***\n");
        fprintf(stderr, "SP=$%02X (minimum=$%02X)\n", cpu->SP, MIN_STACK_POINTER);
        fprintf(stderr, "PC=$%04X A=$%02X X=$%02X Y=$%02X\n",
                cpu->PC, cpu->A, cpu->X, cpu->Y);
        return 0;  /* Failure */
    }
    vm->mem[0x100 | cpu->SP] = value;
    cpu->SP--;
    return 1;  /* Success */
}

static inline int stack_pop(VM* vm, uint8_t* value) {
    CPU* cpu = &vm->cpu;
    /* Check for stack overflow (wrapping above page 1) */
    if (cpu->SP >= 0xFF) {
        fprintf(stderr, "\n*** SECURITY: Stack overflow detected ***\n");
        fprintf(stderr, "SP=$%02X\n", cpu->SP);
        fprintf(stderr, "PC=$%04X A=$%02X X=$%02X Y=$%02X\n",
                cpu->PC, cpu->A, cpu->X, cpu->Y);
        return 0;  /* Failure */
    }
    cpu->SP++;
    *value = vm->mem[0x100 | cpu->SP];
    return 1;  /* Success */
}

static int parse_decimal(const char* s, long* out) {
    char* end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    /* SECURITY FIX: Validate range to prevent sign extension issues */
    if (errno != 0 || end == s || *end != '\0') return 0;
    if (v < 0 || v > 0xFFFF) return 0;  /* Must fit in 16 bits unsigned */
    *out = v;
    return 1;
}

/* VM Memory Helpers */
static UNUSED_FN uint8_t r8(VM* vm, uint16_t a) {
    // Handle memory-mapped I/O reads
    if (a == REG_IN) {
        // Read from input register
        // For now, return 0 (no input available)
        return 0;
    }
    
    // Normal memory read
    return vm->mem[a];
}

static void w8(VM* vm, uint16_t a, uint8_t v) {
    if (a >= ROM_START && a < 0xFFFA) return;
    
    if (a == REG_OUT) {
        fputc((int)v, stdout);
        fflush(stdout);
        return;
    }

    if (a == REG_TMR_CTL) {
        vm->mem[REG_TMR_CTL] = (uint8_t)(v ? 1 : 0);
        return;
    }

    if (a == REG_NMI_TRG) {
        if (!vm->nmi_prev && v) {
            vm->nmi_pending = 1;
        }
        vm->nmi_prev = v ? 1 : 0;
        return;
    }
    
    vm->mem[a] = v;
}

static void w8_raw(VM* vm, uint16_t a, uint8_t v) {
    vm->mem[a] = v;
    if (a > vm->code_end) vm->code_end = a;
}

/* Assembler Parsing Helpers */
static const Spec* find_spec(const char* mnem) {
    for (int i=0; SPECS[i].mnem; i++) {
        if (strcasecmp(SPECS[i].mnem, mnem) == 0) return &SPECS[i];
    }
    return NULL;
}

static uint8_t opcode_for_mode(const Spec* sp, Mode m) {
    switch (m) {
        case OP_IMM:     return sp->op_imm;
        case OP_ABS:     return sp->op_abs;
        case OP_ABS_X:   return sp->op_abs_x;
        case OP_ABS_Y:   return sp->op_abs_y;
        case OP_ZP:      return sp->op_zp;
        case OP_ZP_X:    return sp->op_zp_x;
        case OP_ZP_Y:    return sp->op_zp_y;
        case OP_INDZP_Y: return sp->op_indzp_y;
        case OP_INDX_ZP: return sp->op_indx_zp;
        default:         return 0;
    }
}

static int eval_expr(const char* s, uint32_t* result, Label* labels, int nl, 
                     int line_num, char* err, uint16_t current_pc, const char* current_scope) {
    
    char expr[256];
    strncpy(expr, s, sizeof(expr)-1);
    expr[sizeof(expr)-1] = '\0';
    trim(expr);
        
    const char* parse = expr;
    if (parse[0] == '#') parse++;
        
    /* Handle current address symbol */
    if (strcmp(parse, "*") == 0) {
        *result = current_pc;
        return 1;
    }
    
    /* Handle low/high byte operators */
    if (parse[0] == '<') {
        uint32_t val;
        if (!eval_expr(parse + 1, &val, labels, nl, line_num, err, current_pc, current_scope)) return 0;
        *result = val & 0xFF;
        return 1;
    }
    if (parse[0] == '>') {
        uint32_t val;
        if (!eval_expr(parse + 1, &val, labels, nl, line_num, err, current_pc, current_scope)) return 0;
        *result = (val >> 8) & 0xFF;
        return 1;
    }
    
    /* Handle parentheses */
    if (parse[0] == '(' && parse[strlen(parse)-1] == ')') {
        char inner[256];
        strncpy(inner, parse + 1, sizeof(inner)-1);
        inner[sizeof(inner)-1] = '\0';
        inner[strlen(inner)-1] = '\0';
        return eval_expr(inner, result, labels, nl, line_num, err, current_pc, current_scope);
    }
    
    /* Try to find operators - ORDERED BY PRECEDENCE (lowest to highest) */
    /* Comparison operators (lowest precedence) */
    const char* comp_ops[] = {"==", "!=", "<=", ">=", "<", ">", NULL};
    /* Logical operators */
    const char* logic_ops[] = {"||", "&&", NULL};
    /* Bitwise operators */
    const char* bit_ops[] = {"|", "^", "&", NULL};
    /* Shift operators */
    const char* shift_ops[] = {"<<", ">>", NULL};
    /* Arithmetic operators */
    const char* arith_ops[] = {"+", "-", NULL};
    const char* mult_ops[] = {"*", "/", "%", NULL};
    
    /* Array of operator groups in precedence order (lowest to highest) */
    const char** op_groups[] = {comp_ops, logic_ops, bit_ops, shift_ops, arith_ops, mult_ops, NULL};
    
    for (int group = 0; op_groups[group]; group++) {
        for (int op_idx = 0; op_groups[group][op_idx]; op_idx++) {
            const char* op = op_groups[group][op_idx];
            size_t op_len = strlen(op);
            int paren_depth = 0;
            int found_pos = -1;

            /* Search right-to-left for operator at depth 0 */
            for (int i = strlen(parse) - 1; i >= 0; i--) {
                if (parse[i] == ')') paren_depth++;
                else if (parse[i] == '(') paren_depth--;
                else if (paren_depth == 0 && strncmp(parse + i, op, op_len) == 0) {
                    /* Skip if operator is part of a symbol name */
                    if (i > 0 && (isalnum((unsigned char)parse[i-1]) || parse[i-1] == '_')) continue;
                    
                    /* For single-char operators, make sure we're not matching the start of a two-char op */
                    if (op_len == 1) {
                        /* Skip if this single-char op is part of a two-char operator */
                        if (i > 0) {
                            char prev = parse[i-1];
                            char curr = parse[i];
                            if ((prev == '=' || prev == '!' || prev == '<' || prev == '>') && curr == '=') continue;
                            if ((prev == '|' && curr == '|') || (prev == '&' && curr == '&')) continue;
                            if ((prev == '<' && curr == '<') || (prev == '>' && curr == '>')) continue;
                        }
                        if (i + 1 < (int)strlen(parse)) {
                            char curr = parse[i];
                            char next = parse[i+1];
                            if ((curr == '=' || curr == '!' || curr == '<' || curr == '>') && next == '=') continue;
                            if ((curr == '|' && next == '|') || (curr == '&' && next == '&')) continue;
                            if ((curr == '<' && next == '<') || (curr == '>' && next == '>')) continue;
                        }
                    }
                    
                    /* complier fatal error: implicit conversion changes */
                    if (parse[i + op_len] == '\0') continue;
                    
                    // double type cast to remove compiler eror
                    // if (parse[(size_t)((unsigned int)(i) + op_len)] == '\0') continue;
                    
                    found_pos = i;
                    break;
                }
            }
            
            if (found_pos >= 0) {
                char left[256], right[256];
                strncpy(left, parse, found_pos);
                left[found_pos] = '\0';
                strcpy(right, parse + found_pos + op_len);
                
                uint32_t lval, rval;
                if (!eval_expr(left, &lval, labels, nl, line_num, err, current_pc, current_scope)) return 0;
                if (!eval_expr(right, &rval, labels, nl, line_num, err, current_pc, current_scope)) return 0;
                
                /* Handle operators */
                if (strcmp(op, "==") == 0) { *result = (lval == rval) ? 1 : 0; return 1; }
                if (strcmp(op, "!=") == 0) { *result = (lval != rval) ? 1 : 0; return 1; }
                if (strcmp(op, "<=") == 0) { *result = (lval <= rval) ? 1 : 0; return 1; }
                if (strcmp(op, ">=") == 0) { *result = (lval >= rval) ? 1 : 0; return 1; }
                if (strcmp(op, "<") == 0) { *result = (lval < rval) ? 1 : 0; return 1; }
                if (strcmp(op, ">") == 0) { *result = (lval > rval) ? 1 : 0; return 1; }
                if (strcmp(op, "||") == 0) { *result = (lval || rval) ? 1 : 0; return 1; }
                if (strcmp(op, "&&") == 0) { *result = (lval && rval) ? 1 : 0; return 1; }
                if (strcmp(op, "|") == 0) { *result = lval | rval; return 1; }
                if (strcmp(op, "^") == 0) { *result = lval ^ rval; return 1; }
                if (strcmp(op, "&") == 0) { *result = lval & rval; return 1; }
                if (strcmp(op, "<<") == 0) { *result = lval << rval; return 1; }
                if (strcmp(op, ">>") == 0) { *result = lval >> rval; return 1; }
                if (strcmp(op, "+") == 0) { *result = lval + rval; return 1; }
                if (strcmp(op, "-") == 0) { *result = lval - rval; return 1; }
                if (strcmp(op, "*") == 0) { *result = lval * rval; return 1; }
                if (strcmp(op, "/") == 0) {
                    if (rval == 0) { snprintf(err, 128, "division by zero"); return 0; }
                    *result = lval / rval; 
                    return 1;
                }
                if (strcmp(op, "%") == 0) {
                    if (rval == 0) { snprintf(err, 128, "modulo by zero"); return 0; }
                    *result = lval % rval;
                    return 1;
                }
            }
        }
    }
    
    /* Binary literal */
    if (parse[0] == '%') {
        *result = 0;
        for (const char* p = parse + 1; *p; p++) {
            if (*p == '0' || *p == '1') {
                *result = (*result << 1) | (*p - '0');
            } else {
                snprintf(err, 128, "invalid binary literal '%s'", parse);
                return 0;
            }
        }
        return 1;
    }
    
    /* Hex literal */
    uint32_t hv;
    if (parse_hex(parse, &hv)) {
        *result = hv;
        return 1;
    }
    
    /* Decimal literal */
    long dv;
    if (parse_decimal(parse, &dv)) {
        *result = (uint32_t)dv;
        return 1;
    }
    
    /* Label lookup */
    char buf[96];
    strncpy(buf, parse, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    strtoupper(buf);

    char search_name[128];
    if (buf[0] == '.' && current_scope && current_scope[0]) {
        snprintf(search_name, sizeof(search_name), "%s%s", current_scope, buf);
    } else {
        strncpy(search_name, buf, sizeof(search_name)-1);
        search_name[sizeof(search_name)-1] = '\0';
    }

    for (int i = 0; i < nl; i++) {
        if (strcmp(labels[i].name, search_name) == 0) {
            *result = labels[i].addr;
            return 1;
        }
    }

    snprintf(err, 128, "unknown symbol '%s'", parse);
    return 0;
}


static int parse_imm8_ex(const char* s, uint8_t* out, Label* labels, int nl, 
                         int line_num, char* err, uint16_t current_pc, const char* current_scope) {
    if (!s || !*s) { snprintf(err, 128, "missing immediate"); return 0; }
    
    /* Handle character literals */
    if (s[0] == '\'') {
        if (!s[1] || !s[2] || s[2] != '\'') {
            snprintf(err, 128, "bad character literal '%s'", s);
            return 0;
        }
        if (s[1] == '\\') {
            if (!s[2] || !s[3] || s[3] != '\'') {
                snprintf(err, 128, "bad escape in character literal '%s'", s);
                return 0;
            }
            switch (s[2]) {
                case 'n': *out = '\n'; break;
                case 't': *out = '\t'; break;
                case 'r': *out = '\r'; break;
                case '0': *out = '\0'; break;
                case '\\': *out = '\\'; break;
                case '\'': *out = '\''; break;
                default: *out = s[2]; break;
            }
        } else {
            *out = (uint8_t)s[1];
        }
        return 1;
    }
    
    uint32_t val;
    if (!eval_expr(s, &val, labels, nl, line_num, err, current_pc, current_scope)) return 0;
    
    if (val > 0xFF) {
        snprintf(err, 128, "immediate too large: %u", val);
        return 0;
    }
    
    *out = (uint8_t)val;
    return 1;
}

static int parse_imm16(const char* s, uint16_t* out, Label* labels, int nl, 
                       char* err, uint16_t current_pc, const char* current_scope) {
    if (!s || !*s) { snprintf(err, 128, "missing address"); return 0; }
    
    uint32_t val;
    if (!eval_expr(s, &val, labels, nl, 0, err, current_pc, current_scope)) return 0;
    
    if (val > 0xFFFF) {
        snprintf(err, 128, "address too large: %u", val);
        return 0;
    }
    
    *out = (uint16_t)val;
    return 1;
}

static int is_indx_zp(const char* s, uint8_t* zp, char* err, Label* labels, int nl, uint16_t current_pc, const char* current_scope) {
    (void)current_pc;
    (void)current_scope;
    if (!s) { snprintf(err,128,"operand missing"); return 0; }
    char buf[128]; strncpy(buf, s, sizeof(buf)-1); buf[sizeof(buf)-1]='\0'; trim(buf);
    size_t n = strlen(buf);
    if (n < 6) { snprintf(err,128,"bad ($zz,X) syntax"); return 0; }
    if (buf[0] != '(') { snprintf(err,128,"expected '(' for indirect"); return 0; }
    char* rp = strchr(buf, ')');
    if (!rp) { snprintf(err,128,"missing ')'"); return 0; }
    
    // Find comma before )
    char* comma = strchr(buf, ',');
    if (!comma || comma > rp) { snprintf(err,128,"expected ',X' inside parens"); return 0; }
    
    // Check for ,X
    char* idx = comma + 1;
    while (isspace((unsigned char)*idx)) idx++;
    if (*idx != 'X' && *idx != 'x') { snprintf(err,128,"expected X after comma"); return 0; }
    idx++;
    while (isspace((unsigned char)*idx)) idx++;
    if (idx != rp) { snprintf(err,128,"unexpected characters after X"); return 0; }

    char inner[96];
    size_t ilen = (size_t)(comma - (buf + 1));
    if (ilen >= sizeof(inner)) ilen = sizeof(inner)-1;
    memcpy(inner, buf + 1, ilen);
    inner[ilen] = '\0';
    trim(inner);

    uint32_t hv=0;
    if (parse_hex(inner, &hv)) {
        if (hv>0xFF) { snprintf(err,128,"zero-page index too large $%X", hv); return 0; }
        *zp=(uint8_t)hv; return 1;
    }
    long dv=0;
    if (parse_decimal(inner, &dv)) {
        if (dv<0 || dv>255) { snprintf(err,128,"zero-page index out of range %ld", dv); return 0; }
        *zp=(uint8_t)dv; return 1;
    }
    
    strtoupper(inner);
    for (int i = 0; i < nl; i++) {
        if (strcmp(labels[i].name, inner) == 0) {
            if (labels[i].addr > 0xFF) {
                snprintf(err,128,"label '%s' not in zero-page (0x%04X)", inner, labels[i].addr);
                return 0;
            }
            *zp = (uint8_t)labels[i].addr;
            return 1;
        }
    }
    snprintf(err,128,"unknown zp label '%s'", inner);
    return 0;
}


static int is_indzp_y(const char* s, uint8_t* zp, char* err, Label* labels, int nl, uint16_t current_pc, const char* current_scope) {
    (void)current_pc;     // Supress warning of unused parameter
    (void)current_scope;  // Supress warning of unused parameter
    if (!s) { snprintf(err,128,"operand missing"); return 0; }
    char buf[128]; strncpy(buf, s, sizeof(buf)-1); buf[sizeof(buf)-1]='\0'; trim(buf);
    size_t n = strlen(buf);
    if (n < 6) { snprintf(err,128,"bad ($zz),Y syntax"); return 0; }
    if (buf[0] != '(') { snprintf(err,128,"expected '(' for indirect"); return 0; }
    char* rp = strchr(buf, ')');
    if (!rp) { snprintf(err,128,"missing ')'"); return 0; }
    if (rp[1] != ',' || (rp[2] != 'Y' && rp[2] != 'y')) { snprintf(err,128,"expected ',Y'"); return 0; }

    char inner[96];
    size_t ilen = (size_t)(rp - (buf + 1));
    if (ilen >= sizeof(inner)) ilen = sizeof(inner)-1;
    memcpy(inner, buf + 1, ilen);
    inner[ilen] = '\0';
    trim(inner);

    uint32_t hv=0;
    if (parse_hex(inner, &hv)) {
        if (hv>0xFF) { snprintf(err,128,"zero-page index too large $%X", hv); return 0; }
        *zp=(uint8_t)hv; return 1;
    }
    long dv=0;
    if (parse_decimal(inner, &dv)) {
        if (dv<0 || dv>255) { snprintf(err,128,"zero-page index out of range %ld", dv); return 0; }
        *zp=(uint8_t)dv; return 1;
    }
    
    strtoupper(inner);
    for (int i = 0; i < nl; i++) {
        if (strcmp(labels[i].name, inner) == 0) {
            if (labels[i].addr > 0xFF) {
                snprintf(err,128,"label '%s' not in zero-page (0x%04X)", inner, labels[i].addr);
                return 0;
            }
            *zp = (uint8_t)labels[i].addr;
            return 1;
        }
    }
    snprintf(err,128,"unknown zp label '%s'", inner);
    return 0;
}

static Mode detect_mode(const Spec* sp, const char* operand, char* err, Label* labels, int nl, uint16_t current_pc, const char* current_scope) {
    if (!operand) return OP_NONE;

    char buf[128];
    strncpy(buf, operand, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim(buf);
    if (!*buf) return OP_NONE;

    if (!strcasecmp(sp->mnem, "JMP") || !strcasecmp(sp->mnem, "JSR")) {
        if (!sp->op_abs) {
            snprintf(err, 128, "Instruction %s requires absolute addressing", sp->mnem);
            return OP_NONE;
        }
        return OP_ABS;
    }

    if (buf[0] == '#') {
        if (!sp->op_imm) { 
            snprintf(err,128,"Instruction %s doesn't support immediate", sp->mnem); 
            return OP_NONE; 
        }
        return OP_IMM;
    }

    // Check for indexed indirect ($zp,X)
    {
        uint8_t dummy;
        char temp_err[128] = {0};
        if (is_indx_zp(buf, &dummy, temp_err, labels, nl, current_pc, current_scope)) {
            if (!sp->op_indx_zp) { 
                snprintf(err,128,"Instruction %s doesn't support ($zz,X)", sp->mnem); 
                return OP_NONE; 
            }
            return OP_INDX_ZP;
        }
    }

    // Check for indirect indexed ($zp),Y
    {
        uint8_t dummy;
        char temp_err[128] = {0};
        if (is_indzp_y(buf, &dummy, temp_err, labels, nl, current_pc, current_scope)) {
            if (!sp->op_indzp_y) { 
                snprintf(err,128,"Instruction %s doesn't support ($zz),Y", sp->mnem); 
                return OP_NONE; 
            }
            return OP_INDZP_Y;
        }
    }

    // Check for indexed addressing (,X or ,Y)
    char* comma = strrchr(buf, ',');
    if (comma) {
        *comma = '\0';
        char* base = buf;
        char* reg  = comma + 1;
        trim(base); trim(reg);
        strtoupper(reg);

        if (strcmp(reg, "X") == 0) {
            uint32_t hv;
            if (parse_hex(base, &hv)) {
                if (hv <= 0xFF) {
                    if (!sp->op_zp_x) { 
                        if (sp->op_abs_x) return OP_ABS_X;
                        snprintf(err,128,"no ZP,X form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ZP_X;
                } else {
                    if (!sp->op_abs_x) { 
                        snprintf(err,128,"no ABS,X form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ABS_X;
                }
            }
            
            char up[96]; strncpy(up, base, sizeof(up)-1); up[sizeof(up)-1]='\0'; strtoupper(up);
            for (int i=0;i<nl;i++) {
                if (strcmp(labels[i].name, up)==0) {
                    if (labels[i].addr <= 0x00FFu) {
                        if (!sp->op_zp_x) { 
                            if (sp->op_abs_x) return OP_ABS_X;
                            snprintf(err,128,"no ZP,X form for this instruction"); 
                            return OP_NONE; 
                        }
                        return OP_ZP_X;
                    } else {
                        if (!sp->op_abs_x) { 
                            snprintf(err,128,"no ABS,X form for this instruction"); 
                            return OP_NONE; 
                        }
                        return OP_ABS_X;
                    }
                }
            }
            
            if (sp->op_abs_x) return OP_ABS_X;
            if (sp->op_zp_x)  return OP_ZP_X;
            snprintf(err,128,"unknown symbol '%s' for ,X", base);
            return OP_NONE;
            
        } else if (strcmp(reg, "Y") == 0) {
            uint32_t hv;
            if (parse_hex(base, &hv)) {
                if (hv <= 0xFF) {
                    if (!sp->op_zp_y) { 
                        if (sp->op_abs_y) return OP_ABS_Y;
                        snprintf(err,128,"no ZP,Y form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ZP_Y;
                } else {
                    if (!sp->op_abs_y) { 
                        snprintf(err,128,"no ABS,Y form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ABS_Y;
                }
            }
            
            char up[96]; strncpy(up, base, sizeof(up)-1); up[sizeof(up)-1]='\0'; strtoupper(up);
            for (int i=0;i<nl;i++) {
                if (strcmp(labels[i].name, up)==0) {
                    if (labels[i].addr <= 0x00FFu) {
                        if (!sp->op_zp_y) { 
                            if (sp->op_abs_y) return OP_ABS_Y;
                            snprintf(err,128,"no ZP,Y form for this instruction"); 
                            return OP_NONE; 
                        }
                        return OP_ZP_Y;
                    } else {
                        if (!sp->op_abs_y) { 
                            snprintf(err,128,"no ABS,Y form for this instruction"); 
                            return OP_NONE; 
                        }
                        return OP_ABS_Y;
                    }
                }
            }
            
            if (sp->op_abs_y) return OP_ABS_Y;
            if (sp->op_zp_y)  return OP_ZP_Y;
            snprintf(err,128,"unknown symbol '%s' for ,Y", base);
            return OP_NONE;
            
        } else {
            snprintf(err,128,"unknown index register '%s'", reg);
            return OP_NONE;
        }
    }

    // Non-indexed addressing
    uint32_t hv;
    if (parse_hex(buf, &hv)) {
        if (hv <= 0xFF) {
            if (!sp->op_zp) { 
                if (sp->op_abs) return OP_ABS;
                snprintf(err,128,"no ZP form for this instruction"); 
                return OP_NONE; 
            }
            return OP_ZP;
        } else {
            if (!sp->op_abs) { 
                snprintf(err,128,"no ABS form for this instruction"); 
                return OP_NONE; 
            }
            return OP_ABS;
        }
    }

    {
        char up[96]; strncpy(up, buf, sizeof(up)-1); up[sizeof(up)-1]='\0'; strtoupper(up);
        for (int i=0;i<nl;i++) {
            if (strcmp(labels[i].name, up)==0) {
                if (labels[i].addr <= 0x00FFu) {
                    if (!sp->op_zp) { 
                        if (sp->op_abs) return OP_ABS;
                        snprintf(err,128,"no ZP form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ZP;
                } else {
                    if (!sp->op_abs) { 
                        snprintf(err,128,"no ABS form for this instruction"); 
                        return OP_NONE; 
                    }
                    return OP_ABS;
                }
            }
        }
    }

    if (sp->op_abs) return OP_ABS;
    snprintf(err,128,"unknown symbol '%s'", buf);
    return OP_NONE;
}

/* Add label with scope tracking */
static void add_label(Label* labels, int* nl, const char* name, uint16_t addr, const char* current_scope) {
    char up[64]; 
    strncpy(up, name, sizeof(up)-1); 
    up[sizeof(up)-1]='\0'; 
    strtoupper(up);
    
    int is_local = (up[0] == '.');
    
    /* Build full name for local labels */
    char full_name[128];
    if (is_local && current_scope && current_scope[0]) {
        snprintf(full_name, sizeof(full_name), "%s%s", current_scope, up);
    } else {
        strncpy(full_name, up, sizeof(full_name)-1);
        full_name[sizeof(full_name)-1] = '\0';
    }
    
    /* Check if label already exists and update it */
    for (int i=0; i<*nl; i++) {
        if (strcmp(labels[i].name, full_name)==0) { 
            labels[i].addr=addr; 
            return; 
        }
    }
    
    /* Add new label */
    if (*nl < 1024) {
        strncpy(labels[*nl].name, full_name, sizeof(labels[*nl].name)-1);
        labels[*nl].name[sizeof(labels[*nl].name)-1]='\0';
        labels[*nl].addr = addr;
        labels[*nl].is_local = is_local;
        if (current_scope) {
            strncpy(labels[*nl].scope, current_scope, sizeof(labels[*nl].scope)-1);
            labels[*nl].scope[sizeof(labels[*nl].scope)-1] = '\0';
        } else {
            labels[*nl].scope[0] = '\0';
        }
        (*nl)++;
    }
}

/* // UNSED: Resolve label with scope
static UNUSED_FN int resolve_label(const char* name, Label* labels, int nl, const char* current_scope, uint16_t* addr) {
    char up[64];
    strncpy(up, name, sizeof(up)-1);
    up[sizeof(up)-1] = '\0';
    strtoupper(up);
    
    // If it's a local label reference, prepend current scope
    char search_name[128];
    if (up[0] == '.' && current_scope && current_scope[0]) {
        snprintf(search_name, sizeof(search_name), "%s%s", current_scope, up);
    } else {
        strncpy(search_name, up, sizeof(search_name)-1);
        search_name[sizeof(search_name)-1] = '\0';
    }
    
    // Search for the label
    for (int i = 0; i < nl; i++) {
        if (strcmp(labels[i].name, search_name) == 0) {
            *addr = labels[i].addr;
            return 1;
        }
    }
    
    return 0;
} */

/* Helper function to find a macro */
static Macro* find_macro(Macro* macros, int count, const char* name) {
    char upper[64];
    strncpy(upper, name, sizeof(upper)-1);
    upper[sizeof(upper)-1] = '\0';
    strtoupper(upper);
    
    for (int i = 0; i < count; i++) {
        if (strcmp(macros[i].name, upper) == 0) {
            return &macros[i];
        }
    }
    return NULL;
}

/* Helper to expand a macro call */
static char* expand_macro(Macro* macro, const char* args, int* expanded_lines_count) {
    /* Parse arguments */
    char* arg_values[8] = {0};
    int arg_count = 0;
    
    if (args && *args) {
        char args_copy[512];
        strncpy(args_copy, args, sizeof(args_copy)-1);
        args_copy[sizeof(args_copy)-1] = '\0';
        
        char* token = strtok(args_copy, ",");
        while (token && arg_count < 8) {
            trim(token);
            arg_values[arg_count++] = strdup(token);
            token = strtok(NULL, ",");
        }
    }
    
    if (arg_count != macro->param_count) {
        for (int i = 0; i < arg_count; i++) free(arg_values[i]);
        return NULL;
    }
    
    /* Expand macro body by substituting parameters */
    size_t body_len = strlen(macro->body);
    size_t result_size = body_len * 2 + 1024;  /* Extra space for expansion */
    char* result = (char*)malloc(result_size);
    result[0] = '\0';
    
    const char* src = macro->body;
    char* dst = result;
    size_t remaining = result_size;
    
    while (*src) {
        int matched = 0;
        
        /* Check if we're at a parameter name */
        for (int i = 0; i < macro->param_count; i++) {
            size_t plen = strlen(macro->params[i]);
            if (strncmp(src, macro->params[i], plen) == 0 &&
                !isalnum((unsigned char)src[plen]) && src[plen] != '_') {
                
                /* Substitute the parameter */
                size_t vlen = strlen(arg_values[i]);
                if (vlen < remaining) {
                    strcpy(dst, arg_values[i]);
                    dst += vlen;
                    remaining -= vlen;
                }
                src += plen;
                matched = 1;
                break;
            }
        }
        
        if (!matched) {
            if (remaining > 1) {
                *dst++ = *src++;
                remaining--;
            } else {
                break;
            }
        }
    }
    *dst = '\0';
    
    /* Count lines in expanded macro */
    *expanded_lines_count = 1;
    for (char* p = result; *p; p++) {
        if (*p == '\n') (*expanded_lines_count)++;
    }
    
    /* Free argument copies */
    for (int i = 0; i < arg_count; i++) free(arg_values[i]);
    
    return result;
}

/* // Helper to evaluate conditional expressions
static UNUSED_FN int eval_condition(const char* expr, Label* labels, int nl, uint16_t pc, const char* scope) {
    uint32_t result;
    char err[128];
    if (!eval_expr(expr, &result, labels, nl, 0, err, pc, scope)) {
        return 0;  // Treat undefined as false
    }
    return result != 0;
} */

/* SECURITY FIX: Validate include file path to prevent path traversal attacks */
static int validate_include_path(const char* filename, char* err) {
    if (!filename || !*filename) {
        snprintf(err, 128, "empty filename not allowed");
        return 0;
    }

    /* Reject absolute paths */
    if (filename[0] == '/' || filename[0] == '\\') {
        snprintf(err, 128, "absolute paths not allowed in .INCLUDE");
        return 0;
    }

    /* Check for Windows drive letters (C:, D:, etc.) */
    if (filename[1] == ':' && isalpha((unsigned char)filename[0])) {
        snprintf(err, 128, "absolute paths not allowed in .INCLUDE");
        return 0;
    }

    /* Reject path traversal sequences */
    const char* p = filename;
    while (*p) {
        if (p[0] == '.' && p[1] == '.') {
            /* Check if it's actually "../" or "..\\" */
            if (p[2] == '/' || p[2] == '\\' || p[2] == '\0') {
                snprintf(err, 128, "path traversal (..) not allowed in .INCLUDE");
                return 0;
            }
        }
        p++;
    }

    /* Reject paths with null bytes (path injection) */
    size_t len = strlen(filename);
    for (size_t i = 0; i < len; i++) {
        if (filename[i] == '\0') {
            snprintf(err, 128, "null bytes in path not allowed");
            return 0;
        }
    }

    /* Limit path length */
    if (len > 255) {
        snprintf(err, 128, "path too long (max 255 characters)");
        return 0;
    }

    return 1;
}

/* Read and include file contents */
static char* read_include_file(const char* filename, char* err) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        snprintf(err, 128, "cannot open include file '%.80s'", filename);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* SECURITY FIX: Validate file size to prevent buffer overflow and resource exhaustion */
    #define MAX_INCLUDE_SIZE (2 * 1024 * 1024)  /* 2MB maximum for include files */
    if (len < 0) {
        fclose(f);
        snprintf(err, 128, "cannot determine size of '%.80s'", filename);
        return NULL;
    }
    if (len > MAX_INCLUDE_SIZE) {
        fclose(f);
        snprintf(err, 128, "include file '%.80s' too large (%ld bytes, max %d)",
                 filename, len, MAX_INCLUDE_SIZE);
        return NULL;
    }

    /* SECURITY FIX: Check for integer overflow before malloc */
    if (len >= LONG_MAX - 1) {
        fclose(f);
        snprintf(err, 128, "file size would cause integer overflow");
        return NULL;
    }

    char* buf = (char*)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        snprintf(err, 128, "out of memory reading '%.80s'", filename);
        return NULL;
    }

    size_t bytes_read = fread(buf, 1, (size_t)len, f);
    if (bytes_read != (size_t)len) {
        free(buf);
        fclose(f);
        snprintf(err, 128, "failed to read complete file '%.80s'", filename);
        return NULL;
    }

    buf[len] = '\0';
    fclose(f);

    return buf;
}

/* ============================================================ */
/* ============== ENHANCED TWO-PASS ASSEMBLER ================= */
/* ============================================================ */

static int assemble(VM* vm, const char* src, uint16_t default_org) {

    /* Split source into lines, handling .INCLUDE directives */
    char* copy = strdup(src);
    if (!copy) return 0;

    int cap = 1024, nlines = 0;
    char** lines = (char**)malloc(sizeof(char*) * cap);
    if (!lines) { free(copy); return 0; }

    /* at the beginning of the assemble() function, add these variables */
    Macro macros[64];
    int macro_count = 0;
    CondState cond_stack[16];
    int cond_depth = 0;

    /* SECURITY FIX: Track total macro expansions to prevent resource exhaustion */
    int total_macro_expansions = 0;
    const int MAX_MACRO_EXPANSIONS = 10000;  /* Limit total expansions */


    /* First pass: split into lines and expand .INCLUDE */
    for (char* s = strtok(copy, "\n"); s; s = strtok(NULL, "\n")) {
        /* Check for .INCLUDE directive */
        char check[512];
        strncpy(check, s, sizeof(check)-1);
        check[sizeof(check)-1] = '\0';
        trim(check);
        
        /* Remove comments for checking */
        char* semi = strchr(check, ';');
        if (semi) *semi = '\0';
        trim(check);
        
        if (strncasecmp(check, ".INCLUDE", 8) == 0) {
            char* p = check + 8;
            trim(p);
            
            /* Extract filename (remove quotes if present) */
            char filename[256];
            if (p[0] == '"') {
                char* end = strchr(p + 1, '"');
                if (!end) {
                    fprintf(stderr, "Error: .INCLUDE missing closing quote\n");
                    free(lines); free(copy); return 0;
                }
                size_t len = end - (p + 1);
                if (len >= sizeof(filename)) len = sizeof(filename) - 1;
                memcpy(filename, p + 1, len);
                filename[len] = '\0';
            } else {
                strncpy(filename, p, sizeof(filename)-1);
                filename[sizeof(filename)-1] = '\0';
            }

            /* SECURITY FIX: Validate path before including file */
            char err[128];
            if (!validate_include_path(filename, err)) {
                fprintf(stderr, "Error: .INCLUDE security violation - %s\n", err);
                free(lines); free(copy); return 0;
            }

            /* Read and include the file */
            char* included = read_include_file(filename, err);
            if (!included) {
                fprintf(stderr, "Error: %s\n", err);
                free(lines); free(copy); return 0;
            }
            
            /* Split included file into lines */
            char* inc_copy = strdup(included);
            free(included);
            for (char* inc_line = strtok(inc_copy, "\n"); inc_line; inc_line = strtok(NULL, "\n")) {
                if (nlines == cap) {
                    cap *= 2;
                    char** t = (char**)realloc(lines, sizeof(char*) * cap);
                    if (!t) { free(inc_copy); free(lines); free(copy); return 0; }
                    lines = t;
                }
                lines[nlines++] = strdup(inc_line);
            }
            free(inc_copy);
        } else {
            /* Normal line */
            if (nlines == cap) {
                cap *= 2;
                char** t = (char**)realloc(lines, sizeof(char*) * cap);
                if (!t) { free(lines); free(copy); return 0; }
                lines = t;
            }
            lines[nlines++] = strdup(s);
        }
    }


    Label labels[1024]; 
    int label_count = 0;
    uint16_t pc = default_org ? default_org : 0x0200;
    
    /* NEW: Track current scope for local labels */
    char current_scope[64] = {0};

    /* =========================================================== */
    /* ================= PASS 1: labels + sizing ================= */
    /* =========================================================== */
    
    for (int i = 0; i < nlines; i++) {
        char buf[512]; 
        strncpy(buf, lines[i], sizeof(buf)-1); 
        buf[sizeof(buf)-1] = '\0';
        trim(buf);
        
        /* Remove comments */
        char* semi = strchr(buf, ';'); 
        if (semi) *semi = '\0';
        trim(buf);
        if (!*buf) continue;


        /* ==================== LABEL HANDLING ==================== */
        char* after = buf;
        char* colon = NULL;

        /* Find first colon that's NOT inside quotes */
        int in_quote = 0;
        int in_dquote = 0;  // ADD THIS LINE
        for (char* p = buf; *p; p++) {
            if (*p == '\'' && (p == buf || *(p-1) != '\\')) {
                in_quote = !in_quote;
            } else if (*p == '"' && (p == buf || *(p-1) != '\\')) {  // ADD THESE 2 LINES
                in_dquote = !in_dquote;
            } else if (*p == ':' && !in_quote && !in_dquote) {  // MODIFY THIS LINE
                colon = p;
                break;
            }
        }

        if (colon) {
            *colon = '\0'; 
            trim(buf);
            if (*buf) {
                if (buf[0] != '.') {
                    strncpy(current_scope, buf, sizeof(current_scope)-1);
                    current_scope[sizeof(current_scope)-1] = '\0';
                    strtoupper(current_scope);
                }
                add_label(labels, &label_count, buf, pc, current_scope);
            }
            after = colon + 1;
            trim(after);
            if (!*after) continue;
        }

        char line[512]; 
        strncpy(line, after, sizeof(line)-1); 
        line[sizeof(line)-1] = '\0';
        trim(line);
        if (!*line) continue;

        /* ==================== ASSIGNMENT (NAME = VALUE) ==================== */
        char* equals = NULL;
        in_quote = 0;
        for (char* p = line; *p; p++) {
            if (*p == '\'' && (p == line || *(p-1) != '\\')) {
                in_quote = !in_quote;
            } else if (*p == '=' && !in_quote) {
                /* Skip if this is part of ==, !=, <=, >= */
                if ((p > line && (*(p-1) == '!' || *(p-1) == '<' || *(p-1) == '>' || *(p-1) == '=')) ||
                    (*(p+1) == '=')) {
                    continue;
                }
                equals = p;
                break;
            }
        }
        
        if (equals) {
            char name_part[64];
            size_t name_len = (size_t)(equals - line);
            if (name_len >= sizeof(name_part)) name_len = sizeof(name_part) - 1;
            strncpy(name_part, line, name_len);
            name_part[name_len] = '\0';
            trim(name_part);
            
            if (name_part[0] && !find_spec(name_part)) {
                char value_str[128];
                strncpy(value_str, equals + 1, sizeof(value_str)-1);
                value_str[sizeof(value_str)-1] = '\0';
                trim(value_str);
                
                uint32_t val;
                char err[128];
                if (eval_expr(value_str, &val, labels, label_count, i+1, err, pc, current_scope)) {
                    add_label(labels, &label_count, name_part, (uint16_t)val, current_scope);
                } else {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                continue;
            }
        }

        /* ==================== MACRO DEFINITION ==================== */
        if (strncasecmp(line, ".MACRO", 6) == 0) {
            if (macro_count >= 64) {
                report_error((const char**)lines, i+1, "too many macros (max 64)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 6;
            trim(p);
            
            char macro_name[64];
            if (sscanf(p, "%63s", macro_name) != 1) {
                report_error((const char**)lines, i+1, ".MACRO requires a name");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            strtoupper(macro_name);
            strncpy(macros[macro_count].name, macro_name, sizeof(macros[macro_count].name)-1);
            macros[macro_count].name[sizeof(macros[macro_count].name)-1] = '\0';
            
            /* Parse parameters */
            p = strchr(p, ' ');
            macros[macro_count].param_count = 0;
            if (p) {
                trim(p);
                char* token = strtok(p, ",");
                while (token && macros[macro_count].param_count < 8) {
                    trim(token);
                    strncpy(macros[macro_count].params[macros[macro_count].param_count],
                           token, 31);
                    macros[macro_count].params[macros[macro_count].param_count][31] = '\0';
                    macros[macro_count].param_count++;
                    token = strtok(NULL, ",");
                }
            }
            
            /* Collect macro body until .ENDMACRO */
            size_t body_cap = 1024;
            char* body = (char*)malloc(body_cap);
            body[0] = '\0';
            size_t body_len = 0;
            
            i++;
            while (i < nlines) {
                char check[512];
                strncpy(check, lines[i], sizeof(check)-1);
                check[sizeof(check)-1] = '\0';
                
                char* semi = strchr(check, ';');
                if (semi) *semi = '\0';
                trim(check);
                
                if (strncasecmp(check, ".ENDMACRO", 9) == 0) {
                    break;
                }
                
                size_t line_len = strlen(lines[i]);
                if (body_len + line_len + 2 > body_cap) {
                    body_cap *= 2;
                    char* new_body = (char*)realloc(body, body_cap);
                    if (!new_body) {
                        free(body);
                        report_error((const char**)lines, i+1, "out of memory");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0;
                    }
                    body = new_body;
                }
                
                strcpy(body + body_len, lines[i]);
                body_len += line_len;
                body[body_len++] = '\n';
                body[body_len] = '\0';
                
                i++;
            }
            
            if (i >= nlines) {
                free(body);
                report_error((const char**)lines, i, "unclosed .MACRO");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            macros[macro_count].body = body;
            macro_count++;
            continue;
        }

        /* ==================== CONDITIONAL ASSEMBLY ==================== */
        
        /* .IF directive */
        if (strncasecmp(line, ".IF", 3) == 0 && !isalnum((unsigned char)line[3])) {
            
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* expr = line + 3;
            trim(expr);
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            
            int cond_result = 0;
            
            if (parent_active) {
                uint32_t val;
                char err[128];
                int eval_success = eval_expr(expr, &val, labels, label_count, i+1, err, pc, current_scope);
                
                if (eval_success) {
                    cond_result = (val != 0);
                } else {
                    cond_result = 0;
                }
            }
                        
            cond_stack[cond_depth].active = cond_result;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            
            continue;
        }

        /* .IFDEF directive */
        if (strncasecmp(line, ".IFDEF", 6) == 0) {
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IFDEF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 6;
            trim(p);
            
            char symbol[64];
            if (sscanf(p, "%63s", symbol) != 1) {
                report_error((const char**)lines, i+1, ".IFDEF requires symbol");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            int found = 0;
            strtoupper(symbol);
            for (int j = 0; j < label_count; j++) {
                if (strcmp(labels[j].name, symbol) == 0) {
                    found = 1;
                    break;
                }
            }
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            cond_stack[cond_depth].active = parent_active && found;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            continue;
        }

        /* .IFNDEF directive */
        if (strncasecmp(line, ".IFNDEF", 7) == 0) {
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IFNDEF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 7;
            trim(p);
            
            char symbol[64];
            if (sscanf(p, "%63s", symbol) != 1) {
                report_error((const char**)lines, i+1, ".IFNDEF requires symbol");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            int found = 0;
            strtoupper(symbol);
            for (int j = 0; j < label_count; j++) {
                if (strcmp(labels[j].name, symbol) == 0) {
                    found = 1;
                    break;
                }
            }
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            cond_stack[cond_depth].active = parent_active && !found;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            continue;
        }

        /* .ELSE directive */
        if (strncasecmp(line, ".ELSE", 5) == 0) {
            if (cond_depth == 0) {
                report_error((const char**)lines, i+1, ".ELSE without .IF");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            if (cond_stack[cond_depth-1].has_else) {
                report_error((const char**)lines, i+1, "duplicate .ELSE");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            cond_stack[cond_depth-1].active = !cond_stack[cond_depth-1].active;
            cond_stack[cond_depth-1].has_else = 1;
            continue;
        }

        /* .ENDIF directive */
        if (strncasecmp(line, ".ENDIF", 6) == 0) {
            
            if (cond_depth == 0) {
                report_error((const char**)lines, i+1, ".ENDIF without .IF");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            cond_depth--;
            
            continue;
        }

        /* Skip processing if in inactive conditional block */
        if (cond_depth > 0 && !cond_stack[cond_depth-1].active) {
            continue;
        }

        /* ==================== MACRO INVOCATION ==================== */
        /* Check AFTER conditionals but BEFORE other directives */
        char mnem_check[64];
        if (sscanf(line, "%63s", mnem_check) == 1) {
            Macro* m = find_macro(macros, macro_count, mnem_check);
            if (m) {
                /* SECURITY FIX: Check macro expansion limit */
                total_macro_expansions++;
                if (total_macro_expansions > MAX_MACRO_EXPANSIONS) {
                    report_error((const char**)lines, i+1,
                                 "macro expansion limit exceeded (possible recursion)");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }

                char* args_start = strchr(line, ' ');
                int expanded_count = 0;
                char* expanded = expand_macro(m, args_start ? args_start + 1 : "", &expanded_count);

                if (!expanded) {
                    char err_msg[128];
                    snprintf(err_msg, sizeof(err_msg), "macro %s expects %d arguments",
                            m->name, m->param_count);
                    report_error((const char**)lines, i+1, err_msg);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                
                char** new_lines = (char**)malloc(sizeof(char*) * (nlines + expanded_count));
                if (!new_lines) {
                    free(expanded);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                
                for (int j = 0; j < i; j++) {
                    new_lines[j] = lines[j];
                }
                
                char* exp_copy = strdup(expanded);
                int exp_idx = 0;
                for (char* s = strtok(exp_copy, "\n"); s && exp_idx < expanded_count; s = strtok(NULL, "\n")) {
                    new_lines[i + exp_idx] = strdup(s);
                    exp_idx++;
                }
                free(exp_copy);
                free(expanded);
                
                for (int j = i + 1; j < nlines; j++) {
                    new_lines[j + exp_idx - 1] = lines[j];
                }
                
                free(lines[i]);
                free(lines);
                
                lines = new_lines;
                nlines = nlines + exp_idx - 1;
                
                i--;
                continue;
            }
        }

        /* ==================== ASSEMBLER DIRECTIVES ==================== */
        
        /* .EQU */
        if (strncasecmp(line, ".EQU", 4) == 0) {
            char name[64], value_str[128];
            if (sscanf(line + 4, "%63s %127s", name, value_str) == 2) {
                uint32_t val;
                char err[128];
                if (eval_expr(value_str, &val, labels, label_count, i+1, err, pc, current_scope)) {
                    add_label(labels, &label_count, name, (uint16_t)val, current_scope);
                } else {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
            }
            continue;
        }
        
        /* .ORG */
        if (strncasecmp(line, ".ORG", 4) == 0) {
            char* p = line + 4; 
            trim(p);
            uint16_t a = 0; 
            char e[128];
            if (!parse_imm16(p, &a, labels, label_count, e, pc, current_scope)) {
                report_error((const char**)lines, i+1, e);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            pc = a;
            continue;
        }

        /* .FILL */
        if (strncasecmp(line, ".FILL", 5) == 0) {
            char* p = line + 5;
            trim(p);

            char* comma = strchr(p, ',');
            if (!comma) {
                report_error((const char**)lines, i+1, ".FILL requires count,value");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            *comma = '\0';
            char count_str[64];
            strncpy(count_str, p, sizeof(count_str)-1);
            count_str[sizeof(count_str)-1] = '\0';
            trim(count_str);

            uint32_t count;
            char err[128];
            if (!eval_expr(count_str, &count, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Validate count doesn't cause address overflow */
            if (count >= 0x10000) {
                report_error((const char**)lines, i+1, ".FILL count too large (max 65535)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            if (pc > 0xFFFF - count) {
                report_error((const char**)lines, i+1, ".FILL would cause address overflow");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            pc += (uint16_t)count;
            continue;
        }
        
        /* .DS */
        if (strncasecmp(line, ".DS", 3) == 0) {
            char* p = line + 3;
            trim(p);

            uint32_t count;
            char err[128];
            if (!eval_expr(p, &count, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Validate count doesn't cause address overflow */
            if (count >= 0x10000) {
                report_error((const char**)lines, i+1, ".DS count too large (max 65535)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            if (pc > 0xFFFF - count) {
                report_error((const char**)lines, i+1, ".DS would cause address overflow");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            pc += (uint16_t)count;
            continue;
        }
        
        /* .WORD */
        if (strncasecmp(line, ".WORD", 5) == 0) {
            char* p = line + 5;
            trim(p);
            int count = 0;
            while (*p) {
                while (isspace((unsigned char)*p)) p++;
                if (!*p) break;
                
                char* end = p;
                int paren_depth = 0;
                while (*end) {
                    if (*end == '(') paren_depth++;
                    else if (*end == ')') paren_depth--;
                    else if (*end == ',' && paren_depth == 0) break;
                    end++;
                }
                
                count += 2;
                
                p = end;
                while (isspace((unsigned char)*p)) p++;
                if (*p == ',') p++;
            }
            pc += (uint16_t)count;
            continue;
        }
        
        /* .BYTE / .DB */
        if (strncasecmp(line, ".BYTE", 5) == 0 || strncasecmp(line, ".DB", 3) == 0) {
            char* p = line + (tolower((unsigned char)line[1]) == 'b' ? 5 : 3);
            trim(p);
            int total = 0;
            while (*p) {
                while (isspace((unsigned char)*p)) p++;
                if (!*p) break;
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') { total++; p++; }
                    if (*p != '"') { 
                        report_error((const char**)lines, i+1, "bad .byte string");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    p++;
                } else if (*p == '\'') {
                    p++; 
                    if (!*p) { 
                        report_error((const char**)lines, i+1, "bad .byte char literal");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    if (*p == '\\') { 
                        p++; 
                        if (!*p) { 
                            report_error((const char**)lines, i+1, "bad .byte char escape");
                            for (int k = 0; k < nlines; k++) free(lines[k]);
                            free(lines); free(copy); return 0; 
                        } 
                        p++; 
                    } else { 
                        p++; 
                    }
                    if (*p != '\'') { 
                        report_error((const char**)lines, i+1, "unterminated char literal");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    p++; 
                    total += 1;
                } else {
                    while (*p && *p!=',' && !isspace((unsigned char)*p)) p++;
                    total += 1;
                }
                while (isspace((unsigned char)*p)) p++;
                if (*p == ',') p++;
            }
            pc += (uint16_t)total;
            continue;
        }
        
        /* .ALIGN */
        if (strncasecmp(line, ".ALIGN", 6) == 0) {
            char* p = line + 6;
            trim(p);
            
            uint32_t boundary;
            char err[128];
            if (!eval_expr(p, &boundary, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            if (boundary == 0 || boundary > 0x8000) {
                report_error((const char**)lines, i+1, ".ALIGN boundary must be between 1 and 32768");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            if ((boundary & (boundary - 1)) != 0) {
                report_error((const char**)lines, i+1, ".ALIGN boundary must be a power of 2");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }            
            
            uint16_t remainder = pc % boundary;
            if (remainder != 0) {
                uint16_t padding = boundary - remainder;
                pc += padding;
            }
            continue;
        }

        /* .ASCIIZ / .ASCIZ / .STRINGZ */
        if (strncasecmp(line, ".ASCIIZ", 7) == 0 ||
            strncasecmp(line, ".ASCIZ", 6) == 0 ||
            strncasecmp(line, ".STRINGZ", 8) == 0) {
            char* p = line;
            if (strncasecmp(p, ".ASCIIZ", 7) == 0) p += 7;
            else if (strncasecmp(p, ".ASCIZ", 6) == 0) p += 6;
            else p += 8;
            trim(p);
            char* s = strchr(p, '"'); 
            if (!s) { 
                report_error((const char**)lines, i+1, "bad .asciiz");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0; 
            }
            char* e = strrchr(s+1, '"'); 
            if (!e || e<=s) { 
                report_error((const char**)lines, i+1, "bad .asciiz");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0; 
            }
            pc += (uint16_t)((e - (s + 1)) + 1);
            continue;
        }

        /* ==================== INSTRUCTIONS ==================== */
        
        char mnem[16] = {0}, operand[256] = {0};
        if (sscanf(line, "%15s %255[^\n]", mnem, operand) < 1) continue;

        /* Pseudo-instructions */
        if (!strcasecmp(mnem,"JZ") || !strcasecmp(mnem,"JNZ") ||
            !strcasecmp(mnem,"BEQ") || !strcasecmp(mnem,"BNE") ||
            !strcasecmp(mnem,"BCC") || !strcasecmp(mnem,"BCS") || 
            !strcasecmp(mnem,"BPL") || !strcasecmp(mnem,"BMI") ||
            !strcasecmp(mnem,"BVC") || !strcasecmp(mnem,"BVS")) { 
            pc += 2;
            continue; 
        }

        if (!strcasecmp(mnem, "JMP")) {
            if (operand[0] == '(') {
                pc += 3;
                continue;
            }
        }

        if (!strcasecmp(mnem, "NOP")) {
            pc += 1;
            continue;
        }

        if (!strcasecmp(mnem,"OUT") || !strcasecmp(mnem,"BRK")) { 
            pc += 3; 
            continue; 
        }

        if (!strcasecmp(mnem,"SYS")) {
            if (!*operand) {
                report_error((const char**)lines, i+1, "SYS requires a syscall number (0-5)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            pc += 2;
            continue;
        }

        /* Check for implied-mode instructions FIRST */
        if (!*operand) {
            if (!strcasecmp(mnem,"CLI") || !strcasecmp(mnem,"CLC") || 
                !strcasecmp(mnem,"CLD") || !strcasecmp(mnem,"CLV") ||
                !strcasecmp(mnem,"DEX") || !strcasecmp(mnem,"DEY") ||
                !strcasecmp(mnem,"INX") || !strcasecmp(mnem,"INY") ||
                !strcasecmp(mnem,"LSR") || !strcasecmp(mnem,"ASL") ||
                !strcasecmp(mnem,"ROL") || !strcasecmp(mnem,"ROR") ||
                !strcasecmp(mnem,"PHA") || !strcasecmp(mnem,"PLA") ||
                !strcasecmp(mnem,"PHP") || !strcasecmp(mnem,"PLP") ||
                !strcasecmp(mnem,"RTS") || !strcasecmp(mnem,"RTI") ||
                !strcasecmp(mnem,"SEC") || !strcasecmp(mnem,"SED") ||
                !strcasecmp(mnem,"SEI") || !strcasecmp(mnem,"TAX") || 
                !strcasecmp(mnem,"TAY") || !strcasecmp(mnem,"TXA") || 
                !strcasecmp(mnem,"TYA") || !strcasecmp(mnem,"TSX") || 
                !strcasecmp(mnem,"TXS") || !strcasecmp(mnem,"NOP")) {
                pc += 1;
                continue;
            }
        }        

        /* Regular instructions */
        const Spec* sp = find_spec(mnem);
        if (!sp) {
            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg), "unknown mnemonic '%s'", mnem);
            report_error((const char**)lines, i+1, err_msg);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        char err[128] = {0};
        Mode m = detect_mode(sp, operand, err, labels, label_count, pc, current_scope);
        
        if (m == OP_NONE && err[0]) {
            report_error((const char**)lines, i+1, err);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        uint8_t opc = opcode_for_mode(sp, m);
        if (!opc) {
            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg), "no opcode for %s with that operand", mnem);
            report_error((const char**)lines, i+1, err_msg);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        pc += 1;
        if (m == OP_IMM || m == OP_ZP || m == OP_ZP_X || m == OP_ZP_Y || 
            m == OP_INDZP_Y || m == OP_INDX_ZP) pc += 1;
        else if (m == OP_ABS || m == OP_ABS_X || m == OP_ABS_Y) pc += 2;
    }


    /* =========================================================== */
    /* ================= PASS 2: code generation ================= */
    /* =========================================================== */
    // if (!*buf) continue;

    pc = default_org ? default_org : 0x0200;
    current_scope[0] = '\0';  /* Reset scope for pass 2 */
    cond_depth = 0;  /* Reset conditional depth */

    for (int i = 0; i < nlines; i++) {
        char buf[512]; 
        strncpy(buf, lines[i], sizeof(buf)-1); 
        buf[sizeof(buf)-1] = '\0';
        trim(buf);
        
        char* semi = strchr(buf, ';'); 
        if (semi) *semi = '\0';
        trim(buf);
        if (!*buf) continue;

        /* ==================== LABEL HANDLING ==================== */
        char* after = buf;
        char* colon = NULL;

        /* Find first colon that's NOT inside quotes */
        int in_quote = 0;
        int in_dquote = 0;  // ADD THIS LINE
        for (char* p = buf; *p; p++) {
            if (*p == '\'' && (p == buf || *(p-1) != '\\')) {
                in_quote = !in_quote;
            } else if (*p == '"' && (p == buf || *(p-1) != '\\')) {  // ADD THESE 2 LINES
                in_dquote = !in_dquote;
            } else if (*p == ':' && !in_quote && !in_dquote) {  // MODIFY THIS LINE
                colon = p;
                break;
            }
        }

        if (colon) {
            *colon = '\0'; 
            trim(buf);
            if (*buf) {
                if (buf[0] != '.') {
                    strncpy(current_scope, buf, sizeof(current_scope)-1);
                    current_scope[sizeof(current_scope)-1] = '\0';
                    strtoupper(current_scope);
                }
                add_label(labels, &label_count, buf, pc, current_scope);
            }
            after = colon + 1;
            trim(after);
            if (!*after) continue;
        }

        char line[512]; 
        strncpy(line, after, sizeof(line)-1); 
        line[sizeof(line)-1] = '\0';
        trim(line);
        if (!*line) continue;
        
        /* ==================== ASSIGNMENT (NAME = VALUE) ==================== */
        char* equals = NULL;
        in_quote = 0;
        for (char* p = line; *p; p++) {
            if (*p == '\'' && (p == line || *(p-1) != '\\')) {
                in_quote = !in_quote;
            } else if (*p == '=' && !in_quote) {
                /* Skip if this is part of ==, !=, <=, >= */
                if ((p > line && (*(p-1) == '!' || *(p-1) == '<' || *(p-1) == '>' || *(p-1) == '=')) ||
                    (*(p+1) == '=')) {
                    continue;
                }
                equals = p;
                break;
            }
        }

        if (equals) {
            char name_part[64];
            size_t name_len = (size_t)(equals - line);
            if (name_len >= sizeof(name_part)) name_len = sizeof(name_part) - 1;
            strncpy(name_part, line, name_len);
            name_part[name_len] = '\0';
            trim(name_part);
            
            if (name_part[0] && !find_spec(name_part)) {
                char value_str[128];
                strncpy(value_str, equals + 1, sizeof(value_str)-1);
                value_str[sizeof(value_str)-1] = '\0';
                trim(value_str);
                
                uint32_t val;
                char err[128];
                if (eval_expr(value_str, &val, labels, label_count, i+1, err, pc, current_scope)) {
                    add_label(labels, &label_count, name_part, (uint16_t)val, current_scope);
                } else {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                continue;
            }
        }

        /* New directive: .SAVEROM to save assembled code as ROM image. Add in Pass 2 directives section */
        if (strncasecmp(line, ".SAVEROM", 8) == 0) {
            char filename[256];
            uint16_t start_addr, end_addr;
            
            char* p = line + 8;
            trim(p);
            
            // Parse: .SAVEROM "filename.rom", start, end
            char* quote1 = strchr(p, '"');
            if (!quote1) {
                report_error((const char**)lines, i+1, ".SAVEROM requires filename in quotes");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* quote2 = strchr(quote1 + 1, '"');
            if (!quote2) {
                report_error((const char**)lines, i+1, ".SAVEROM missing closing quote");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            size_t fname_len = quote2 - (quote1 + 1);
            if (fname_len >= sizeof(filename)) fname_len = sizeof(filename) - 1;
            memcpy(filename, quote1 + 1, fname_len);
            filename[fname_len] = '\0';
            
            // Parse start and end addresses
            char* comma = strchr(quote2, ',');
            if (!comma) {
                report_error((const char**)lines, i+1, ".SAVEROM requires start,end addresses");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char start_str[64], end_str[64];
            char* comma2 = strchr(comma + 1, ',');
            if (!comma2) {
                report_error((const char**)lines, i+1, ".SAVEROM requires start,end addresses");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            size_t start_len = comma2 - (comma + 1);
            if (start_len >= sizeof(start_str)) start_len = sizeof(start_str) - 1;
            memcpy(start_str, comma + 1, start_len);
            start_str[start_len] = '\0';
            trim(start_str);
            
            strcpy(end_str, comma2 + 1);
            trim(end_str);
            
            char err[128];
            if (!parse_imm16(start_str, &start_addr, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            if (!parse_imm16(end_str, &end_addr, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            // Validate addresses
            if (start_addr < ROM_START || end_addr > 0xFFFF || start_addr > end_addr) {
                report_error((const char**)lines, i+1, ".SAVEROM addresses must be in ROM range $C000-$FFFF");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            // Save the ROM
            if (!save_rom(vm, filename, start_addr, end_addr)) {
                report_error((const char**)lines, i+1, "Failed to save ROM image");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            continue;
        }


        /* ==================== MACRO DEFINITION ==================== */

        if (strncasecmp(line, ".MACRO", 6) == 0) {
            if (macro_count >= 64) {
                report_error((const char**)lines, i+1, "too many macros (max 64)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 6;
            trim(p);
            
            char macro_name[64];
            if (sscanf(p, "%63s", macro_name) != 1) {
                report_error((const char**)lines, i+1, ".MACRO requires a name");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            strtoupper(macro_name);
            strncpy(macros[macro_count].name, macro_name, sizeof(macros[macro_count].name)-1);
            macros[macro_count].name[sizeof(macros[macro_count].name)-1] = '\0';
            
            p = strchr(p, ' ');
            macros[macro_count].param_count = 0;
            if (p) {
                trim(p);
                char* token = strtok(p, ",");
                while (token && macros[macro_count].param_count < 8) {
                    trim(token);
                    strncpy(macros[macro_count].params[macros[macro_count].param_count],
                           token, 31);
                    macros[macro_count].params[macros[macro_count].param_count][31] = '\0';
                    macros[macro_count].param_count++;
                    token = strtok(NULL, ",");
                }
            }
            
            size_t body_cap = 1024;
            char* body = (char*)malloc(body_cap);
            body[0] = '\0';
            size_t body_len = 0;
            
            i++;
            while (i < nlines) {
                char check[512];
                strncpy(check, lines[i], sizeof(check)-1);
                check[sizeof(check)-1] = '\0';
                
                char* semi = strchr(check, ';');
                if (semi) *semi = '\0';
                trim(check);
                
                if (strncasecmp(check, ".ENDMACRO", 9) == 0) {
                    break;
                }
                
                size_t line_len = strlen(lines[i]);
                if (body_len + line_len + 2 > body_cap) {
                    body_cap *= 2;
                    char* new_body = (char*)realloc(body, body_cap);
                    if (!new_body) {
                        free(body);
                        report_error((const char**)lines, i+1, "out of memory");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0;
                    }
                    body = new_body;
                }
                
                strcpy(body + body_len, lines[i]);
                body_len += line_len;
                body[body_len++] = '\n';
                body[body_len] = '\0';
                
                i++;
            }
            
            if (i >= nlines) {
                free(body);
                report_error((const char**)lines, i, "unclosed .MACRO");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            macros[macro_count].body = body;
            macro_count++;
            continue;
        }

        /* ==================== CONDITIONAL ASSEMBLY ==================== */
        
        /* .IF directive */
        if (strncasecmp(line, ".IF", 3) == 0 && !isalnum((unsigned char)line[3])) {
            
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* expr = line + 3;
            trim(expr);
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            
            int cond_result = 0;
            
            if (parent_active) {
                uint32_t val;
                char err[128];
                int eval_success = eval_expr(expr, &val, labels, label_count, i+1, err, pc, current_scope);
                
                if (eval_success) {
                    cond_result = (val != 0);
                } else {
                    cond_result = 0;
                }
            }
                        
            cond_stack[cond_depth].active = cond_result;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            
            continue;
        }

        /* .IFDEF directive */
        if (strncasecmp(line, ".IFDEF", 6) == 0) {
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IFDEF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 6;
            trim(p);
            
            char symbol[64];
            if (sscanf(p, "%63s", symbol) != 1) {
                report_error((const char**)lines, i+1, ".IFDEF requires symbol");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            int found = 0;
            strtoupper(symbol);
            for (int j = 0; j < label_count; j++) {
                if (strcmp(labels[j].name, symbol) == 0) {
                    found = 1;
                    break;
                }
            }
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            cond_stack[cond_depth].active = parent_active && found;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            continue;
        }

        /* .IFNDEF directive */
        if (strncasecmp(line, ".IFNDEF", 7) == 0) {
            if (cond_depth >= 16) {
                report_error((const char**)lines, i+1, ".IFNDEF nesting too deep");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            char* p = line + 7;
            trim(p);
            
            char symbol[64];
            if (sscanf(p, "%63s", symbol) != 1) {
                report_error((const char**)lines, i+1, ".IFNDEF requires symbol");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            int found = 0;
            strtoupper(symbol);
            for (int j = 0; j < label_count; j++) {
                if (strcmp(labels[j].name, symbol) == 0) {
                    found = 1;
                    break;
                }
            }
            
            int parent_active = (cond_depth == 0) || cond_stack[cond_depth-1].active;
            cond_stack[cond_depth].active = parent_active && !found;
            cond_stack[cond_depth].has_else = 0;
            cond_depth++;
            continue;
        }

        /* .ELSE directive */
        if (strncasecmp(line, ".ELSE", 5) == 0) {
            if (cond_depth == 0) {
                report_error((const char**)lines, i+1, ".ELSE without .IF");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            if (cond_stack[cond_depth-1].has_else) {
                report_error((const char**)lines, i+1, "duplicate .ELSE");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            cond_stack[cond_depth-1].active = !cond_stack[cond_depth-1].active;
            cond_stack[cond_depth-1].has_else = 1;
            continue;
        }

        /* .ENDIF directive */
        if (strncasecmp(line, ".ENDIF", 6) == 0) {
            
            if (cond_depth == 0) {
                report_error((const char**)lines, i+1, ".ENDIF without .IF");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            cond_depth--;
            
            continue;
        }

        /* Skip processing if in inactive conditional block */
        if (cond_depth > 0 && !cond_stack[cond_depth-1].active) {
            continue;
        }

        /* ==================== MACRO INVOCATION ==================== */
        char mnem_check[64];
        if (sscanf(line, "%63s", mnem_check) == 1) {
            Macro* m = find_macro(macros, macro_count, mnem_check);
            if (m) {
                /* SECURITY FIX: Check macro expansion limit */
                total_macro_expansions++;
                if (total_macro_expansions > MAX_MACRO_EXPANSIONS) {
                    report_error((const char**)lines, i+1,
                                 "macro expansion limit exceeded (possible recursion)");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }

                char* args_start = strchr(line, ' ');
                int expanded_count = 0;
                char* expanded = expand_macro(m, args_start ? args_start + 1 : "", &expanded_count);

                if (!expanded) {
                    char err_msg[128];
                    snprintf(err_msg, sizeof(err_msg), "macro %s expects %d arguments",
                            m->name, m->param_count);
                    report_error((const char**)lines, i+1, err_msg);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                
                char** new_lines = (char**)malloc(sizeof(char*) * (nlines + expanded_count));
                if (!new_lines) {
                    free(expanded);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                
                for (int j = 0; j < i; j++) {
                    new_lines[j] = lines[j];
                }
                
                char* exp_copy = strdup(expanded);
                int exp_idx = 0;
                for (char* s = strtok(exp_copy, "\n"); s && exp_idx < expanded_count; s = strtok(NULL, "\n")) {
                    new_lines[i + exp_idx] = strdup(s);
                    exp_idx++;
                }
                free(exp_copy);
                free(expanded);
                
                for (int j = i + 1; j < nlines; j++) {
                    new_lines[j + exp_idx - 1] = lines[j];
                }
                
                free(lines[i]);
                free(lines);
                
                lines = new_lines;
                nlines = nlines + exp_idx - 1;
                
                i--;
                continue;
            }
        }

        /* ==================== ASSEMBLER DIRECTIVES ==================== */
        
        /* Skip .EQU */
        if (strncasecmp(line, ".EQU", 4) == 0) continue;
        
        /* .ORG */
        if (strncasecmp(line, ".ORG", 4) == 0) {
            char* p = line + 4; 
            trim(p);
            uint16_t a = 0; 
            char e[128];
            if (!parse_imm16(p, &a, labels, label_count, e, pc, current_scope)) {
                report_error((const char**)lines, i+1, e);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            pc = a;
            continue;
        }
        
        /* .FILL */
        if (strncasecmp(line, ".FILL", 5) == 0) {
            char* p = line + 5;
            trim(p);
            
            char* comma = strchr(p, ',');
            if (!comma) {
                report_error((const char**)lines, i+1, ".FILL requires count,value");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            *comma = '\0';
            char count_str[64], value_str[64];
            strncpy(count_str, p, sizeof(count_str)-1);
            count_str[sizeof(count_str)-1] = '\0';
            trim(count_str);
            
            strncpy(value_str, comma + 1, sizeof(value_str)-1);
            value_str[sizeof(value_str)-1] = '\0';
            trim(value_str);

            uint32_t count, value;
            char err[128];
            if (!eval_expr(count_str, &count, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Off-by-one error fix and overflow check */
            if (count >= 0x10000) {
                report_error((const char**)lines, i+1, ".FILL count too large (max 65535)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Check for address overflow before writing */
            if (pc > 0xFFFF - count) {
                report_error((const char**)lines, i+1, ".FILL would cause address overflow");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            if (!eval_expr(value_str, &value, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            if (value > 0xFF) {
                report_error((const char**)lines, i+1, ".FILL value must be 0-255");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            for (uint32_t j = 0; j < count; j++) {
                w8_raw(vm, pc++, (uint8_t)value);
            }
            continue;
        }

        /* .DS */
        if (strncasecmp(line, ".DS", 3) == 0) {
            char* p = line + 3;
            trim(p);

            uint32_t count;
            char err[128];
            if (!eval_expr(p, &count, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Off-by-one error fix and overflow check */
            if (count >= 0x10000) {
                report_error((const char**)lines, i+1, ".DS count too large (max 65535)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            /* SECURITY FIX: Check for address overflow before writing */
            if (pc > 0xFFFF - count) {
                report_error((const char**)lines, i+1, ".DS would cause address overflow");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            for (uint32_t j = 0; j < count; j++) {
                w8_raw(vm, pc++, 0);
            }
            continue;
        }

        /* .WORD */
        if (strncasecmp(line, ".WORD", 5) == 0) {
            char* p = line + 5;
            trim(p);
            
            while (*p) {
                while (isspace((unsigned char)*p)) p++;
                if (!*p) break;
                
                char* end = p;
                int paren_depth = 0;
                while (*end) {
                    if (*end == '(') paren_depth++;
                    else if (*end == ')') paren_depth--;
                    else if (*end == ',' && paren_depth == 0) break;
                    end++;
                }
                
                char save = *end;
                *end = '\0';
                
                char expr[256];
                strncpy(expr, p, sizeof(expr)-1);
                expr[sizeof(expr)-1] = '\0';
                trim(expr);
                
                uint16_t word_val;
                char err[128];
                if (!parse_imm16(expr, &word_val, labels, label_count, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                
                w8_raw(vm, pc++, (uint8_t)word_val);
                w8_raw(vm, pc++, (uint8_t)(word_val >> 8));
                
                *end = save;
                p = end;
                while (isspace((unsigned char)*p)) p++;
                if (*p == ',') p++;
            }
            continue;
        }

        /* .BYTE / .DB */
        if (strncasecmp(line, ".BYTE", 5) == 0 || strncasecmp(line, ".DB", 3) == 0) {
            char* p = line + (tolower((unsigned char)line[1]) == 'b' ? 5 : 3);
            trim(p);
            while (*p) {
                while (isspace((unsigned char)*p)) p++;
                if (!*p) break;
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') {
                        w8_raw(vm, pc++, (uint8_t)*p);
                        p++;
                    }
                    if (*p != '"') { 
                        report_error((const char**)lines, i+1, "bad .byte string");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    p++;
                } else if (*p == '\'') {
                    p++; 
                    if (!*p) { 
                        report_error((const char**)lines, i+1, "bad .byte char literal");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    uint8_t ch = 0;
                    if (*p == '\\') { 
                        p++; 
                        if (!*p) { 
                            report_error((const char**)lines, i+1, "bad .byte char escape");
                            for (int k = 0; k < nlines; k++) free(lines[k]);
                            free(lines); free(copy); return 0; 
                        } 
                        if (*p == 'n') ch = '\n';
                        else if (*p == 't') ch = '\t';
                        else if (*p == 'r') ch = '\r';
                        else if (*p == '0') ch = '\0';
                        else ch = (uint8_t)*p;
                        p++; 
                    } else { 
                        ch = (uint8_t)*p; 
                        p++; 
                    }
                    if (*p != '\'') { 
                        report_error((const char**)lines, i+1, "unterminated char literal");
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0; 
                    }
                    p++; 
                    w8_raw(vm, pc++, ch);
                } else {
                    char* end = p;
                    while (*end && *end!=',' && !isspace((unsigned char)*end)) end++;
                    char save = *end; *end = '\0';
                    
                    uint8_t bval;
                    char err[128];
                    if (!parse_imm8_ex(p, &bval, labels, label_count, i+1, err, pc, current_scope)) {
                        report_error((const char**)lines, i+1, err);
                        for (int k = 0; k < nlines; k++) free(lines[k]);
                        free(lines); free(copy); return 0;
                    }
                    
                    *end = save;
                    w8_raw(vm, pc++, bval);
                    p = end;
                }
                while (isspace((unsigned char)*p)) p++;
                if (*p == ',') p++;
            }
            continue;
        }
        
        /* .ALIGN */
        if (strncasecmp(line, ".ALIGN", 6) == 0) {
            char* p = line + 6;
            trim(p);
            
            uint32_t boundary;
            char err[128];
            if (!eval_expr(p, &boundary, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            if (boundary == 0 || boundary > 0x8000) {
                report_error((const char**)lines, i+1, ".ALIGN boundary must be between 1 and 32768");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }

            if ((boundary & (boundary - 1)) != 0) {
                report_error((const char**)lines, i+1, ".ALIGN boundary must be a power of 2");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            uint16_t remainder = pc % boundary;
            if (remainder != 0) {
                uint16_t padding = boundary - remainder;
                for (uint16_t j = 0; j < padding; j++) {
                    w8_raw(vm, pc++, 0);
                }
            }
            continue;
        }

        /* .ASCIIZ / .ASCIZ / .STRINGZ */
        if (strncasecmp(line, ".ASCIIZ", 7) == 0 ||
            strncasecmp(line, ".ASCIZ", 6) == 0 ||
            strncasecmp(line, ".STRINGZ", 8) == 0) {
            char* p = line;
            if (strncasecmp(p, ".ASCIIZ", 7) == 0) p += 7;
            else if (strncasecmp(p, ".ASCIZ", 6) == 0) p += 6;
            else p += 8;
            trim(p);
            char* s = strchr(p, '"'); 
            if (!s) { 
                report_error((const char**)lines, i+1, "bad .asciiz");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0; 
            }
            char* e = strrchr(s+1, '"'); 
            if (!e || e<=s) { 
                report_error((const char**)lines, i+1, "bad .asciiz");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0; 
            }
            for (char* c = s+1; c < e; c++) {
                w8_raw(vm, pc++, (uint8_t)*c);
            }
            w8_raw(vm, pc++, 0);
            continue;
        }

        /* ==================== INSTRUCTIONS ==================== */
        
        char mnem[16] = {0}, operand[256] = {0};
        if (sscanf(line, "%15s %255[^\n]", mnem, operand) < 1) continue;

        /* Pseudo-instructions */
        if (!strcasecmp(mnem,"JZ")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far, use JMP instead");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0xF0);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"JNZ")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far, use JMP instead");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0xD0);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem, "JMP") && operand[0] == '(') {
            char* close = strchr(operand, ')');
            if (!close) {
                report_error((const char**)lines, i+1, "missing ')'");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            char addr_str[64];
            size_t len = close - (operand + 1);
            if (len >= sizeof(addr_str)) len = sizeof(addr_str) - 1;
            memcpy(addr_str, operand + 1, len);
            addr_str[len] = '\0';
            
            uint16_t addr = 0;
            char err[128] = {0};
            if (!parse_imm16(addr_str, &addr, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            w8_raw(vm, pc++, 0x6C);
            w8_raw(vm, pc++, (uint8_t)addr);
            w8_raw(vm, pc++, (uint8_t)(addr >> 8));
            continue;
        }

        if (!strcasecmp(mnem,"BCC")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0x90);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"BCS")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0xB0);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"BEQ")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far, use JMP instead");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0xF0);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"BNE")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far, use JMP instead");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0xD0);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"BPL")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0x10);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;
        }

        if (!strcasecmp(mnem,"BMI")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0x30);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;            
        }

        if (!strcasecmp(mnem,"BVC")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0x50);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;  
        }

        if (!strcasecmp(mnem,"BVS")) {
            uint16_t target = 0;
            char err[128] = {0};
            if (!parse_imm16(operand, &target, labels, label_count, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            int16_t offset = (int16_t)(target - (pc + 2));
            if (offset < -128 || offset > 127) {
                report_error((const char**)lines, i+1, "branch too far");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            w8_raw(vm, pc++, 0x70);
            w8_raw(vm, pc++, (uint8_t)offset);
            continue;  
        }

        if (!strcasecmp(mnem,"BRK")) {
            w8_raw(vm, pc++, 0x00);
            w8_raw(vm, pc++, 0x00);
            w8_raw(vm, pc++, 0x00);
            continue;
        } 

        if (!strcasecmp(mnem,"OUT")) {
            w8_raw(vm, pc++, 0x8D);
            w8_raw(vm, pc++, 0x00); 
            w8_raw(vm, pc++, 0x80);
            continue;
        }

        if (!strcasecmp(mnem,"SYS")) {
            if (!*operand) {
                report_error((const char**)lines, i+1, "SYS requires a syscall number (0-5)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            uint8_t num = 0;
            char err[128] = {0};
            
            const char* parse_str = operand;
            if (operand[0] == '#') {
                parse_str = operand;
            }
            
            if (!parse_imm8_ex(parse_str, &num, labels, label_count, i+1, err, pc, current_scope)) {
                report_error((const char**)lines, i+1, err);
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            if (num > 5) {
                report_error((const char**)lines, i+1, "Invalid syscall number (must be 0-5)");
                for (int k = 0; k < nlines; k++) free(lines[k]);
                free(lines); free(copy); return 0;
            }
            
            w8_raw(vm, pc++, 0x02);
            w8_raw(vm, pc++, num);
            continue;
        }

        /* Check for implied-mode instructions FIRST */
        if (!*operand) {
            if (!strcasecmp(mnem,"ASL")) { w8_raw(vm, pc++, 0x0A); continue; }
            if (!strcasecmp(mnem,"CLC")) { w8_raw(vm, pc++, 0x18); continue; }
            if (!strcasecmp(mnem,"CLD")) { w8_raw(vm, pc++, 0xD8); continue; }  // ADD THIS                                    
            if (!strcasecmp(mnem,"CLI")) { w8_raw(vm, pc++, 0x58); continue; }
            if (!strcasecmp(mnem,"CLV")) { w8_raw(vm, pc++, 0xB8); continue; }  // ADD THIS
            if (!strcasecmp(mnem,"DEX")) { w8_raw(vm, pc++, 0xCA); continue; }
            if (!strcasecmp(mnem,"DEY")) { w8_raw(vm, pc++, 0x88); continue; }
            if (!strcasecmp(mnem,"INX")) { w8_raw(vm, pc++, 0xE8); continue; }
            if (!strcasecmp(mnem,"INY")) { w8_raw(vm, pc++, 0xC8); continue; }
            if (!strcasecmp(mnem,"LSR")) { w8_raw(vm, pc++, 0x4A); continue; }
            if (!strcasecmp(mnem,"NOP")) { w8_raw(vm, pc++, 0xEA); continue; }
            if (!strcasecmp(mnem,"PHA")) { w8_raw(vm, pc++, 0x48); continue; }
            if (!strcasecmp(mnem,"PHP")) { w8_raw(vm, pc++, 0x08); continue; }
            if (!strcasecmp(mnem,"PLA")) { w8_raw(vm, pc++, 0x68); continue; }
            if (!strcasecmp(mnem,"PLP")) { w8_raw(vm, pc++, 0x28); continue; }
            if (!strcasecmp(mnem,"ROL")) { w8_raw(vm, pc++, 0x2A); continue; }
            if (!strcasecmp(mnem,"ROR")) { w8_raw(vm, pc++, 0x6A); continue; }
            if (!strcasecmp(mnem,"RTI")) { w8_raw(vm, pc++, 0x40); continue; }
            if (!strcasecmp(mnem,"RTS")) { w8_raw(vm, pc++, 0x60); continue; }
            if (!strcasecmp(mnem,"SEC")) { w8_raw(vm, pc++, 0x38); continue; }            
            if (!strcasecmp(mnem,"SED")) { w8_raw(vm, pc++, 0xF8); continue; }  // ADD THIS
            if (!strcasecmp(mnem,"SEI")) { w8_raw(vm, pc++, 0x78); continue; }
            if (!strcasecmp(mnem,"TAX")) { w8_raw(vm, pc++, 0xAA); continue; }
            if (!strcasecmp(mnem,"TAY")) { w8_raw(vm, pc++, 0xA8); continue; }
            if (!strcasecmp(mnem,"TSX")) { w8_raw(vm, pc++, 0xBA); continue; }
            if (!strcasecmp(mnem,"TXA")) { w8_raw(vm, pc++, 0x8A); continue; }
            if (!strcasecmp(mnem,"TXS")) { w8_raw(vm, pc++, 0x9A); continue; }
            if (!strcasecmp(mnem,"TYA")) { w8_raw(vm, pc++, 0x98); continue; }

            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg), "%s needs an operand", mnem);
            report_error((const char**)lines, i+1, err_msg);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        /* Regular instructions */
        const Spec* sp = find_spec(mnem);
        if (!sp) {
            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg), "unknown mnemonic '%s'", mnem);
            report_error((const char**)lines, i+1, err_msg);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        char err[128] = {0};
        Mode m = detect_mode(sp, operand, err, labels, label_count, pc, current_scope);
        
        if (m == OP_NONE && err[0]) { 
            report_error((const char**)lines, i+1, err);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0; 
        }

        uint8_t opc = opcode_for_mode(sp, m);
        if (!opc) {
            char err_msg[128];
            snprintf(err_msg, sizeof(err_msg), "no opcode for %s with that operand", mnem);
            report_error((const char**)lines, i+1, err_msg);
            for (int k = 0; k < nlines; k++) free(lines[k]);
            free(lines); free(copy); return 0;
        }

        w8_raw(vm, pc++, opc);

        switch (m) {
            case OP_IMM: {
                uint8_t imm = 0;
                if (!parse_imm8_ex(operand + 1, &imm, labels, label_count, i+1, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                w8_raw(vm, pc++, imm);
                break;
            }
            case OP_ZP: {
                uint8_t zp = 0;
                if (!parse_imm8_ex(operand, &zp, labels, label_count, i+1, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                w8_raw(vm, pc++, zp);
                break;
            }
            case OP_ZP_X: {
                char* comma = strchr(operand, ',');
                if (!comma) { 
                    report_error((const char**)lines, i+1, "expected ,X");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0; 
                }
                *comma = '\0';
                uint8_t zp = 0;
                if (!parse_imm8_ex(operand, &zp, labels, label_count, i+1, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                *comma = ',';
                w8_raw(vm, pc++, zp);
                break;
            }
            case OP_ZP_Y: {
                char* comma = strchr(operand, ',');
                if (!comma) { 
                    report_error((const char**)lines, i+1, "expected ,Y");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0; 
                }
                *comma = '\0';
                uint8_t zp = 0;
                if (!parse_imm8_ex(operand, &zp, labels, label_count, i+1, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                *comma = ',';
                w8_raw(vm, pc++, zp);
                break;
            }
            case OP_ABS: {
                uint16_t addr = 0;
                if (!parse_imm16(operand, &addr, labels, label_count, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                w8_raw(vm, pc++, (uint8_t)addr);
                w8_raw(vm, pc++, (uint8_t)(addr >> 8));
                break;
            }
            case OP_ABS_X: {
                char* comma = strchr(operand, ',');
                if (!comma) { 
                    report_error((const char**)lines, i+1, "expected ,X");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0; 
                }
                *comma = '\0';
                uint16_t addr = 0;
                if (!parse_imm16(operand, &addr, labels, label_count, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                *comma = ',';
                w8_raw(vm, pc++, (uint8_t)addr);
                w8_raw(vm, pc++, (uint8_t)(addr >> 8));
                break;
            }
            case OP_ABS_Y: {
                char* comma = strchr(operand, ',');
                if (!comma) { 
                    report_error((const char**)lines, i+1, "expected ,Y");
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0; 
                }
                *comma = '\0';
                uint16_t addr = 0;
                if (!parse_imm16(operand, &addr, labels, label_count, err, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                *comma = ',';
                w8_raw(vm, pc++, (uint8_t)addr);
                w8_raw(vm, pc++, (uint8_t)(addr >> 8));
                break;
            }
            case OP_INDZP_Y: {
                uint8_t zp = 0;
                if (!is_indzp_y(operand, &zp, err, labels, label_count, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                w8_raw(vm, pc++, zp);
                break;
            }
            case OP_INDX_ZP: {
                uint8_t zp = 0;
                if (!is_indx_zp(operand, &zp, err, labels, label_count, pc, current_scope)) {
                    report_error((const char**)lines, i+1, err);
                    for (int k = 0; k < nlines; k++) free(lines[k]);
                    free(lines); free(copy); return 0;
                }
                w8_raw(vm, pc++, zp);
                break;
            }
            default: break;
        }
    }

    /* SECURITY FIX: Free all allocated macro bodies to prevent memory leak */
    for (int m = 0; m < macro_count; m++) {
        if (macros[m].body) {
            free(macros[m].body);
            macros[m].body = NULL;
        }
    }

    for (int i = 0; i < nlines; i++) {
        free(lines[i]);
    }
    free(lines);
    free(copy);

    return 1;

}

    

/* =================== VM Core =================== */
static void vm_reset(VM* vm, uint16_t entry) {
    memset(&vm->cpu, 0, sizeof(vm->cpu));
    vm->cpu.SP = 0xFF;
    vm->cpu.PC = entry;
    vm->cpu.P = FLAG_U;
    vm->irq_pending = 0;
    vm->last_timer_cycle = 0;
    vm->nmi_pending = 0;
    vm->nmi_prev = 0;
}

static void vm_timer_tick(VM* vm) {
    if (vm->mem[REG_TMR_CTL] && 
        (vm->cpu.cycles - vm->last_timer_cycle) >= 10000) {
        vm->last_timer_cycle = vm->cpu.cycles;
        vm->mem[REG_TMR_CNT]++;
        if (!(vm->cpu.P & FLAG_I)) {
            vm->irq_pending = 1;
        }
    }
}

/* Validate critical system state before execution */
static int validate_vm_state(VM* vm) {
    /* Check reset vector is valid */
    uint16_t reset = vm->mem[VEC_RESET] | (vm->mem[VEC_RESET + 1] << 8);
    if (reset == 0x0000) {
        fprintf(stderr, "Error: Reset vector not initialized\n");
        return 0;
    }
    
    /* Warn about uninitialized interrupt vectors */
    uint16_t nmi = vm->mem[VEC_NMI] | (vm->mem[VEC_NMI + 1] << 8);
    uint16_t irq = vm->mem[VEC_IRQ] | (vm->mem[VEC_IRQ + 1] << 8);
    
    if (vm->debug) {
        printf("Vector check:\n");
        printf("  RESET: $%04X\n", reset);
        printf("  NMI:   $%04X %s\n", nmi, nmi == 0 ? "(disabled)" : "");
        printf("  IRQ:   $%04X %s\n", irq, irq == 0 ? "(disabled)" : "");
    }
    
    return 1;
}

/* =================== COMPLETE FIXED cpu_execute() FUNCTION =================== */

static void cpu_execute(VM* vm) {
    CPU* cpu = &vm->cpu;
    uint8_t* mem = vm->mem;

    /* SECURITY FIX: Use global constant for execution limit */
    uint64_t start_cycles = cpu->cycles;
    uint64_t max_cycles = start_cycles + MAX_EXECUTION_CYCLES;

    while (1) {

        /* SECURITY FIX: Prevent infinite loops and DoS attacks */
        if (cpu->cycles > max_cycles) {
            fprintf(stderr, "\n*** SECURITY: Execution timeout (%llu cycles) ***\n",
                    (unsigned long long)MAX_EXECUTION_CYCLES);
            fprintf(stderr, "Program exceeded maximum execution time.\n");
            fprintf(stderr, "This may indicate an infinite loop or malicious code.\n");
            fprintf(stderr, "PC=$%04X A=$%02X X=$%02X Y=$%02X P=$%02X SP=$%02X\n",
                    cpu->PC, cpu->A, cpu->X, cpu->Y, cpu->P, cpu->SP);
            return;
        }
        
        /* Validate PC is in valid range */
        if (cpu->PC > 0xFFFF) {
            fprintf(stderr, "\nPC out of range: $%04X\n", (unsigned)cpu->PC);
            return;
        }
                cpu->cycles++;

        /* Check for NMI first (non-maskable, higher priority BEFORE fetching instruction) */
        if (vm->nmi_pending) {

            vm->nmi_pending = 0;

            /* SECURITY FIX: Use safe stack operations */
            if (!stack_push(vm, (uint8_t)(cpu->PC >> 8))) return;  /* Push PC high byte */
            if (!stack_push(vm, (uint8_t)cpu->PC)) return;         /* Push PC low byte */
            if (!stack_push(vm, cpu->P & ~FLAG_B)) return;         /* Push status (B clear for NMI) */
            
            /* Set interrupt disable flag (NMI does this too) */
            cpu->P |= FLAG_I;
            
            /* Jump to NMI vector */
            uint16_t nmi_vec = mem[VEC_NMI] | (mem[VEC_NMI + 1] << 8);
            cpu->PC = nmi_vec;
            
            continue;
        }

        /* Check for IRQ (maskable, lower priority) */
        if (vm->irq_pending && !(cpu->P & FLAG_I)) {
            vm->irq_pending = 0;

            /* SECURITY FIX: Use safe stack operations */
            if (!stack_push(vm, (uint8_t)(cpu->PC >> 8))) return;  /* Push PC high byte */
            if (!stack_push(vm, (uint8_t)cpu->PC)) return;         /* Push PC low byte */
            if (!stack_push(vm, cpu->P & ~FLAG_B)) return;         /* Push status (B clear for IRQ) */
            
            /* Set interrupt disable flag */
            cpu->P |= FLAG_I;
            
            /* Jump to IRQ vector */
            uint16_t irq_vec = mem[VEC_IRQ] | (mem[VEC_IRQ + 1] << 8);
            cpu->PC = irq_vec;
            
            continue; /* Skip normal fetch */
        }
        
        /* Call timer tick periodically */
        if ((cpu->cycles % 100) == 0) {
            vm_timer_tick(vm);
        }
        

        /* Fetch the rest of execution loop */
        uint8_t opc = mem[cpu->PC++];
        
        /* Decode & Execute */
        switch (opc) {

            /* ADC - Fixed flag setting */
            /* ADC - Add with Carry (with BCD support) */
            case 0x69: { /* ADC imm */
                uint8_t arg = mem[cpu->PC++];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    /* Determine carry out */
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    /* Z and N flags based on binary result (6502 quirk) */
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    /* Set ALL flags at once to avoid clobbering */
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x6D: { /* ADC abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x7D: { /* ADC abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x79: { /* ADC abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x65: { /* ADC zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t arg = mem[zaddr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x75: { /* ADC zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t arg = mem[zaddr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x71: { /* ADC (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }

            case 0x61: { /* ADC (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint8_t arg = mem[base];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int carry_in = (cpu->P & FLAG_C) ? 1 : 0;
                    int al = (cpu->A & 0x0F) + (arg & 0x0F) + carry_in;
                    int ah = (cpu->A >> 4) + (arg >> 4);
                    
                    if (al > 9) {
                        al -= 10;
                        ah++;
                    }
                    
                    uint8_t carry_out;
                    if (ah > 9) {
                        ah -= 10;
                        carry_out = FLAG_C;
                    } else {
                        carry_out = 0;
                    }
                    
                    uint16_t binary_sum = cpu->A + arg + carry_in;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_out |
                             ((binary_sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_sum & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    uint16_t sum = cpu->A + arg + (cpu->P & FLAG_C);
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (sum > 0xFF ? FLAG_C : 0) |
                             ((sum & 0xFF) == 0 ? FLAG_Z : 0) |
                             (~(cpu->A ^ arg) & (cpu->A ^ sum) & 0x80 ? FLAG_V : 0) |
                             (sum & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)sum;
                }
                break;
            }


            /* AND - Fixed flag setting */
            case 0x29: { /* AND imm */
                uint8_t arg = mem[cpu->PC++];
                cpu->A &= arg;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x2D: { /* AND abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->A &= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x3D: { /* AND abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                cpu->A &= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x25: { /* AND zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->A &= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x35: { /* AND zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                cpu->A &= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x31: { /* AND (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                cpu->A &= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x39: { /* AND abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                cpu->A &= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x21: { /* AND (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                cpu->A &= mem[base];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            /* ASL - Arithmetic Shift Left (Accumulator) */
            case 0x0A: { /* ASL A */
                uint8_t carry_out = (cpu->A & 0x80) ? FLAG_C : 0;
                cpu->A <<= 1;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            /* ASL - Arithmetic Shift Left (Memory) */
            case 0x0E: { /* ASL abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) {
                    uint8_t carry_out = (mem[addr] & 0x80) ? FLAG_C : 0;
                    mem[addr] <<= 1;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            case 0x1E: { /* ASL abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                if (addr < ROM_START) {
                    uint8_t carry_out = (mem[addr] & 0x80) ? FLAG_C : 0;
                    mem[addr] <<= 1;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            case 0x06: { /* ASL zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t carry_out = (mem[zaddr] & 0x80) ? FLAG_C : 0;
                mem[zaddr] <<= 1;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x16: { /* ASL zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t carry_out = (mem[zaddr] & 0x80) ? FLAG_C : 0;
                mem[zaddr] <<= 1;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            /* BIT - Bit Test */
            case 0x24: { /* BIT zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t value = mem[zaddr];
                uint8_t result = cpu->A & value;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_V|FLAG_N)) |
                         (result == 0 ? FLAG_Z : 0) |
                         (value & 0x40 ? FLAG_V : 0) |
                         (value & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x2C: { /* BIT abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t value = mem[addr];
                uint8_t result = cpu->A & value;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_V|FLAG_N)) |
                         (result == 0 ? FLAG_Z : 0) |
                         (value & 0x40 ? FLAG_V : 0) |
                         (value & 0x80 ? FLAG_N : 0);
                break;
            }

            /* Branch instructions */
            case 0x90: { /* BCC - Branch if Carry Clear */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (!(cpu->P & FLAG_C)) cpu->PC += offset;
                break;
            }
            case 0xB0: { /* BCS - Branch if Carry Set */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (cpu->P & FLAG_C) cpu->PC += offset;
                break;
            }

            /* Move the BPL/BMI/BVC/BVS cases lower, not to middle of the CMP cases. 
            Put them after all the CMP cases, near the other branch instructions (BCC/BCS/BEQ/BNE).
            Move lines containing cases 0x10, 0x30, 0x50, 0x70 from their current position 
            (around line 1990) to after all CMP cases are complete (around line 2085, before CPX starts)*/

            case 0x10: { /* BPL - Branch if Plus (N=0) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (!(cpu->P & FLAG_N)) cpu->PC += offset;
                break;
            }

            case 0x30: { /* BMI - Branch if Minus (N=1) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (cpu->P & FLAG_N) cpu->PC += offset;
                break;
            }

            case 0x50: { /* BVC - Branch if Overflow Clear (V=0) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (!(cpu->P & FLAG_V)) cpu->PC += offset;
                break;
            }

            case 0x70: { /* BVS - Branch if Overflow Set (V=1) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                if (cpu->P & FLAG_V) cpu->PC += offset;
                break;
            }

            /* CLC */
            case 0x18: cpu->P &= ~FLAG_C; break;

            /* CLD - Clear Decimal Mode */
            case 0xD8: cpu->P &= ~FLAG_D; break;

            /* CLI */
            case 0x58: cpu->P &= ~FLAG_I; break;

            /* CLV */
            case 0xB8: cpu->P &= ~FLAG_V; break;

            /* CMP - Fixed flag setting */
            case 0xC9: { /* CMP imm */
                uint8_t arg = mem[cpu->PC++];
                uint8_t diff = cpu->A - arg;
                
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                         
                break;
            }
            
            case 0xCD: { /* CMP abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xDD: { /* CMP abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xC5: { /* CMP zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t arg = mem[zaddr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xD5: { /* CMP zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t arg = mem[zaddr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xD1: { /* CMP (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0xD9: { /* CMP abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xC1: { /* CMP (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint8_t arg = mem[base];
                uint8_t diff = cpu->A - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->A >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }

             /* CPX - Compare X Register */
            case 0xE0: { /* CPX imm */
                uint8_t arg = mem[cpu->PC++];
                uint8_t diff = cpu->X - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->X >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xEC: { /* CPX abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->X - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->X >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xE4: { /* CPX zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t arg = mem[zaddr];
                uint8_t diff = cpu->X - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->X >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }

            /* CPY - Compare Y Register */
            case 0xC0: { /* CPY imm */
                uint8_t arg = mem[cpu->PC++];
                uint8_t diff = cpu->Y - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->Y >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xCC: { /* CPY abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t arg = mem[addr];
                uint8_t diff = cpu->Y - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->Y >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xC4: { /* CPY zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t arg = mem[zaddr];
                uint8_t diff = cpu->Y - arg;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         (cpu->Y >= arg ? FLAG_C : 0) |
                         (diff == 0 ? FLAG_Z : 0) |
                         (diff & 0x80 ? FLAG_N : 0);
                break;
            }

            /* DEC - Decrement Memory */
            case 0xCE: { /* DEC abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) {
                    mem[addr]--;
                    cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }
            case 0xDE: { /* DEC abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                if (addr < ROM_START) {
                    mem[addr]--;
                    cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }
            case 0xC6: { /* DEC zp */
                uint8_t zaddr = mem[cpu->PC++];
                mem[zaddr]--;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xD6: { /* DEC zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                mem[zaddr]--;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            /* DEX - Fixed flag setting */
            case 0xCA: 
                cpu->X--;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;

            /* DEY - Fixed flag setting */
            case 0x88:
                cpu->Y--;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;

            /* EOR - Exclusive OR */
            case 0x49: { /* EOR imm */
                uint8_t arg = mem[cpu->PC++];
                cpu->A ^= arg;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x4D: { /* EOR abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->A ^= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x5D: { /* EOR abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                cpu->A ^= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x45: { /* EOR zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->A ^= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x55: { /* EOR zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                cpu->A ^= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x51: { /* EOR (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                cpu->A ^= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x59: { /* EOR abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                cpu->A ^= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x41: { /* EOR (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                cpu->A ^= mem[base];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            /* INC - Increment Memory */
            case 0xEE: { /* INC abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) {
                    mem[addr]++;
                    cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }
            case 0xFE: { /* INC abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                if (addr < ROM_START) {
                    mem[addr]++;
                    cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }
            case 0xE6: { /* INC zp */
                uint8_t zaddr = mem[cpu->PC++];
                mem[zaddr]++;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xF6: { /* INC zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                mem[zaddr]++;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }


            /* INX - Fixed flag setting */
            case 0xE8:
                cpu->X++;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;

            /* INY - Fixed flag setting */
            case 0xC8:
                cpu->Y++;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;

            /* JMP */
            case 0x4C: {
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC = addr;
                break;
            }

            /* JMP (indirect) */
            case 0x6C: { /* JMP (indirect) */
                uint16_t ptr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                /* 6502 bug: if ptr is $xxFF, high byte wraps to $xx00 */
                uint8_t lo = mem[ptr];
                uint8_t hi;
                if ((ptr & 0xFF) == 0xFF) {
                    hi = mem[ptr & 0xFF00];  // Bug: wraps within page
                } else {
                    hi = mem[ptr + 1];
                }
                cpu->PC = lo | (hi << 8);
                break;
            }

            /* JSR */
            case 0x20: { /* JSR */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t ret_addr = cpu->PC - 1;  // 6502 convention: push PC-1

                /* SECURITY FIX: Use safe stack operations */
                if (!stack_push(vm, (uint8_t)(ret_addr >> 8))) return;  /* Push high byte */
                if (!stack_push(vm, (uint8_t)ret_addr)) return;         /* Push low byte */

                cpu->PC = addr;
                break;
            }

            /* LDA - Fixed flag setting */
            case 0xA9: { /* LDA imm */
                cpu->A = mem[cpu->PC++];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xAD: { /* LDA abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->A = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xBD: { /* LDA abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                cpu->A = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xA5: { /* LDA zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->A = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xB5: { /* LDA zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                cpu->A = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xB1: { /* LDA (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                cpu->A = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0xB9: { /* LDA abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                cpu->A = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xA1: { /* LDA (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                cpu->A = mem[base];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            /* LDX - Fixed flag setting */
            case 0xA2: { /* LDX imm */
                cpu->X = mem[cpu->PC++];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xAE: { /* LDX abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->X = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xBE: { /* LDX abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                cpu->X = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xA6: { /* LDX zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->X = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;
            }

            /* LDY - Fixed flag setting */
            case 0xA0: { /* LDY imm */
                cpu->Y = mem[cpu->PC++];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xAC: { /* LDY abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->Y = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xBC: { /* LDY abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                cpu->Y = mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xA4: { /* LDY zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->Y = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0xB4: { /* LDY zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                cpu->Y = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0xB6: { /* LDX zp,Y */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->Y) & 0xFF;
                cpu->X = mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x4A: { /* LSR A */
                uint8_t carry_out = (cpu->A & 1) ? FLAG_C : 0;
                cpu->A >>= 1;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (cpu->A == 0 ? FLAG_Z : 0);
                /* N is always 0 after LSR since bit 7 of result is 0 */
                break;
            }            

            /* ORA - Fixed flag setting */
            case 0x09: { /* ORA imm */
                uint8_t arg = mem[cpu->PC++];
                cpu->A |= arg;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x0D: { /* ORA abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                cpu->A |= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x1D: { /* ORA abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                cpu->A |= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x05: { /* ORA zp */
                uint8_t zaddr = mem[cpu->PC++];
                cpu->A |= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x15: { /* ORA zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                cpu->A |= mem[zaddr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x11: { /* ORA (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                cpu->A |= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x19: { /* ORA abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                cpu->A |= mem[addr];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }
            case 0x01: { /* ORA (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                cpu->A |= mem[base];
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            /* PHP - Push Processor Status */
            case 0x08: {
                /* SECURITY FIX: Use safe stack push */
                if (!stack_push(vm, cpu->P | FLAG_B)) return;  /* B flag set when pushed by PHP */
                break;
            }

            /* PLP - Pull Processor Status */
            case 0x28: {
                /* SECURITY FIX: Use safe stack pop */
                uint8_t temp;
                if (!stack_pop(vm, &temp)) return;
                cpu->P = temp;
                cpu->P |= FLAG_U;   /* U flag always set */
                cpu->P &= ~FLAG_B;  /* B flag always clear after PLP */
                break;
            }

            /* ROL - Rotate Left */
            case 0x2A: { /* ROL A */
                uint8_t old_carry = (cpu->P & FLAG_C) ? 1 : 0;
                uint8_t carry_out = (cpu->A & 0x80) ? FLAG_C : 0;
                cpu->A = (cpu->A << 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x26: { /* ROL zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t old_carry = (cpu->P & FLAG_C) ? 1 : 0;
                uint8_t carry_out = (mem[zaddr] & 0x80) ? FLAG_C : 0;
                mem[zaddr] = (mem[zaddr] << 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x36: { /* ROL zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t old_carry = (cpu->P & FLAG_C) ? 1 : 0;
                uint8_t carry_out = (mem[zaddr] & 0x80) ? FLAG_C : 0;
                mem[zaddr] = (mem[zaddr] << 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x2E: { /* ROL abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) {
                    uint8_t old_carry = (cpu->P & FLAG_C) ? 1 : 0;
                    uint8_t carry_out = (mem[addr] & 0x80) ? FLAG_C : 0;
                    mem[addr] = (mem[addr] << 1) | old_carry;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            case 0x3E: { /* ROL abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                if (addr < ROM_START) {
                    uint8_t old_carry = (cpu->P & FLAG_C) ? 1 : 0;
                    uint8_t carry_out = (mem[addr] & 0x80) ? FLAG_C : 0;
                    mem[addr] = (mem[addr] << 1) | old_carry;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            /* ROR - Rotate Right */
            case 0x6A: { /* ROR A */
                uint8_t old_carry = (cpu->P & FLAG_C) ? 0x80 : 0;
                uint8_t carry_out = (cpu->A & 1) ? FLAG_C : 0;
                cpu->A = (cpu->A >> 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x66: { /* ROR zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t old_carry = (cpu->P & FLAG_C) ? 0x80 : 0;
                uint8_t carry_out = (mem[zaddr] & 1) ? FLAG_C : 0;
                mem[zaddr] = (mem[zaddr] >> 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x76: { /* ROR zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t old_carry = (cpu->P & FLAG_C) ? 0x80 : 0;
                uint8_t carry_out = (mem[zaddr] & 1) ? FLAG_C : 0;
                mem[zaddr] = (mem[zaddr] >> 1) | old_carry;
                cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                         carry_out |
                         (mem[zaddr] == 0 ? FLAG_Z : 0) |
                         (mem[zaddr] & 0x80 ? FLAG_N : 0);
                break;
            }

            case 0x6E: { /* ROR abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) {
                    uint8_t old_carry = (cpu->P & FLAG_C) ? 0x80 : 0;
                    uint8_t carry_out = (mem[addr] & 1) ? FLAG_C : 0;
                    mem[addr] = (mem[addr] >> 1) | old_carry;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            case 0x7E: { /* ROR abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                if (addr < ROM_START) {
                    uint8_t old_carry = (cpu->P & FLAG_C) ? 0x80 : 0;
                    uint8_t carry_out = (mem[addr] & 1) ? FLAG_C : 0;
                    mem[addr] = (mem[addr] >> 1) | old_carry;
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_N)) |
                             carry_out |
                             (mem[addr] == 0 ? FLAG_Z : 0) |
                             (mem[addr] & 0x80 ? FLAG_N : 0);
                }
                break;
            }

            /* RTI - Return from Interrupt (UPDATED) */
            case 0x40: { /* RTI */
                /* SECURITY FIX: Use safe stack pop */
                uint8_t status, lo, hi;
                if (!stack_pop(vm, &status)) return;  /* Pop status flags first */
                cpu->P = status;
                cpu->P |= FLAG_U;
                if (!stack_pop(vm, &lo)) return;      /* Pop low byte */
                if (!stack_pop(vm, &hi)) return;      /* Pop high byte */
                cpu->PC = lo | (hi << 8);
                break;
            }

            /* RTS */
            case 0x60: { /* RTS */
                /* SECURITY FIX: Use safe stack pop */
                uint8_t lo, hi;
                if (!stack_pop(vm, &lo)) return;   /* Pop low byte */
                if (!stack_pop(vm, &hi)) return;   /* Pop high byte */
                cpu->PC = (lo | (hi << 8)) + 1;
                break;
            }

            /* SBC - Subtract with Carry */
            /* SBC - Subtract with Carry (with BCD support) */

            case 0xE9: { /* SBC imm */
                uint8_t arg = mem[cpu->PC++];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    /* Determine carry flag */
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;  /* Borrow occurred - clear carry */
                    } else {
                        carry_flag = FLAG_C;  /* No borrow - set carry */
                    }
                    
                    /* Z and N flags based on binary result (6502 quirk) */
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    /* Set ALL flags at once to avoid clobbering carry */
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xED: { /* SBC abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xFD: { /* SBC abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xE5: { /* SBC zp */
                uint8_t zaddr = mem[cpu->PC++];
                uint8_t arg = mem[zaddr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xF5: { /* SBC zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint8_t arg = mem[zaddr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xF1: { /* SBC (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xF9: { /* SBC abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                uint8_t arg = mem[addr];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            case 0xE1: { /* SBC (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint8_t arg = mem[base];
                
                if (cpu->P & FLAG_D) {
                    /* BCD mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int al = (cpu->A & 0x0F) - (arg & 0x0F) - borrow;
                    int ah = (cpu->A >> 4) - (arg >> 4);
                    
                    if (al < 0) {
                        al += 10;
                        ah--;
                    }
                    
                    uint8_t carry_flag;
                    if (ah < 0) {
                        ah += 10;
                        carry_flag = 0;
                    } else {
                        carry_flag = FLAG_C;
                    }
                    
                    int binary_result = (int)cpu->A - (int)arg - borrow;
                    uint8_t result = (ah << 4) | (al & 0x0F);
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             carry_flag |
                             (((uint8_t)binary_result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (binary_result & 0x80 ? FLAG_N : 0);
                    
                    cpu->A = result;
                } else {
                    /* Binary mode */
                    int borrow = (cpu->P & FLAG_C) ? 0 : 1;
                    int result = (int)cpu->A - (int)arg - borrow;
                    
                    cpu->P = (cpu->P & ~(FLAG_C|FLAG_Z|FLAG_V|FLAG_N)) |
                             (result >= 0 ? FLAG_C : 0) |
                             (((uint8_t)result) == 0 ? FLAG_Z : 0) |
                             ((cpu->A ^ arg) & (cpu->A ^ result) & 0x80 ? FLAG_V : 0) |
                             (result & 0x80 ? FLAG_N : 0);
                    cpu->A = (uint8_t)result;
                }
                break;
            }

            /* SEC */
            case 0x38: cpu->P |= FLAG_C; break;

            /* SED - Set Decimal Mode */
            case 0xF8: cpu->P |= FLAG_D; break;

            /* SEI */
            case 0x78: cpu->P |= FLAG_I; break;

            /* STA - Store Accumulator */
            case 0x8D: { /* STA abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                w8(vm, addr, cpu->A);
                break;
            }

            case 0x9D: { /* STA abs,X */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->X;
                w8(vm, addr, cpu->A);
                break;
            }

            case 0x85: { /* STA zp */
                uint8_t zaddr = mem[cpu->PC++];
                w8(vm, zaddr, cpu->A);
                break;
            }

            case 0x95: { /* STA zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                w8(vm, zaddr, cpu->A);
                break;
            }

            case 0x91: { /* STA (zp),Y */
                uint8_t zaddr = mem[cpu->PC++];
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                uint16_t addr = base + cpu->Y;
                w8(vm, addr, cpu->A);
                break;
            }

            case 0x99: { /* STA abs,Y */
                uint16_t base = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                uint16_t addr = base + cpu->Y;
                w8(vm, addr, cpu->A);
                break;
            }
            case 0x81: { /* STA (zp,X) */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                uint16_t base = mem[zaddr] | (mem[(zaddr+1)&0xFF] << 8);
                w8(vm, base, cpu->A);
                break;
            }

            /* STX */
            case 0x8E: { /* STX abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) mem[addr] = cpu->X;
                break;
            }
            case 0x86: { /* STX zp */
                uint8_t zaddr = mem[cpu->PC++];
                mem[zaddr] = cpu->X;
                break;
            }

            /* STY */
            case 0x8C: { /* STY abs */
                uint16_t addr = mem[cpu->PC] | (mem[cpu->PC+1] << 8);
                cpu->PC += 2;
                if (addr < ROM_START) mem[addr] = cpu->Y;
                break;
            }
            case 0x84: { /* STY zp */
                uint8_t zaddr = mem[cpu->PC++];
                mem[zaddr] = cpu->Y;
                break;
            }
            case 0x94: { /* STY zp,X */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->X) & 0xFF;
                mem[zaddr] = cpu->Y;
                break;
            }

            case 0x96: { /* STX zp,Y */
                uint8_t zaddr = (mem[cpu->PC++] + cpu->Y) & 0xFF;
                mem[zaddr] = cpu->X;
                break;
            }

            /* SYS - FIXED: Always consume operand byte */
            case 0x02: {
                uint8_t sysnum = mem[cpu->PC++];
                
                switch (sysnum) {
                    case SYS_PUTCHAR: fputc((int)cpu->A, stdout); fflush(stdout); break;
                    case SYS_GETCHAR: {
                        int ch = fgetc(stdin);
                        cpu->A = (ch == EOF) ? 0 : (uint8_t)ch;
                        break;
                    }

                    case SYS_PRINT: {
                        /* SECURITY FIX: Add bounds checking to prevent infinite loop and wraparound */
                        uint16_t addr = cpu->X | (cpu->Y << 8);
                        uint16_t count = 0;
                        const uint16_t MAX_PRINT = 4096;  /* Limit output to 4KB */

                        while (mem[addr] && count < MAX_PRINT) {
                            fputc((int)mem[addr], stdout);
                            count++;
                            /* SECURITY FIX: Prevent address wraparound */
                            if (addr == 0xFFFF) break;
                            addr++;
                        }
                        fflush(stdout);
                        break;
                    }

                    case SYS_READLN: {
                        /* SECURITY FIX: Validate buffer address and length */
                        uint16_t addr = cpu->X | (cpu->Y << 8);
                        int maxlen = cpu->A;

                        /* SECURITY FIX: Validate maxlen is reasonable */
                        if (maxlen <= 0 || maxlen > 255) {
                            maxlen = 255;
                        }

                        char buffer[256];
                        char* result = fgets(buffer, maxlen + 1, stdin);

                        if (result) {
                            int len = 0;
                            while (buffer[len] && buffer[len] != '\n' && len < maxlen) {
                                mem[addr++] = (uint8_t)buffer[len];
                                len++;
                            }
                            mem[addr] = 0;
                            cpu->A = (uint8_t)len;
                        } else {
                            mem[addr] = 0;
                            cpu->A = 0;
                        }
                        break;
                    }
                    
                    case SYS_PUTNUM: {
                        printf("%d", cpu->A);
                        fflush(stdout);
                        break;
                    }

                    case SYS_GETNUM: {
                        int num = 0;
                        if (scanf("%d", &num) == 1) {
                            cpu->A = (uint8_t)(num & 0xFF);
                            /* Consume the newline left by scanf */
                            int ch;
                            while ((ch = getchar()) != '\n' && ch != EOF) {
                                /* consume until newline */
                            }
                        } else {
                            cpu->A = 0;
                            /* Clear to newline on error */
                            int ch;
                            while ((ch = getchar()) != '\n' && ch != EOF) {
                                /* consume until newline */
                            }
                        }
                        break;
                    }

                    default: break;
                }
                break;
            }

            /* TAX - Fixed flag setting */
            case 0xAA:
                cpu->X = cpu->A;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;

            /* TAY - Fixed flag setting */
            case 0xA8:
                cpu->Y = cpu->A;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->Y == 0 ? FLAG_Z : 0) |
                         (cpu->Y & 0x80 ? FLAG_N : 0);
                break;

            /* TXA - Fixed flag setting */
            case 0x8A:
                cpu->A = cpu->X;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;

            /* TSX - Transfer Stack Pointer to X */
            case 0xBA:
                cpu->X = cpu->SP;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->X == 0 ? FLAG_Z : 0) |
                         (cpu->X & 0x80 ? FLAG_N : 0);
                break;

            /* TXS - Transfer X to Stack Pointer */
            case 0x9A:
                cpu->SP = cpu->X;
                break;

            /* TYA - Fixed flag setting */
            case 0x98:
                cpu->A = cpu->Y;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;

            /* Branch instructions */
            case 0xD0: { /* BNE (JNZ) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                
                if (!(cpu->P & FLAG_Z)) cpu->PC += offset;
                break;
            }

            case 0xF0: { /* BEQ (JZ) */
                int8_t offset = (int8_t)mem[cpu->PC++];
                                
                if (cpu->P & FLAG_Z) cpu->PC += offset;                
                break;
            }

            /* Fixed Stack instructions */
            case 0x48: { /* PHA */
                /* SECURITY FIX: Use safe stack push */
                if (!stack_push(vm, cpu->A)) return;
                break;
            }

            case 0x68: { /* PLA - Fixed flag setting */
                /* SECURITY FIX: Use safe stack pop */
                if (!stack_pop(vm, &cpu->A)) return;
                cpu->P = (cpu->P & ~(FLAG_Z|FLAG_N)) |
                         (cpu->A == 0 ? FLAG_Z : 0) |
                         (cpu->A & 0x80 ? FLAG_N : 0);
                break;
            }


            /* NOP - No Operation */
            case 0xEA: break;  /* NOP - do nothing, just advance PC */
 
            /* BRK - Software Interrupt / Halt */
            case 0x00: { /* BRK */
                uint16_t brk_vec = mem[VEC_IRQ] | (mem[VEC_IRQ + 1] << 8);
                
                if (vm->debug) {
                    fprintf(stderr, "\nBRK at $%04X, vector=$%04X\n", cpu->PC, brk_vec);
                }
                                
                /* Safe halt conditions:
                 * 1. Vector is 0x0000 (uninitialized)
                 * 2. Vector points below $0200 (likely garbage/uninitialized RAM)
                 * 3. Vector points to ROM area but ROM is empty (0x0000)
                 */

                if (brk_vec == 0x0000 || brk_vec < 0x0200) {
                    if (vm->debug) {
                        fprintf(stderr, "Halting (invalid vector)\n");
                    }
                    return;
                }
                                
                /* Valid BRK vector found - execute as software interrupt */

                /* Increment PC by 2 (BRK is 2-byte instruction with signature byte) */
                cpu->PC += 2;

                /* SECURITY FIX: Use safe stack operations */
                if (!stack_push(vm, (uint8_t)(cpu->PC >> 8))) return;  /* Push PC high byte */
                if (!stack_push(vm, (uint8_t)cpu->PC)) return;         /* Push PC low byte */
                if (!stack_push(vm, cpu->P | FLAG_B)) return;          /* Push status with B flag SET */

                /* Set interrupt disable flag */
                cpu->P |= FLAG_I;

                /* Jump to BRK/IRQ vector */
                cpu->PC = brk_vec;
                
                break;
            }

            default: {
                fprintf(stderr, "\nUnknown opcode $%02X at $%04X\n", opc, cpu->PC - 1);
                fprintf(stderr, "Registers: A=$%02X X=$%02X Y=$%02X P=$%02X SP=$%02X\n",
                        cpu->A, cpu->X, cpu->Y, cpu->P, cpu->SP);
                fprintf(stderr, "Next bytes: $%02X $%02X $%02X\n",
                        mem[cpu->PC], mem[cpu->PC + 1], mem[cpu->PC + 2]);
                
                /* Option: Try to continue by skipping the bad instruction */
                if (vm->debug) {
                    fprintf(stderr, "Attempting to continue...\n");
                    cpu->PC++;  // Skip bad opcode
                    break;
                }
                
                return;  // Halt on unknown opcode
            }
        }
    }
}

/* File I/O */
static char* slurp_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* SECURITY FIX: Validate file size to prevent buffer overflow and resource exhaustion */
    #define MAX_FILE_SIZE (10 * 1024 * 1024)  /* 10MB maximum */
    if (len < 0) {
        fprintf(stderr, "Error: Cannot determine file size for '%s'\n", path);
        fclose(f);
        return NULL;
    }
    if (len > MAX_FILE_SIZE) {
        fprintf(stderr, "Error: File '%s' too large (%ld bytes, max %d bytes)\n",
                path, len, MAX_FILE_SIZE);
        fclose(f);
        return NULL;
    }

    /* SECURITY FIX: Check for integer overflow before malloc */
    if (len >= LONG_MAX - 1) {
        fprintf(stderr, "Error: File size would cause integer overflow\n");
        fclose(f);
        return NULL;
    }

    char* buf = (char*)malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "Error: Out of memory reading file\n");
        fclose(f);
        return NULL;
    }

    size_t bytes_read = fread(buf, 1, (size_t)len, f);
    if (bytes_read != (size_t)len) {
        fprintf(stderr, "Error: Failed to read complete file\n");
        free(buf);
        fclose(f);
        return NULL;
    }

    buf[len] = '\0';
    fclose(f);
    return buf;
}

/* Enhanced save_rom with detailed debugging */
static int save_rom(VM* vm, const char* path, uint16_t start, uint16_t end) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot open %s for writing\n", path);
        return 0;
    }
    
    uint16_t length = end - start + 1;
    
    printf("\n=== SAVE_ROM DEBUG ===\n");
    printf("Start: $%04X, End: $%04X, Length: %u ($%04X)\n", start, end, length, length);
    printf("Header bytes to write: %02X %02X %02X %02X\n",
           start & 0xFF, start >> 8, length & 0xFF, length >> 8);
    
    /* Show what's at the vector locations BEFORE writing */
    printf("Memory at vectors before save:\n");
    printf("  $FFFC = $%02X, $FFFD = $%02X\n", vm->mem[0xFFFC], vm->mem[0xFFFD]);
    
    /* Write header */
    fputc(start & 0xFF, f);
    fputc(start >> 8, f);
    fputc(length & 0xFF, f);
    fputc(length >> 8, f);
    
    /* Write data */
    size_t written = fwrite(&vm->mem[start], 1, length, f);
    fclose(f);
    
    printf("Bytes written: %zu (expected %u)\n", written, length);
    
    if (written != length) {
        fprintf(stderr, "Error writing ROM image\n");
        return 0;
    }
    
    /* Verify by reading back the file */
    f = fopen(path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        printf("File size on disk: %ld bytes (header=4 + data=%u = %u)\n", 
               file_size, length, length + 4);
        
        /* Read the end of the file to verify vectors were written */
        fseek(f, file_size - 6, SEEK_SET);
        printf("Last 6 bytes of file: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X ", fgetc(f));
        }
        printf("\n");
        fclose(f);
    }
    printf("===================\n\n");
    
    printf("ROM saved: $%04X-$%04X (%u bytes) to %s\n", 
           start, end, length, path);
    return 1;
}

/* Enhanced load_rom with detailed debugging */
static int load_rom(VM* vm, const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open ROM file %s\n", path);
        return 0;
    }
    
    printf("\n=== LOAD_ROM DEBUG ===\n");
    
    /* Check file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("File size: %ld bytes\n", file_size);
    
    /* Read header */
    int b0 = fgetc(f);
    int b1 = fgetc(f);
    int b2 = fgetc(f);
    int b3 = fgetc(f);
    
    printf("Header bytes read: %02X %02X %02X %02X\n", b0, b1, b2, b3);
    
    if (b0 == EOF || b1 == EOF || b2 == EOF || b3 == EOF) {
        fprintf(stderr, "Invalid ROM file format\n");
        fclose(f);
        return 0;
    }
    
    uint16_t start = b0 | (b1 << 8);
    uint16_t length = b2 | (b3 << 8);

    printf("Decoded: Start=$%04X, Length=%u ($%04X)\n", start, length, length);

    /* SECURITY FIX: Validate ROM region with proper overflow checking */
    if (start < ROM_START) {
        fprintf(stderr, "ROM start address must be >= $C000\n");
        fclose(f);
        return 0;
    }

    /* SECURITY FIX: Check for integer overflow before addition */
    if (length > 0x10000 - start) {
        fprintf(stderr, "ROM length would exceed memory bounds (start=$%04X, length=%u)\n",
                start, length);
        fclose(f);
        return 0;
    }

    /* SECURITY FIX: Validate actual file contains claimed data */
    long expected_file_size = 4 + (long)length;  /* 4-byte header + data */
    if (file_size < expected_file_size) {
        fprintf(stderr, "ROM file too small: expected %ld bytes, got %ld bytes\n",
                expected_file_size, file_size);
        fclose(f);
        return 0;
    }

    printf("Will load to memory range: $%04X-$%04X\n", start, (uint16_t)(start + length - 1));
    
    /* Read last 6 bytes of file to verify vectors are present */
    long data_start = ftell(f);
    fseek(f, file_size - 6, SEEK_SET);
    printf("Last 6 bytes of file data: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X ", fgetc(f));
    }
    printf("\n");
    fseek(f, data_start, SEEK_SET);
    
    /* Load directly into memory */
    size_t read = fread(&vm->mem[start], 1, length, f);
    fclose(f);
    
    printf("Bytes read: %zu (expected %u)\n", read, length);
    
    if (read != length) {
        fprintf(stderr, "Error reading ROM image (expected %u, got %zu)\n", 
                length, read);
        return 0;
    }
    
    /* Verify what ended up in memory at vector locations */
    printf("Memory at vectors after load:\n");
    printf("  $FFFC = $%02X, $FFFD = $%02X\n", vm->mem[0xFFFC], vm->mem[0xFFFD]);
    printf("  Decoded reset vector: $%04X\n", vm->mem[0xFFFC] | (vm->mem[0xFFFD] << 8));
    printf("===================\n\n");
    
    printf("ROM loaded: $%04X-$%04X (%u bytes) from %s\n", 
           start, (uint16_t)(start + length - 1), length, path);
    return 1;
}


/* Main Driver */
static int load_and_run(VM* vm, const char* asm_src, int trace, int disasm_only, int debug, int stats) {
    memset(vm->mem, 0, RAM_SIZE);
    vm->trace = trace;
    vm->disasm_only = disasm_only;
    vm->debug = debug;
    vm->stats = stats;

    if (!assemble(vm, asm_src, 0x0200)) {
        fprintf(stderr, "Assembly failed.\n");
        return 1;
    }

    if (disasm_only) {

        /* Show raw hex dump for debugging */
        fprintf(stderr, "\n=== Raw Memory Dump $0220-$0230 ===\n");
        for (int i = 0x0220; i < 0x0231; i++) {
            fprintf(stderr, "%04X: %02X\n", i, vm->mem[i]);
        }
        fprintf(stderr, "\n");
                
        /* Disassembly output */
        uint16_t pc = 0x0200;
        while (pc <= vm->code_end) {
            uint8_t opc = vm->mem[pc];
            
            /* Handle BRK - stop after first one */
            if (opc == 0x00) {
                printf("%04X: BRK\n", pc); 
                pc++;
                break;  /* CHANGED: From continue to break. Stop disassembly after first BRK */
            }

            /* Handle implied-mode instructions first */
            switch (opc) {
                case 0x0A: printf("%04X: ASL\n", pc); pc++; continue;
                case 0x18: printf("%04X: CLC\n", pc); pc++; continue;
                case 0xD8: printf("%04X: CLD\n", pc); pc++; continue;
                case 0x58: printf("%04X: CLI\n", pc); pc++; continue;
                case 0xB8: printf("%04X: CLV\n", pc); pc++; continue;
                case 0xCA: printf("%04X: DEX\n", pc); pc++; continue;
                case 0x88: printf("%04X: DEY\n", pc); pc++; continue;
                case 0xC8: printf("%04X: INY\n", pc); pc++; continue;
                case 0xE8: printf("%04X: INX\n", pc); pc++; continue;
                case 0x4A: printf("%04X: LSR\n", pc); pc++; continue;
                case 0xEA: printf("%04X: NOP\n", pc); pc++; continue;                    
                case 0x48: printf("%04X: PHA\n", pc); pc++; continue;
                case 0x08: printf("%04X: PHP\n", pc); pc++; continue;
                case 0x68: printf("%04X: PLA\n", pc); pc++; continue;
                case 0x28: printf("%04X: PLP\n", pc); pc++; continue;
                case 0x2A: printf("%04X: ROL\n", pc); pc++; continue;
                case 0x6A: printf("%04X: ROR\n", pc); pc++; continue;                    
                case 0x40: printf("%04X: RTI\n", pc); pc++; continue;
                case 0x60: printf("%04X: RTS\n", pc); pc++; continue;
                case 0x38: printf("%04X: SEC\n", pc); pc++; continue;
                case 0xF8: printf("%04X: SED\n", pc); pc++; continue;
                case 0x78: printf("%04X: SEI\n", pc); pc++; continue;
                case 0xAA: printf("%04X: TAX\n", pc); pc++; continue;
                case 0xA8: printf("%04X: TAY\n", pc); pc++; continue;
                case 0x8A: printf("%04X: TXA\n", pc); pc++; continue;
                case 0xBA: printf("%04X: TSX\n", pc); pc++; continue;  // ADD THIS
                case 0x9A: printf("%04X: TXS\n", pc); pc++; continue;  // ADD THIS                    
                case 0x98: printf("%04X: TYA\n", pc); pc++; continue;
                case 0x90: printf("%04X: BCC $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0xB0: printf("%04X: BCS $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0x10: printf("%04X: BPL $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0x30: printf("%04X: BMI $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0x50: printf("%04X: BVC $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0x70: printf("%04X: BVS $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0xD0: printf("%04X: JNZ $%04X\n", pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0xF0: printf("%04X: JZ $%04X\n",  pc, (uint16_t)(pc + 2 + (int8_t)vm->mem[pc+1])); pc += 2; continue;
                case 0x6C: { /* JMP Indirect */
                    uint16_t addr = vm->mem[pc+1] | (vm->mem[pc+2] << 8);
                    printf("%04X: JMP ($%04X)\n", pc, addr);
                    pc += 3;
                    continue;
                }
            }
            
            const Spec* sp = NULL;
            for (int i = 0; SPECS[i].mnem; i++) {
                if (SPECS[i].op_imm == opc || SPECS[i].op_abs == opc || 
                    SPECS[i].op_abs_x == opc || SPECS[i].op_zp == opc ||
                    SPECS[i].op_zp_x == opc || SPECS[i].op_indzp_y == opc) {
                    sp = &SPECS[i];
                    break;
                }
            }
            
            if (!sp) {
                /* Not a recognized instruction - display as .BYTE */
                printf("%04X: .BYTE $%02X\n", pc, opc);
                pc++;
                continue;
            }

            printf("%04X: %s", pc, sp->mnem);
            pc++;

            /* Determine addressing mode and print operand */
            if (opc == sp->op_imm) {
                printf(" #$%02X\n", vm->mem[pc++]);
            } else if (opc == sp->op_zp || opc == sp->op_zp_x || opc == sp->op_zp_y) {
                printf(" $%02X", vm->mem[pc++]);
                if (opc == sp->op_zp_x) printf(",X");
                if (opc == sp->op_zp_y) printf(",Y");
                printf("\n");
            } else if (opc == sp->op_abs || opc == sp->op_abs_x || opc == sp->op_abs_y) {
                uint16_t addr = vm->mem[pc] | (vm->mem[pc+1] << 8);
                printf(" $%04X", addr);
                if (opc == sp->op_abs_x) printf(",X");
                if (opc == sp->op_abs_y) printf(",Y");
                printf("\n");
                pc += 2;
            } else if (opc == sp->op_indzp_y) {
                printf(" ($%02X),Y\n", vm->mem[pc++]);
            } else if (opc == sp->op_indx_zp) {
                printf(" ($%02X,X)\n", vm->mem[pc++]);
            } else {
                printf("\n");
            }
        }
        return 0;
    }

    // Removed w8_raw(vm, VEC_IRQ + 1, 0x03); w8_raw(vm, VEC_IRQ, 0x00); w8_raw(vm, VEC_IRQ, 0x00);
    w8_raw(vm, VEC_IRQ, 0x00);
    w8_raw(vm, VEC_IRQ + 1, 0x00);  
    w8_raw(vm, VEC_RESET, 0x00);
    w8_raw(vm, VEC_RESET + 1, 0x02);

    vm_reset(vm, 0x0200);

    /* ADD THIS VALIDATION CHECK HERE */
    if (debug && !validate_vm_state(vm)) {
        return 1;
    }

    cpu_execute(vm);

    if (stats) {
        printf("\n=== Statistics ===\n");
        printf("Cycles: %llu\n", vm->cpu.cycles);
    }

    return 0;
}


static void print_help(const char* program_name) {
    printf("Tiny8VM - Educational 8-bit Virtual Machine with 6502-like CPU\n\n");
    
    printf("USAGE:\n");
    printf("  %s <command> [options]\n\n", program_name);
    
    printf("COMMANDS:\n\n");
    
    printf("  Assembly and Execution:\n");
    printf("    %s <program.asm> [options]\n", program_name);
    printf("        Assemble and run a program from source\n");
    printf("        Options: --trace  --disasm  --debug  --stats\n\n");
    
    printf("  ROM Operations:\n");
    printf("    %s --makerom <input.asm> <output.rom> [start] [end]\n", program_name);
    printf("        Assemble source and create ROM image\n");
    printf("        Defaults: start=$C000, end=$FFEF\n");
    printf("        Example: %s --makerom kernel.asm kernel.rom\n", program_name);
    
    printf("    %s --rom <rom.bin> [options]\n", program_name);
    printf("        Load and execute a ROM image\n");
    printf("        Options: --trace  --stats\n\n");
    
    printf("  Help:\n");
    printf("    %s --help\n", program_name);
    printf("    %s -h\n", program_name);
    printf("        Display this help message\n\n");
    
    printf("OPTIONS:\n");
    printf("  --trace      Show instruction trace during execution\n");
    printf("  --disasm     Disassemble only (don't execute)\n");
    printf("  --debug      Enable debug output\n");
    printf("  --stats      Show execution statistics after completion\n\n");
    
    printf("MEMORY MAP:\n");
    printf("  $0000-$7FFF  RAM (32KB)\n");
    printf("  $8000-$BFFF  Memory-mapped I/O (16KB)\n");
    printf("  $C000-$FFEF  ROM (16KB - 16 bytes)\n");
    printf("  $FFFA-$FFFB  NMI vector\n");
    printf("  $FFFC-$FFFD  RESET vector\n");
    printf("  $FFFE-$FFFF  IRQ/BRK vector\n\n");
    
    printf("I/O REGISTERS:\n");
    printf("  $8000  Output register (write only)\n");
    printf("  $8001  Input register (read only)\n");
    printf("  $8010  Timer control\n");
    printf("  $8011  Timer counter\n");
    printf("  $8020  NMI trigger\n\n");
    
    printf("SYSCALLS (SYS #n):\n");
    printf("  0  PUTCHAR  - Output character in A\n");
    printf("  1  GETCHAR  - Read character into A\n");
    printf("  2  PRINT    - Print null-terminated string at (X,Y)\n");
    printf("  3  READLN   - Read line into buffer at (X,Y), max length in A\n");
    printf("  4  PUTNUM   - Print decimal number in A\n");
    printf("  5  GETNUM   - Read decimal number into A\n\n");
    
    printf("ASSEMBLER DIRECTIVES:\n");
    printf("  .ORG addr        Set assembly address\n");
    printf("  .EQU name, val   Define constant\n");
    printf("  .BYTE values     Define byte(s)\n");
    printf("  .WORD values     Define word(s)\n");
    printf("  .ASCIIZ \"text\"   Define null-terminated string\n");
    printf("  .FILL n, val     Fill n bytes with value\n");
    printf("  .DS n            Define n bytes of storage (zeros)\n");
    printf("  .ALIGN n         Align to n-byte boundary\n");
    printf("  .INCLUDE \"file\"  Include another file\n");
    printf("  .MACRO name      Define macro (end with .ENDMACRO)\n");
    printf("  .IF expr         Conditional assembly (.ELSE, .ENDIF)\n");
    printf("  .IFDEF symbol    Assemble if symbol defined\n");
    printf("  .IFNDEF symbol   Assemble if symbol not defined\n\n");
    
    printf("EXPRESSION OPERATORS:\n");
    printf("  Arithmetic: + - * / %%\n");
    printf("  Bitwise:    & | ^ << >>\n");
    printf("  Comparison: == != < > <= >=\n");
    printf("  Logical:    && ||\n");
    printf("  Special:    < (low byte)  > (high byte)  * (current address)\n\n");
    
    printf("NUMBER FORMATS:\n");
    printf("  Decimal:     42 or 255\n");
    printf("  Hexadecimal: $FF or 0xFF\n");
    printf("  Binary:      %%11110000\n");
    printf("  Character:   'A' or '\\n'\n\n");
    
    printf("EXAMPLES:\n");
    printf("  # Run a program\n");
    printf("  %s hello.asm\n\n", program_name);
    
    printf("  # Disassemble without executing\n");
    printf("  %s program.asm --disasm\n\n", program_name);
    
    printf("  # Run with trace and statistics\n");
    printf("  %s test.asm --trace --stats\n\n", program_name);
    
    printf("  # Create ROM image\n");
    printf("  %s --makerom kernel.asm kernel.rom\n\n", program_name);
    
    printf("  # Execute ROM\n");
    printf("  %s --rom kernel.rom\n\n", program_name);
    
    printf("ROM REQUIREMENTS:\n");
    printf("  ROM images MUST define interrupt vectors at $FFFA-$FFFF:\n");
    printf("    .ORG $FFFA\n");
    printf("    .WORD nmi_handler    ; NMI vector\n");
    printf("    .WORD reset_handler  ; RESET vector (entry point)\n");
    printf("    .WORD irq_handler    ; IRQ/BRK vector\n\n");
    
    printf("For more information, see the documentation.\n");
}


/* Updated main() function to support ROM operations: */
int main(int argc, char* argv[]) {
    // Handle help first
    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        print_help(argv[0]);
        return argc < 2 ? 1 : 0;
    }

    // Handle --makerom: assemble and save as ROM
    if (!strcmp(argv[1], "--makerom")) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s --makerom <input.asm> <output.rom> [start_addr] [end_addr]\n", argv[0]);
            fprintf(stderr, "Defaults: start=$C000, end=$FFEF\n");
            fprintf(stderr, "Example: %s --makerom kernel.asm kernel.rom\n", argv[0]);
            fprintf(stderr, "Example: %s --makerom kernel.asm kernel.rom 0xE000 0xFFEF\n", argv[0]);
            fprintf(stderr, "Example: %s --makerom kernel.asm kernel.rom 0xE000 0xFFEF\n\n", argv[0]);
            return 1;
        }
        
        char* src = slurp_file(argv[2]);
        if (!src) {
            fprintf(stderr, "Couldn't read %s\n", argv[2]);
            return 1;
        }
        
        VM vm = {0};
        
        // Parse start and end addresses with defaults
        uint16_t start = ROM_START;  // Default $C000
        uint16_t end = 0xFFEF;       // Default $FFEF
        
        if (argc >= 5) {
            start = (uint16_t)strtoul(argv[4], NULL, 0);
        }
        if (argc >= 6) {
            end = (uint16_t)strtoul(argv[5], NULL, 0);
        }
                
        // Validate ROM region
        if (start < ROM_START || end > 0xFFFF || start > end) {
            fprintf(stderr, "Error: ROM addresses must be in range $C000-$FFFF\n");
            free(src);
            return 1;
        }
        
        // Assemble with ROM start address
        memset(vm.mem, 0, RAM_SIZE);
        if (!assemble(&vm, src, start)) {
            fprintf(stderr, "Assembly failed.\n");
            free(src);
            return 1;
        }
        free(src);
        
        // ===== INSERT THE VECTOR CHECK HERE =====
        // Check that reset vector is defined
        uint16_t reset_vec = vm.mem[VEC_RESET] | (vm.mem[VEC_RESET + 1] << 8);
        if (reset_vec == 0) {
            fprintf(stderr, "\nERROR: No reset vector defined at $FFFC-$FFFD\n");
            fprintf(stderr, "ROM images must define interrupt vectors.\n\n");
            fprintf(stderr, "Add these lines to the end of your .asm file:\n\n");
            fprintf(stderr, "    .ORG $FFFA\n");
            fprintf(stderr, "    .WORD $0000         ; NMI vector\n");
            fprintf(stderr, "    .WORD $%04X         ; RESET vector (entry point)\n", start);
            fprintf(stderr, "    .WORD $0000         ; IRQ/BRK vector\n\n");
            return 1;
        }
        // ===== END OF VECTOR CHECK =====

        // Debug: Check what's at the vector locations
        printf("\nDebug - Vector locations in memory:\n");
        printf("  $FFFA-$FFFB (NMI):   $%02X%02X\n", vm.mem[0xFFFB], vm.mem[0xFFFA]);
        printf("  $FFFC-$FFFD (RESET): $%02X%02X\n", vm.mem[0xFFFD], vm.mem[0xFFFC]);
        printf("  $FFFE-$FFFF (IRQ):   $%02X%02X\n", vm.mem[0xFFFF], vm.mem[0xFFFE]);
        printf("  Code start: $C000 = $%02X\n\n", vm.mem[0xC000]);

        // Removed reset_vec = vm.mem[VEC_RESET] | (vm.mem[VEC_RESET + 1] << 8);        

        // NEW: If vectors are defined, automatically extend save range to include them
        if (end < 0xFFFF) {
            printf("Note: Extending ROM save to $FFFF to include vectors\n");
            end = 0xFFFF;
        }
        
        // Save ROM image
        if (!save_rom(&vm, argv[3], start, end)) {
            return 1;
        }
        
        printf("ROM image created successfully.\n");
        printf("Reset vector: $%04X\n", reset_vec);
        return 0;
    } 
    
    // Handle --rom: load ROM and run
    if (!strcmp(argv[1], "--rom")) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --rom <rom.bin> [--trace|--stats]\n", argv[0]);
            return 1;
        }
        
        VM vm = {0};
        memset(vm.mem, 0, RAM_SIZE);
        
        if (!load_rom(&vm, argv[2])) {
            return 1;
        }
        
        // After load_rom(), before reading reset vector
        printf("\nDebug - Loaded vector locations:\n");
        printf("  $FFFA-$FFFB (NMI):   $%02X%02X\n", vm.mem[0xFFFB], vm.mem[0xFFFA]);
        printf("  $FFFC-$FFFD (RESET): $%02X%02X\n", vm.mem[0xFFFD], vm.mem[0xFFFC]);
        printf("  $FFFE-$FFFF (IRQ):   $%02X%02X\n", vm.mem[0xFFFF], vm.mem[0xFFFE]);

        int trace = 0, stats = 0;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--trace")) trace = 1;
            else if (!strcmp(argv[i], "--stats")) stats = 1;
        }
        
        vm.trace = trace;
        vm.stats = stats;
        
        // Set up vectors for ROM execution
        // ROM should define its own vectors at $FFFA-$FFFF
        
        // Read reset vector from ROM
        uint16_t entry = vm.mem[VEC_RESET] | (vm.mem[VEC_RESET + 1] << 8);
        
        printf("Starting ROM execution at $%04X\n", entry);
        vm_reset(&vm, entry);
        cpu_execute(&vm);
        
        if (stats) {
            printf("\n=== Statistics ===\n");
            printf("Cycles: %llu\n", vm.cpu.cycles);
        }
        
        return 0;
    }

    // Normal operation: assemble and run from source
    const char* path = argv[1];
    int trace = 0, disasm_only = 0, debug = 0, stats = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--trace")) trace = 1;
        else if (!strcmp(argv[i], "--disasm")) disasm_only = 1;
        else if (!strcmp(argv[i], "--debug")) debug = 1;
        else if (!strcmp(argv[i], "--stats")) stats = 1;
    }

    char* src = slurp_file(path);
    if (!src) {
        fprintf(stderr, "Couldn't read %s\n", path);
        return 1;
    }

    VM vm = {0};
    int rc = load_and_run(&vm, src, trace, disasm_only, debug, stats);
    free(src);
    return rc;
}
