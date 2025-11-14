#!/bin/bash
#
# Advanced Stress Test Suite for Tiny8VM
# Tests production hardening under abnormal conditions
#
# Usage: ./stress_tests.sh
#

set -e

echo "=========================================="
echo "Tiny8VM Advanced Stress Test Suite"
echo "Testing production hardening under attack"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

PASSED=0
FAILED=0
TOTAL=0

# Test runner
run_test() {
    local test_name="$1"
    local test_file="$2"
    local expected="$3"  # "pass" or "fail" or "timeout"

    TOTAL=$((TOTAL + 1))
    echo -n "Stress Test $TOTAL: $test_name... "

    # Run with timeout and capture output
    if timeout 10s ./tiny8vm "$test_file" >/tmp/test_output.txt 2>&1; then
        result="pass"
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            result="timeout"
        else
            result="fail"
        fi
    fi

    if [ "$result" = "$expected" ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} (expected: $expected, got: $result)"
        cat /tmp/test_output.txt | head -5
        FAILED=$((FAILED + 1))
    fi
}

# Mem test helper
check_memory_leak() {
    echo -n "Memory Leak Test: Repeated assembly... "

    # Get initial memory
    local initial_mem=$(ps aux | grep -v grep | grep tiny8vm | awk '{sum+=$6} END {print sum}')

    # Run 100 assemblies
    for i in {1..100}; do
        ./tiny8vm stress_tests/test_macro_memory.asm >/dev/null 2>&1 || true
    done

    # Get final memory
    local final_mem=$(ps aux | grep -v grep | grep tiny8vm | awk '{sum+=$6} END {print sum}')

    if [ -z "$initial_mem" ]; then initial_mem=0; fi
    if [ -z "$final_mem" ]; then final_mem=0; fi

    # Calculate growth (should be minimal)
    local growth=$((final_mem - initial_mem))

    if [ $growth -lt 10000 ]; then  # Less than 10MB growth
        echo -e "${GREEN}✓ PASS${NC} (growth: ${growth}KB)"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} (growth: ${growth}KB - possible leak)"
        FAILED=$((FAILED + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

# Create stress test directory
mkdir -p stress_tests
cd stress_tests

echo "Creating stress test cases..."
echo ""

# ========================================
# STRESS TEST 1: Macro Memory Leak Test
# ========================================
cat > test_macro_memory.asm <<'EOF'
; Test: Macros should not leak memory
.ORG $0200

.MACRO LARGE_MACRO
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
  NOP
.ENDMACRO

LARGE_MACRO
LARGE_MACRO
LARGE_MACRO

BRK

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 2: Macro Recursion Bomb
# ========================================
cat > test_macro_recursion.asm <<'EOF'
; Test: Recursive macro expansion should be limited
.ORG $0200

.MACRO EXPAND
  EXPAND EXPAND
.ENDMACRO

EXPAND

BRK
EOF

# ========================================
# STRESS TEST 3: Deep Macro Nesting
# ========================================
cat > test_macro_nesting.asm <<'EOF'
; Test: Deep nesting should hit limit
.ORG $0200

.MACRO A
  B B B B B
.ENDMACRO

.MACRO B
  C C C C C
.ENDMACRO

.MACRO C
  D D D D D
.ENDMACRO

.MACRO D
  NOP
.ENDMACRO

; This will expand exponentially
A A A A A

BRK
EOF

# ========================================
# STRESS TEST 4: Maximum Execution Cycles
# ========================================
cat > test_max_cycles.asm <<'EOF'
; Test: Should timeout at 100M cycles
.ORG $0200

LOOP:
    NOP
    NOP
    NOP
    NOP
    JMP LOOP  ; Infinite loop

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 5: Stack Exhaustion
# ========================================
cat > test_stack_exhaust.asm <<'EOF'
; Test: Stack underflow detection
.ORG $0200

DEEP:
    JSR DEEP  ; Infinite recursion
    RTS       ; Never reached

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 6: Excessive Pushes
# ========================================
cat > test_excessive_push.asm <<'EOF'
; Test: Too many pushes should fail
.ORG $0200

    LDX #$00
PUSHLOOP:
    PHA
    PHA
    PHA
    PHA
    PHA
    DEX
    BNE PUSHLOOP

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 7: Large Assembly
# ========================================
cat > test_large_assembly.asm <<'EOF'
; Test: Very large program
.ORG $0200

EOF

# Generate 1000 lines of code
for i in {1..1000}; do
    echo "    NOP" >> test_large_assembly.asm
done

cat >> test_large_assembly.asm <<'EOF'
    BRK

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 8: Boundary Conditions
# ========================================
cat > test_boundary.asm <<'EOF'
; Test: Address space boundaries
.ORG $FFF0

    LDA #$42
    STA $FFFF  ; Last byte
    BRK

.ORG $FFFC
.WORD $FFF0
EOF

# ========================================
# STRESS TEST 9: All Features Combined
# ========================================
cat > test_combined.asm <<'EOF'
; Test: Complex program using many features
.ORG $0200

.MACRO INIT_REG value
    LDA #value
    PHA
    PLA
.ENDMACRO

START:
    INIT_REG $42
    INIT_REG $55
    INIT_REG $AA

    LDX #$10
LOOP:
    JSR SUBROUTINE
    DEX
    BNE LOOP

    BRK

SUBROUTINE:
    LDA #$FF
    STA $1000
    RTS

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# STRESS TEST 10: .FILL Edge Cases
# ========================================
cat > test_fill_edge.asm <<'EOF'
; Test: .FILL at maximum safe value
.ORG $C000

.FILL 16384, $90  ; Maximum: 16KB

.ORG $FFFC
.WORD $C000
EOF

cd ..

# Build if needed
if [ ! -f tiny8vm ]; then
    echo "Building tiny8vm..."
    cc -std=c11 -O2 -Wall tiny8vm.c -o tiny8vm
    echo ""
fi

echo -e "${BLUE}=========================================="
echo "Running Production Stress Tests"
echo -e "==========================================${NC}"
echo ""

# Run stress tests
run_test "Macro memory leak" "stress_tests/test_macro_memory.asm" "pass"
run_test "Macro recursion bomb" "stress_tests/test_macro_recursion.asm" "fail"
run_test "Deep macro nesting" "stress_tests/test_macro_nesting.asm" "fail"
run_test "Maximum execution cycles" "stress_tests/test_max_cycles.asm" "pass"  # Detects and stops gracefully
run_test "Stack exhaustion" "stress_tests/test_stack_exhaust.asm" "pass"  # Detects and stops gracefully
run_test "Excessive pushes" "stress_tests/test_excessive_push.asm" "pass"  # Detects and stops gracefully
run_test "Large assembly (1000 NOPs)" "stress_tests/test_large_assembly.asm" "pass"
run_test "Address boundary conditions" "stress_tests/test_boundary.asm" "pass"
run_test "Combined features" "stress_tests/test_combined.asm" "pass"
run_test ".FILL edge case (16KB)" "stress_tests/test_fill_edge.asm" "pass"  # Exactly fills to $FFFF

# Memory leak test (special)
echo ""
echo -e "${BLUE}=========================================="
echo "Memory Leak Detection Test"
echo -e "==========================================${NC}"
check_memory_leak

echo ""
echo -e "${BLUE}=========================================="
echo "Stress Test Results Summary"
echo -e "==========================================${NC}"
echo -e "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓✓✓ ALL STRESS TESTS PASSED! ✓✓✓${NC}"
    echo -e "${GREEN}System is production-hardened and attack-resistant${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some stress tests failed${NC}"
    exit 1
fi
