#!/bin/bash
#
# Comprehensive Security Test Suite for Tiny8VM
# Tests all critical and medium-severity vulnerability fixes
#
# Usage: ./security_tests.sh
#

set -e

echo "=========================================="
echo "Tiny8VM Security Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
TOTAL=0

# Test runner function
run_test() {
    local test_name="$1"
    local test_file="$2"
    local expected_result="$3"  # "pass" or "fail" or "timeout"

    TOTAL=$((TOTAL + 1))
    echo -n "Test $TOTAL: $test_name... "

    # Run the test with timeout
    if timeout 5s ./tiny8vm "$test_file" >/dev/null 2>&1; then
        result="pass"
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            result="timeout"
        else
            result="fail"
        fi
    fi

    if [ "$result" = "$expected_result" ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} (expected: $expected_result, got: $result)"
        FAILED=$((FAILED + 1))
    fi
}

# Create test directory
mkdir -p security_tests
cd security_tests

echo "Creating security test cases..."
echo ""

# ========================================
# TEST 1: Infinite Loop Detection
# ========================================
cat > test_infinite_loop.asm <<'EOF'
; Test: Infinite loop should timeout after 100M cycles
.ORG $0200

START:
    NOP
    JMP START  ; Infinite loop

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# TEST 2: Stack Underflow Detection
# ========================================
cat > test_stack_underflow.asm <<'EOF'
; Test: Deep recursion should cause stack underflow
.ORG $0200

RECURSE:
    JSR RECURSE  ; Recursive call - will underflow stack
    RTS

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# TEST 3: Large File Rejection
# ========================================
# Create a file that's too large (>10MB)
echo "; Test: File size validation" > test_large_file.asm
dd if=/dev/zero bs=1M count=11 2>/dev/null | tr '\0' '\n' >> test_large_file.asm

# ========================================
# TEST 4: Path Traversal Prevention
# ========================================
cat > test_path_traversal.asm <<'EOF'
; Test: Path traversal should be blocked
.ORG $0200
.INCLUDE "../../../etc/passwd"
NOP
BRK
EOF

# ========================================
# TEST 5: Integer Overflow in .FILL
# ========================================
cat > test_fill_overflow.asm <<'EOF'
; Test: .FILL with count that causes overflow
.ORG $FFF0
.FILL 0x10000, $90  ; Should be rejected
EOF

# ========================================
# TEST 6: Integer Overflow in .DS
# ========================================
cat > test_ds_overflow.asm <<'EOF'
; Test: .DS with count that causes overflow
.ORG $FFF0
.DS 0x10000  ; Should be rejected
EOF

# ========================================
# TEST 7: Valid Program (Control Test)
# ========================================
cat > test_valid_program.asm <<'EOF'
; Test: Valid program should execute successfully
.ORG $0200

    LDA #$42
    STA $1000
    BRK

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# TEST 8: Stack Operations Safety
# ========================================
cat > test_stack_safety.asm <<'EOF'
; Test: Normal stack operations should work
.ORG $0200

    LDA #$AA
    PHA
    PLA
    JSR SUBROUTINE
    BRK

SUBROUTINE:
    LDA #$55
    RTS

.ORG $FFFC
.WORD $0200
EOF

# ========================================
# TEST 9: Negative Value Rejection
# ========================================
cat > test_negative_value.asm <<'EOF'
; Test: Negative values should be rejected
.ORG $0200

    LDA #-1  ; Should be rejected
    BRK
EOF

cd ..

# Build tiny8vm if not already built
if [ ! -f tiny8vm ]; then
    echo "Building tiny8vm..."
    cc -std=c11 -O2 -Wall tiny8vm.c -o tiny8vm
    echo ""
fi

echo "Running security tests..."
echo "=========================================="
echo ""

# Run tests
run_test "Infinite loop timeout" "security_tests/test_infinite_loop.asm" "fail"
run_test "Stack underflow detection" "security_tests/test_stack_underflow.asm" "fail"
run_test "Large file rejection" "security_tests/test_large_file.asm" "fail"
run_test "Path traversal prevention" "security_tests/test_path_traversal.asm" "fail"
run_test "FILL integer overflow" "security_tests/test_fill_overflow.asm" "fail"
run_test "DS integer overflow" "security_tests/test_ds_overflow.asm" "fail"
run_test "Valid program execution" "security_tests/test_valid_program.asm" "pass"
run_test "Stack operations safety" "security_tests/test_stack_safety.asm" "pass"
run_test "Negative value rejection" "security_tests/test_negative_value.asm" "fail"

echo ""
echo "=========================================="
echo "Test Results Summary"
echo "=========================================="
echo -e "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All security tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
