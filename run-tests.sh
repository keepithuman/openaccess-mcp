#!/bin/bash

# OpenAccess MCP Test Runner
# This script runs the test suite and stores results for future reference

set -e

# Configuration
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEST_RESULTS_DIR="test-results"
COVERAGE_DIR="${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}"
TEST_LOG="${TEST_RESULTS_DIR}/test_run_${TIMESTAMP}.log"
SUMMARY_LOG="${TEST_RESULTS_DIR}/test_summary_${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 OpenAccess MCP Test Runner${NC}"
echo -e "${BLUE}Timestamp: ${TIMESTAMP}${NC}"
echo ""

# Create test results directory if it doesn't exist
mkdir -p "${TEST_RESULTS_DIR}"

# Function to log messages
log() {
    echo -e "$1" | tee -a "${TEST_LOG}"
}

# Function to log summary
log_summary() {
    echo -e "$1" >> "${SUMMARY_LOG}"
}

# Start logging
log "${BLUE}=== Test Run Started at $(date) ===${NC}"
log ""

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    log "${YELLOW}⚠️  Virtual environment not detected. Attempting to activate...${NC}"
    if [ -d "venv" ]; then
        source venv/bin/activate
        log "${GREEN}✅ Virtual environment activated${NC}"
    else
        log "${RED}❌ No virtual environment found. Please create one first.${NC}"
        exit 1
    fi
else
    log "${GREEN}✅ Virtual environment is active: $VIRTUAL_ENV${NC}"
fi

# Check dependencies
log "${BLUE}📦 Checking dependencies...${NC}"
if ! python -c "import pytest" 2>/dev/null; then
    log "${RED}❌ pytest not found. Installing...${NC}"
    pip install pytest pytest-asyncio pytest-cov
fi

log "${GREEN}✅ Dependencies check passed${NC}"
log ""

# Run tests with coverage
log "${BLUE}🧪 Running test suite...${NC}"
log "Command: python -m pytest tests/ -v --cov=openaccess_mcp --cov-report=html:${COVERAGE_DIR} --cov-report=xml:${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}.xml"

# Run tests and capture output
if python -m pytest tests/ -v --cov=openaccess_mcp --cov-report=html:"${COVERAGE_DIR}" --cov-report=xml:"${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}.xml" 2>&1 | tee -a "${TEST_LOG}"; then
    TEST_EXIT_CODE=0
    log "${GREEN}✅ All tests passed!${NC}"
else
    TEST_EXIT_CODE=$?
    log "${RED}❌ Some tests failed (exit code: ${TEST_EXIT_CODE})${NC}"
fi

log ""

# Generate summary
log "${BLUE}📊 Generating test summary...${NC}"

# Extract test results from log
TOTAL_TESTS=$(grep -c "PASSED\|FAILED\|ERROR" "${TEST_LOG}" || echo "0")
PASSED_TESTS=$(grep -c "PASSED" "${TEST_LOG}" || echo "0")
FAILED_TESTS=$(grep -c "FAILED" "${TEST_LOG}" || echo "0")
ERROR_TESTS=$(grep -c "ERROR" "${TEST_LOG}" || echo "0")

# Extract coverage information
if [ -f "${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}.xml" ]; then
    COVERAGE_PERCENT=$(grep -o 'coverage="[0-9.]*"' "${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}.xml" | head -1 | grep -o '[0-9.]*' || echo "0")
else
    COVERAGE_PERCENT="0"
fi

# Write summary
{
    echo "=== OpenAccess MCP Test Summary ==="
    echo "Timestamp: ${TIMESTAMP}"
    echo "Test Results:"
    echo "  Total Tests: ${TOTAL_TESTS}"
    echo "  Passed: ${PASSED_TESTS}"
    echo "  Failed: ${FAILED_TESTS}"
    echo "  Errors: ${ERROR_TESTS}"
    echo "  Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
    echo ""
    echo "Coverage: ${COVERAGE_PERCENT}%"
    echo ""
    echo "Files Generated:"
    echo "  Test Log: ${TEST_LOG}"
    echo "  Coverage HTML: ${COVERAGE_DIR}/index.html"
    echo "  Coverage XML: ${TEST_RESULTS_DIR}/coverage_${TIMESTAMP}.xml"
    echo "  Summary: ${SUMMARY_LOG}"
    echo ""
    echo "Exit Code: ${TEST_EXIT_CODE}"
} > "${SUMMARY_LOG}"

# Display summary
log "${BLUE}📋 Test Summary:${NC}"
log "  Total Tests: ${TOTAL_TESTS}"
log "  Passed: ${PASSED_TESTS}"
log "  Failed: ${FAILED_TESTS}"
log "  Errors: ${ERROR_TESTS}"
log "  Coverage: ${COVERAGE_PERCENT}%"
log ""

# Create symlink to latest results
ln -sf "test_run_${TIMESTAMP}.log" "${TEST_RESULTS_DIR}/latest_test.log"
ln -sf "coverage_${TIMESTAMP}" "${TEST_RESULTS_DIR}/latest_coverage"
ln -sf "test_summary_${TIMESTAMP}.txt" "${TEST_RESULTS_DIR}/latest_summary.txt"

log "${GREEN}✅ Test results saved to:${NC}"
log "  📄 Test Log: ${TEST_LOG}"
log "  📊 Coverage: ${COVERAGE_DIR}/index.html"
log "  📋 Summary: ${SUMMARY_LOG}"
log "  🔗 Latest: ${TEST_RESULTS_DIR}/latest_*"
log ""

# Final status
if [ ${TEST_EXIT_CODE} -eq 0 ]; then
    log "${GREEN}🎉 Test run completed successfully!${NC}"
else
    log "${RED}💥 Test run completed with failures${NC}"
fi

log "${BLUE}=== Test Run Completed at $(date) ===${NC}"

exit ${TEST_EXIT_CODE}
