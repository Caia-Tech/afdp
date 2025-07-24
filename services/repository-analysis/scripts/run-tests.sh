#!/bin/bash

# AFDP Repository Analysis Service - Test Runner Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_MODE=${TEST_MODE:-"all"} # all, unit, integration, performance
VERBOSE=${VERBOSE:-"false"}
COVERAGE=${COVERAGE:-"false"}
DOCKER=${DOCKER:-"false"}

# Print header
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}AFDP Repository Analysis Service Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to check dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}✗ Cargo not found. Please install Rust.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Rust/Cargo found${NC}"
    
    # Check Docker (if using Docker mode)
    if [ "$DOCKER" = "true" ]; then
        if ! command -v docker &> /dev/null; then
            echo -e "${RED}✗ Docker not found. Please install Docker.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ Docker found${NC}"
        
        if ! command -v docker-compose &> /dev/null; then
            echo -e "${RED}✗ docker-compose not found. Please install docker-compose.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ docker-compose found${NC}"
    fi
    
    echo ""
}

# Function to start test infrastructure
start_infrastructure() {
    echo -e "${YELLOW}Starting test infrastructure...${NC}"
    
    if [ "$DOCKER" = "true" ]; then
        docker-compose -f docker-compose.test.yml up -d
        
        # Wait for services to be ready
        echo -e "${YELLOW}Waiting for services to be ready...${NC}"
        sleep 10
        
        # Check service health
        docker-compose -f docker-compose.test.yml ps
    else
        echo -e "${YELLOW}Using local services (ensure PostgreSQL, Qdrant, and Pulsar are running)${NC}"
    fi
    
    echo ""
}

# Function to run unit tests
run_unit_tests() {
    echo -e "${BLUE}Running unit tests...${NC}"
    
    if [ "$COVERAGE" = "true" ]; then
        cargo tarpaulin --out Html --output-dir ./coverage
    else
        cargo test --lib -- ${VERBOSE_FLAG}
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Unit tests passed${NC}"
    else
        echo -e "${RED}✗ Unit tests failed${NC}"
        return 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    echo -e "${BLUE}Running integration tests...${NC}"
    
    # Set test database URL
    export DATABASE_URL="postgresql://afdp_repo:test_password@localhost:5432/afdp_repository_analysis"
    export QDRANT_URL="http://localhost:6333"
    export PULSAR_URL="pulsar://localhost:6650"
    
    cargo test --test '*' -- ${VERBOSE_FLAG} --test-threads=1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Integration tests passed${NC}"
    else
        echo -e "${RED}✗ Integration tests failed${NC}"
        return 1
    fi
}

# Function to run performance tests
run_performance_tests() {
    echo -e "${BLUE}Running performance tests...${NC}"
    
    export RUN_PERF_TESTS=true
    cargo test --release performance -- ${VERBOSE_FLAG} --test-threads=1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Performance tests passed${NC}"
    else
        echo -e "${RED}✗ Performance tests failed${NC}"
        return 1
    fi
}

# Function to run security audit
run_security_audit() {
    echo -e "${BLUE}Running security audit...${NC}"
    
    # Check for known vulnerabilities
    if command -v cargo-audit &> /dev/null; then
        cargo audit
    else
        echo -e "${YELLOW}cargo-audit not installed. Run: cargo install cargo-audit${NC}"
    fi
    
    # Check for common security issues
    if command -v cargo-clippy &> /dev/null; then
        cargo clippy -- -D warnings
    else
        echo -e "${YELLOW}clippy not installed. Run: rustup component add clippy${NC}"
    fi
}

# Function to generate test report
generate_report() {
    echo -e "${BLUE}Generating test report...${NC}"
    
    REPORT_FILE="test-results/test-report-$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p test-results
    
    {
        echo "AFDP Repository Analysis Service - Test Report"
        echo "============================================="
        echo "Date: $(date)"
        echo "Test Mode: $TEST_MODE"
        echo ""
        echo "Test Results:"
        echo "- Unit Tests: ${UNIT_RESULT:-N/A}"
        echo "- Integration Tests: ${INTEGRATION_RESULT:-N/A}"
        echo "- Performance Tests: ${PERF_RESULT:-N/A}"
        echo ""
        
        if [ "$COVERAGE" = "true" ]; then
            echo "Code Coverage: See coverage/tarpaulin-report.html"
        fi
    } > "$REPORT_FILE"
    
    echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
}

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    if [ "$DOCKER" = "true" ]; then
        docker-compose -f docker-compose.test.yml down -v
    fi
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                TEST_MODE="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE="true"
                VERBOSE_FLAG="--nocapture"
                shift
                ;;
            --coverage)
                COVERAGE="true"
                shift
                ;;
            --docker)
                DOCKER="true"
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --mode <all|unit|integration|performance>  Test mode (default: all)"
                echo "  --verbose                                   Verbose output"
                echo "  --coverage                                  Generate code coverage"
                echo "  --docker                                    Use Docker for dependencies"
                echo "  --help                                      Show this help"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                exit 1
                ;;
        esac
    done
    
    # Set up error handling
    trap cleanup EXIT
    
    # Check dependencies
    check_dependencies
    
    # Start infrastructure if needed
    if [ "$DOCKER" = "true" ] || [ "$TEST_MODE" = "integration" ] || [ "$TEST_MODE" = "all" ]; then
        start_infrastructure
    fi
    
    # Run tests based on mode
    case $TEST_MODE in
        unit)
            run_unit_tests
            UNIT_RESULT=$?
            ;;
        integration)
            run_integration_tests
            INTEGRATION_RESULT=$?
            ;;
        performance)
            run_performance_tests
            PERF_RESULT=$?
            ;;
        all)
            run_unit_tests
            UNIT_RESULT=$?
            
            if [ $UNIT_RESULT -eq 0 ]; then
                run_integration_tests
                INTEGRATION_RESULT=$?
            fi
            
            if [ $INTEGRATION_RESULT -eq 0 ]; then
                run_performance_tests
                PERF_RESULT=$?
            fi
            
            # Run security audit
            run_security_audit
            ;;
        *)
            echo -e "${RED}Invalid test mode: $TEST_MODE${NC}"
            exit 1
            ;;
    esac
    
    # Generate report
    generate_report
    
    # Summary
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    if [ "$UNIT_RESULT" = "0" ] && [ "$INTEGRATION_RESULT" = "0" ] && [ "$PERF_RESULT" = "0" ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed${NC}"
        exit 1
    fi
}

# Run main function
main "$@"