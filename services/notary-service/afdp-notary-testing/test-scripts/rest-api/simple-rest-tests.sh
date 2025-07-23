#!/bin/bash

# Simple REST API test script for AFDP Notary Service
# Tests basic functionality with curl commands

set -e

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3030}"
SAMPLE_DATA_DIR="../sample-data"
OUTPUT_DIR="./output"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}🚀 AFDP Notary Service REST API Tests${NC}"
echo -e "${BLUE}📡 Testing against: $BASE_URL${NC}"
echo -e "${BLUE}📁 Sample data directory: $SAMPLE_DATA_DIR${NC}"
echo ""

# Function to log with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to test health endpoint
test_health() {
    log "${BLUE}Testing health endpoint...${NC}"
    
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "Accept: application/json" \
        "$BASE_URL/health" || echo "HTTPSTATUS:000")
    
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    BODY=$(echo "$RESPONSE" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$HTTP_STATUS" -eq 200 ]; then
        log "${GREEN}✅ Health check passed${NC}"
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
    else
        log "${RED}❌ Health check failed (HTTP $HTTP_STATUS)${NC}"
        echo "$BODY"
        exit 1
    fi
    echo ""
}

# Function to test notarization endpoint
test_notarization() {
    local evidence_file=$1
    local scenario_name=$2
    
    log "${BLUE}Testing notarization: $scenario_name${NC}"
    
    # Generate correlation ID
    CORRELATION_ID="test-$(date +%s)-$$"
    
    # Make the request
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "X-Correlation-ID: $CORRELATION_ID" \
        -H "X-Request-ID: $(uuidgen)" \
        -d @"$evidence_file" \
        "$BASE_URL/api/v1/notarize" || echo "HTTPSTATUS:000")
    
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    BODY=$(echo "$RESPONSE" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    # Save response
    OUTPUT_FILE="$OUTPUT_DIR/notarize_${scenario_name}_${TIMESTAMP}.json"
    echo "$BODY" > "$OUTPUT_FILE"
    
    if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
        log "${GREEN}✅ Notarization succeeded (HTTP $HTTP_STATUS)${NC}"
        
        # Extract evidence hash and rekor log ID for verification
        EVIDENCE_HASH=$(echo "$BODY" | jq -r '.evidence_package_hash // empty' 2>/dev/null)
        REKOR_LOG_ID=$(echo "$BODY" | jq -r '.rekor_log_id // empty' 2>/dev/null)
        
        if [ -n "$EVIDENCE_HASH" ]; then
            log "📋 Evidence Hash: $EVIDENCE_HASH"
        fi
        if [ -n "$REKOR_LOG_ID" ]; then
            log "📜 Rekor Log ID: $REKOR_LOG_ID"
        fi
        
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
        
        # Test verification if we got a hash
        if [ -n "$EVIDENCE_HASH" ]; then
            test_verification "$EVIDENCE_HASH" "$scenario_name"
        fi
        
    else
        log "${RED}❌ Notarization failed (HTTP $HTTP_STATUS)${NC}"
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
    fi
    echo ""
}

# Function to test verification endpoint
test_verification() {
    local evidence_hash=$1
    local scenario_name=$2
    
    log "${BLUE}Testing verification: $scenario_name${NC}"
    
    CORRELATION_ID="verify-$(date +%s)-$$"
    
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "Accept: application/json" \
        -H "X-Correlation-ID: $CORRELATION_ID" \
        -H "X-Request-ID: $(uuidgen)" \
        "$BASE_URL/api/v1/verify/$evidence_hash" || echo "HTTPSTATUS:000")
    
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    BODY=$(echo "$RESPONSE" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    # Save response
    OUTPUT_FILE="$OUTPUT_DIR/verify_${scenario_name}_${TIMESTAMP}.json"
    echo "$BODY" > "$OUTPUT_FILE"
    
    if [ "$HTTP_STATUS" -eq 200 ]; then
        log "${GREEN}✅ Verification succeeded${NC}"
        
        VERIFIED=$(echo "$BODY" | jq -r '.verified // false' 2>/dev/null)
        if [ "$VERIFIED" = "true" ]; then
            log "${GREEN}🔍 Evidence verified successfully${NC}"
        else
            log "${YELLOW}⚠️ Evidence not verified${NC}"
        fi
        
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
    else
        log "${RED}❌ Verification failed (HTTP $HTTP_STATUS)${NC}"
        echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
    fi
    echo ""
}

# Function to run performance test
run_performance_test() {
    local evidence_file=$1
    local requests=${2:-10}
    local concurrency=${3:-2}
    
    log "${BLUE}Running performance test ($requests requests, $concurrency concurrent)${NC}"
    
    # Check if apache bench is available
    if ! command -v ab &> /dev/null; then
        log "${YELLOW}⚠️ Apache Bench (ab) not found, skipping performance test${NC}"
        return
    fi
    
    # Create a temporary file with the POST data
    TEMP_POST_FILE=$(mktemp)
    cp "$evidence_file" "$TEMP_POST_FILE"
    
    # Run apache bench
    OUTPUT_FILE="$OUTPUT_DIR/performance_test_${TIMESTAMP}.txt"
    
    ab -n "$requests" -c "$concurrency" \
       -p "$TEMP_POST_FILE" \
       -T "application/json" \
       -H "X-Correlation-ID: perf-test-$TIMESTAMP" \
       "$BASE_URL/api/v1/notarize" > "$OUTPUT_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        log "${GREEN}✅ Performance test completed${NC}"
        
        # Extract key metrics
        REQUESTS_PER_SEC=$(grep "Requests per second" "$OUTPUT_FILE" | awk '{print $4}')
        MEAN_TIME=$(grep "Time per request" "$OUTPUT_FILE" | head -1 | awk '{print $4}')
        
        if [ -n "$REQUESTS_PER_SEC" ]; then
            log "📊 Requests per second: $REQUESTS_PER_SEC"
        fi
        if [ -n "$MEAN_TIME" ]; then
            log "⏱️ Mean time per request: ${MEAN_TIME}ms"
        fi
        
        log "📄 Full results saved to: $OUTPUT_FILE"
    else
        log "${RED}❌ Performance test failed${NC}"
    fi
    
    # Clean up
    rm -f "$TEMP_POST_FILE"
    echo ""
}

# Function to test all scenarios
test_all_scenarios() {
    log "${BLUE}Testing all evidence scenarios...${NC}"
    
    local success_count=0
    local total_count=0
    
    # Find all JSON files in sample data directory (excluding config files)
    while IFS= read -r -d '' file; do
        # Skip the test scenarios config file
        if [[ $(basename "$file") == "test-scenarios.json" ]]; then
            continue
        fi
        
        total_count=$((total_count + 1))
        
        # Extract scenario name from file path
        scenario_name=$(basename "$file" .json | tr '/' '_' | tr '-' '_')
        
        log "${BLUE}[$total_count] Testing: $(basename "$file")${NC}"
        
        # Test this scenario
        if test_notarization "$file" "$scenario_name"; then
            success_count=$((success_count + 1))
        fi
        
        # Small delay between tests
        sleep 1
        
    done < <(find "$SAMPLE_DATA_DIR" -name "*.json" -type f -print0)
    
    log "${BLUE}📊 Test Summary:${NC}"
    log "   Total scenarios: $total_count"
    log "   Successful: $success_count"
    log "   Failed: $((total_count - success_count))"
    log "   Success rate: $(( success_count * 100 / total_count ))%"
}

# Main execution
main() {
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        log "${RED}❌ curl is required but not installed${NC}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log "${YELLOW}⚠️ jq not found, JSON responses will not be formatted${NC}"
    fi
    
    # Test health first
    test_health
    
    # Test all scenarios
    test_all_scenarios
    
    # Run performance test on the first available evidence file
    FIRST_EVIDENCE_FILE=$(find "$SAMPLE_DATA_DIR" -name "*.json" -type f ! -name "test-scenarios.json" | head -1)
    if [ -n "$FIRST_EVIDENCE_FILE" ]; then
        run_performance_test "$FIRST_EVIDENCE_FILE" 20 3
    fi
    
    log "${GREEN}🎉 All tests completed!${NC}"
    log "📁 Results saved in: $OUTPUT_DIR"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            BASE_URL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--url BASE_URL] [--help]"
            echo ""
            echo "Options:"
            echo "  --url BASE_URL    Base URL of the notary service (default: http://localhost:3030)"
            echo "  --help           Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  BASE_URL         Alternative way to set the base URL"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main