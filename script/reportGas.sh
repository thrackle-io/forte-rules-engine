#!/bin/bash

set -e  # Exit on any error

# Ensure we're running with bash
if [ -z "$BASH_VERSION" ]; then
    echo "This script requires bash. Please run with: bash $0"
    exit 1
fi

# Configuration
GAS_TEST_PATH="test/utils/gasReport/GasReport.t.sol"
HARDCODED_TEST_PATH="test/utils/gasReport/GasReportHardcoded.t.sol"
# Default to gasReports/GAS_USAGE.md for local runs, can be overridden for CI
OUTPUT_MD_FILE="${GAS_REPORT_OUTPUT_FILE:-gasReports/GAS_USAGE.md}"
SNAPSHOTS_FILE="snapshots/RulesEngineUnitTests.json"
TEMP_DIR="/tmp/gas-report-$$"
GAS_OUTPUT_FILE="$TEMP_DIR/gas_output.txt"
HARDCODED_OUTPUT_FILE="$TEMP_DIR/hardcoded_output.txt"
PARSED_RESULTS_FILE="$TEMP_DIR/parsed_results.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [ "$VERBOSE_MODE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Usage function
usage() {
    cat << EOF
Gas Report Generation Script

DESCRIPTION:
    Generates comprehensive gas usage reports for the Rules Engine project.
    Runs both Rules Engine tests and hardcoded baseline tests, parses results,
    and generates markdown reports with gas snapshots.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help      Show this help message and exit
    -v, --verbose   Enable verbose output (shows debug information)
    -d, --debug     Enable debug mode (verbose + preserve temp files + bash debug)

EXAMPLES:
    # Generate gas report with default settings
    $0

    # Generate gas report with verbose output
    $0 -v

    # Generate gas report in debug mode (for troubleshooting)
    $0 -d

FILES GENERATED:
    gasReports/GAS_USAGE.md                    Main gas usage report
    gasReports/archive/gas-report_*.md         Timestamped archive (CI only)

INPUT FILES:
    test/utils/gasReport/GasReport.t.sol       Rules Engine gas tests
    test/utils/gasReport/GasReportHardcoded.t.sol  Hardcoded baseline tests
    snapshots/RulesEngineUnitTests.json       Gas snapshots from test suite

REQUIREMENTS:
    - Foundry (forge command)
    - jq (for JSON parsing, optional but recommended)
    - foundry.toml in project root

ENVIRONMENT VARIABLES:
    GAS_REPORT_OUTPUT_FILE    Override default output file path
                              Default: gasReports/GAS_USAGE.md

For more information, see: gasReports/GAS_REPORTS.md
EOF
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ] && [ "$DEBUG_MODE" != true ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Create temporary directory
mkdir -p "$TEMP_DIR"

# Function to check if required files exist
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [ ! -f "$GAS_TEST_PATH" ]; then
        log_error "Gas test file not found: $GAS_TEST_PATH"
        exit 1
    fi
    
    if [ ! -f "$HARDCODED_TEST_PATH" ]; then
        log_error "Hardcoded gas test file not found: $HARDCODED_TEST_PATH"
        exit 1
    fi
    
    if [ ! -f "foundry.toml" ]; then
        log_error "foundry.toml not found. Are you in the project root?"
        exit 1
    fi
    
    if ! command -v forge &> /dev/null; then
        log_error "forge command not found. Please install Foundry."
        exit 1
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_MD_FILE")"
    
    # Create archive directory if it doesn't exist
    mkdir -p "gasReports/archive"
    
    log_info "Prerequisites check passed"
}

# Function to update snapshots first
update_snapshots() {
    log_info "Updating gas snapshots..."
    log_debug "Running: forge test --ffi"
    
    # Run all tests to update snapshots
    if ! forge test --ffi > /dev/null 2>&1; then
        log_warn "Some tests failed during snapshot update, but continuing..."
    fi
    
    log_info "Snapshots updated"
}

# Function to run gas tests and capture output
run_gas_tests() {
    log_info "Running Rules Engine gas tests..."
    log_debug "Command: forge test -vvv --ffi --match-path $GAS_TEST_PATH"
    
    # Run the gas tests and capture output
    if ! forge test -vvv --ffi --match-path "$GAS_TEST_PATH" > "$GAS_OUTPUT_FILE" 2>&1; then
        log_error "Rules Engine gas tests failed. Check the output:"
        cat "$GAS_OUTPUT_FILE"
        exit 1
    fi
    
    log_info "Rules Engine gas tests completed successfully"
}

# Function to run hardcoded gas tests
run_hardcoded_tests() {
    log_info "Running hardcoded baseline gas tests..."
    log_debug "Command: forge test -vv --ffi --match-path $HARDCODED_TEST_PATH"
    
    # Run the hardcoded tests and capture output
    if ! forge test -vv --ffi --match-path "$HARDCODED_TEST_PATH" > "$HARDCODED_OUTPUT_FILE" 2>&1; then
        log_error "Hardcoded gas tests failed. Check the output:"
        cat "$HARDCODED_OUTPUT_FILE"
        exit 1
    fi
    
    log_info "Hardcoded gas tests completed successfully"
}

# Function to parse gas test results from both test files
parse_gas_results() {
    log_info "Parsing gas test results..."
    
    # Clear the results file
    > "$PARSED_RESULTS_FILE"
    
    local result_count=0
    
    # Parse Rules Engine tests (from GasReport.t.sol)
    log_debug "Parsing Rules Engine test results..."
    while IFS= read -r line; do
        # Look for lines that start with whitespace and end with a number
        if echo "$line" | grep -E "^[[:space:]]+.*[[:space:]]+[0-9]+$" > /dev/null; then
            # Extract the gas value (last number in the line)
            gas_value=$(echo "$line" | grep -o '[0-9]*$')
            # Extract everything before the last number as rule name
            rule_name=$(echo "$line" | sed 's/[[:space:]]*[0-9]*$//' | sed 's/^[[:space:]]*//')
            
            # Skip empty rule names
            if [ -n "$rule_name" ] && [ -n "$gas_value" ]; then
                echo "$rule_name|$gas_value" >> "$PARSED_RESULTS_FILE"
                log_debug "Parsed Rules Engine: $rule_name = $gas_value"
                result_count=$((result_count + 1))
            fi
        fi
    done < "$GAS_OUTPUT_FILE"
    
    # Parse Hardcoded tests (from GasReportHardcoded.t.sol)
    log_debug "Parsing hardcoded test results..."
    while IFS= read -r line; do
        # Look for lines that start with whitespace and end with a number
        if echo "$line" | grep -E "^[[:space:]]+.*[[:space:]]+[0-9]+$" > /dev/null; then
            # Extract the gas value (last number in the line)
            gas_value=$(echo "$line" | grep -o '[0-9]*$')
            # Extract everything before the last number as rule name
            rule_name=$(echo "$line" | sed 's/[[:space:]]*[0-9]*$//' | sed 's/^[[:space:]]*//')
            
            # Skip empty rule names
            if [ -n "$rule_name" ] && [ -n "$gas_value" ]; then
                echo "$rule_name|$gas_value" >> "$PARSED_RESULTS_FILE"
                log_debug "Parsed Hardcoded: $rule_name = $gas_value"
                result_count=$((result_count + 1))
            fi
        fi
    done < "$HARDCODED_OUTPUT_FILE"
    
    log_info "Parsed $result_count total gas results"
    
    if [ $result_count -eq 0 ]; then
        log_warn "No gas results were parsed. Check the test output format."
        if [ "$VERBOSE_MODE" = true ]; then
            log_debug "Showing first 20 lines of Rules Engine test output:"
            head -20 "$GAS_OUTPUT_FILE"
            log_debug "Showing first 20 lines of hardcoded test output:"
            head -20 "$HARDCODED_OUTPUT_FILE"
        fi
    fi
}

# Function to extract snapshots data
extract_snapshots() {
    log_info "Extracting snapshots data..."
    
    if [ ! -f "$SNAPSHOTS_FILE" ]; then
        log_warn "Snapshots file not found: $SNAPSHOTS_FILE"
        return 1
    fi
    
    # Validate JSON format
    if command -v jq &> /dev/null; then
        if ! jq empty "$SNAPSHOTS_FILE" 2>/dev/null; then
            log_warn "Invalid JSON in snapshots file"
            return 1
        fi
        log_info "Snapshots data validated and extracted"
    else
        log_info "Snapshots file found (jq not available for validation)"
    fi
    
    return 0
}

# Function to generate markdown content
generate_markdown() {
    log_info "Generating markdown report..."
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$OUTPUT_MD_FILE" << EOF
# Gas Usage Report

**Last Updated:** $timestamp  
**Generated automatically by:** \`script/reportGas.sh\`

## Purpose

This chart shows how individual active rules affect gas consumption of basic token actions.

The gas tests were done using a simple contract with very little overhead. The comparison is between the base usage (Rules engine integrated but with no active rules) and with the rule active and passing.

These gas tests can be run with the following commands:

**Rules Engine Tests:**
\`\`\`bash
forge test -vvv --ffi --match-path test/utils/gasReport/GasReport.t.sol
\`\`\`

**Hardcoded Baseline Tests:**
\`\`\`bash
forge test -vv --ffi --match-path test/utils/gasReport/GasReportHardcoded.t.sol
\`\`\`

Or regenerate this entire report with:

\`\`\`bash
./script/reportGas.sh
\`\`\`

## Gas Usage Results

Column Definitions:
- Rule = Rule being tested
- Gas = Gas used to evaluate the rule

---

| Rule | Gas |
|:-|:-|
EOF

    # Add parsed gas results to markdown
    local gas_data_added=false
    
    if [ -f "$PARSED_RESULTS_FILE" ] && [ -s "$PARSED_RESULTS_FILE" ]; then
        # Remove duplicates and sort results for consistent output
        # Sort by rule name for better organization
        sort -u "$PARSED_RESULTS_FILE" | sort -t'|' -k1,1 | while IFS='|' read -r rule_name gas_value; do
            if [ -n "$rule_name" ] && [ -n "$gas_value" ]; then
                echo "| $rule_name | $gas_value |" >> "$OUTPUT_MD_FILE"
            fi
        done
        gas_data_added=true
    fi
    
    # If no gas data was parsed, add a message
    if [ "$gas_data_added" = false ]; then
        echo "| No gas data parsed from tests | - |" >> "$OUTPUT_MD_FILE"
        log_warn "No gas data was successfully parsed from test output"
        if [ "$DEBUG_MODE" = true ]; then
            log_debug "For debugging, check: $GAS_OUTPUT_FILE and $HARDCODED_OUTPUT_FILE"
        fi
    fi
    
    # Add snapshots section if available
    if extract_snapshots; then
        cat >> "$OUTPUT_MD_FILE" << EOF

## Gas Snapshots

The following snapshots are taken from automated test runs and represent comprehensive gas usage across the entire test suite:

EOF
        
        if command -v jq &> /dev/null && [ -f "$SNAPSHOTS_FILE" ]; then
            echo "| Test | Gas Used |" >> "$OUTPUT_MD_FILE"
            echo "|:-|:-|" >> "$OUTPUT_MD_FILE"
            
            # Parse JSON snapshots and add to markdown
            # Sort by test name for consistent output
            jq -r 'to_entries[] | "\(.key)|\(.value)"' "$SNAPSHOTS_FILE" 2>/dev/null | sort | while IFS='|' read -r test_name gas_value; do
                echo "| $test_name | $gas_value |" >> "$OUTPUT_MD_FILE"
            done || {
                echo "| Error parsing snapshots | - |" >> "$OUTPUT_MD_FILE"
                log_warn "Error parsing snapshots JSON"
            }
        else
            echo "*Snapshots data available in:* [\`$SNAPSHOTS_FILE\`]($SNAPSHOTS_FILE)" >> "$OUTPUT_MD_FILE"
            
            if [ ! -f "$SNAPSHOTS_FILE" ]; then
                echo "*Note: Snapshots file not found. Run tests to generate snapshots.*" >> "$OUTPUT_MD_FILE"
            fi
        fi
    fi
    
    # Add footer with generation info
    cat >> "$OUTPUT_MD_FILE" << EOF

---
EOF
    
    log_info "Markdown report generated: $OUTPUT_MD_FILE"
}

# Function to display summary
show_summary() {
    log_info "=== Gas Report Generation Summary ==="
    echo "✅ Snapshots updated"
    echo "✅ Rules Engine gas tests executed"
    echo "✅ Hardcoded baseline tests executed"
    echo "✅ Results parsed from test logs"
    echo "✅ Markdown report updated: $OUTPUT_MD_FILE"
    
    # Count parsed results
    if [ -f "$PARSED_RESULTS_FILE" ]; then
        local result_count=$(wc -l < "$PARSED_RESULTS_FILE" 2>/dev/null || echo "0")
        echo "📊 Total gas measurements parsed: $result_count"
        
        # Count by source
        local rules_engine_count=$(grep -c "Using REv2\|Event Effect\|OFAC\|Oracle\|Pause\|Min Transfer" "$PARSED_RESULTS_FILE" 2>/dev/null || echo "0")
        local hardcoded_count=$(grep -c "Base\|Hardcoding" "$PARSED_RESULTS_FILE" 2>/dev/null || echo "0")
        
        echo "   - Rules Engine tests: $rules_engine_count"
        echo "   - Hardcoded baseline tests: $hardcoded_count"
        
        # Show what was parsed if verbose
        if [ "$VERBOSE_MODE" = true ] && [ -f "$PARSED_RESULTS_FILE" ]; then
            echo ""
            echo "Parsed results:"
            while IFS='|' read -r rule_name gas_value; do
                echo "  - $rule_name: $gas_value"
            done < "$PARSED_RESULTS_FILE"
        fi
    fi
    
    if [ -f "$SNAPSHOTS_FILE" ]; then
        echo "✅ Snapshots included from: $SNAPSHOTS_FILE"
        if command -v jq &> /dev/null; then
            local snapshot_count=$(jq 'length' "$SNAPSHOTS_FILE" 2>/dev/null || echo "unknown")
            echo "   - Snapshot entries: $snapshot_count"
        fi
    else
        echo "⚠️  No snapshots file found: $SNAPSHOTS_FILE"
    fi
    
    echo ""
    echo "📝 Generated report contents:"
    echo "   - Gas usage comparison table (Rules Engine + Hardcoded baselines)"
    echo "   - Test execution commands for both test suites"
    echo "   - Timestamp and generation info"
    if [ -f "$SNAPSHOTS_FILE" ]; then
        echo "   - Complete gas snapshots from test suite"
    fi
    
    echo ""
}

# Handle command line arguments
DEBUG_MODE=false
VERBOSE_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE_MODE=true
            shift
            ;;
        -d|--debug)
            DEBUG_MODE=true
            VERBOSE_MODE=true
            set -x
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Modify cleanup function for debug mode
if [ "$DEBUG_MODE" = true ]; then
    cleanup() {
        if [ -d "$TEMP_DIR" ]; then
            log_debug "Debug mode: Preserving temp files in $TEMP_DIR"
            log_debug "Rules Engine output: $GAS_OUTPUT_FILE"
            log_debug "Hardcoded output: $HARDCODED_OUTPUT_FILE"
            log_debug "Parsed results: $PARSED_RESULTS_FILE"
        fi
    }
fi

# Main execution
main() {
    log_info "Starting comprehensive gas report generation..."
    
    check_prerequisites
    update_snapshots
    run_gas_tests
    run_hardcoded_tests
    parse_gas_results
    generate_markdown
    show_summary
    
    log_info "Comprehensive gas report generation completed successfully!"
}

# Run main function
main "$@"