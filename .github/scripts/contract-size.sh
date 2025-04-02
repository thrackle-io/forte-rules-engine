#!/bin/bash
export TERM=xterm-color
YELLOW='\033[33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
# Helper script for running the contract-size workflow

# Run the command and capture output
output=$(forge build --sizes)
should_fail="false"
# Process the output: remove commas, truncate to 69 chars, and loop through lines
while IFS= read -r line; do
    clean_line=$(echo "$line" | tr -d ',' | cut -c1-69)

    # Extract all numbers from the line
    for num in $(echo "$clean_line" | grep -oE '[0-9]+'); do
        # Load variable with position 3 to 46 (inclusive)
        contract=${clean_line:2:44}
        contract="${contract%"${contract##*[![:space:]]}"}"
        # echo $contract
        if (( num > 24000 )); then
            printf "${RED} FAIL ${NC} Contract found that exceeds the max size of 24Kb! ${RED} $contract ${NC} \n"
            printf "       Its size is: ${RED} $num ${NC} \n"
            should_fail="true"
        elif (( num > 21000 )); then
            printf "${YELLOW} WARNING ${NC} Contract found that is near the max size of 24Kb. ${YELLOW} $contract ${NC} \n"
            printf "          Its size is: ${YELLOW} $num ${NC} \n"
            should_fail="true"
        fi
    done    
done <<< "$output"
if [ "$should_fail" = "true" ]; then
  printf "${RED} ERROR: Failed to pass all checks. See individual results for details.  \n"
  exit -1 # terminate and indicate error
fi




