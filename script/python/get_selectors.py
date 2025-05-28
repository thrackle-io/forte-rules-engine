import subprocess
import argparse
import json
from eth_abi import encode

# This script retrieves the function selectors of a specified smart contract using Forge.
# It encodes the selectors into a format suitable for use in Ethereum transactions.
#
# Steps:
# 1. Accept the contract name as a command-line argument.
# 2. Use Forge to inspect the contract and retrieve its method identifiers (selectors).
# 3. Parse the output from Forge and extract the selectors.
# 4. Encode the selectors as a `bytes4[]` array using the `eth_abi` library.
# 5. Print the encoded selectors in hexadecimal format.
#
# Usage:
# Run the script with the contract name as an argument:
# `python get_selectors.py <contract_name>`


def get_selectors(args):
    # Retrieve the contract name from the command-line arguments
    contract = args.contract
    line = ""

    # Run the Forge command to inspect the contract and retrieve its method identifiers (selectors)
    while line == "":
        res = subprocess.run(
            ["forge", "inspect", contract, "mi", "--json"], capture_output=True
        )
        line = res.stdout.decode()

    # Parse the JSON output from Forge
    res = json.loads(line)

    # Extract the selectors and convert them to bytes
    selectors = []
    for signature in res:
        selector = res[signature]
        selectors.append(bytes.fromhex(selector))

    # Encode the selectors as a `bytes4[]` array using the `eth_abi` library
    enc = encode(["bytes4[]"], [selectors])

    # Print the encoded selectors in hexadecimal format
    print("0x" + enc.hex(), end="")


def parse_args():
    # Set up argument parsing for the script
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=str, help="The name of the contract to inspect")
    return parser.parse_args()


def main():
    # Parse the command-line arguments and call the `get_selectors` function
    args = parse_args()
    get_selectors(args)


# Entry point of the script
if __name__ == "__main__":
    main()
