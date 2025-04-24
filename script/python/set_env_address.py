# This script updates a specified environment variable in the `.env` file with a new value.
# It uses regular expressions to locate the variable and replace its value.
#
# Steps:
# 1. Accept the variable name and new value as command-line arguments.
# 2. Read the `.env` file and locate the specified variable using a regex pattern.
# 3. Replace the variable's value with the new value.
# 4. Write the updated content back to the `.env` file.
#
# Usage:
# Run the script with the variable name and value as arguments:
# `python set_env_address.py <variable_name> <value>`
#
# Example:
# `python set_env_address.py DIAMOND_ADDRESS 0x1234567890abcdef`
#
# @author 
# @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220

import argparse
import re

def set_env_variable(args):
    """
    Updates the specified environment variable in the `.env` file.

    Args:
        args: Parsed command-line arguments containing the variable name and value.
    """
    # Open the `.env` file and read its contents
    with open('.env', 'r') as file:
        filedata = file.read()

        # Define a regex pattern to locate the variable and replace its value
        pattern = "\n" + args.variable_name + r'=\S*'
        filedata = re.sub(pattern, "\n" + args.variable_name + '=' + args.value + '', filedata)

    # Write the updated content back to the `.env` file
    with open('.env', 'w') as file:
        file.write(filedata)


def parse_args():
    """
    Parses command-line arguments for the script.

    Returns:
        argparse.Namespace: Parsed arguments containing the variable name and value.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("variable_name", type=str, help="The name of the environment variable to update")
    parser.add_argument("value", type=str, help="The new value for the environment variable")
    return parser.parse_args()


def main():
    """
    Main function to parse arguments and update the environment variable.
    """
    args = parse_args()
    set_env_variable(args)


# Entry point of the script
if __name__ == "__main__":
    main()