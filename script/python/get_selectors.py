import subprocess
import argparse
import json


from eth_abi import encode


def get_selectors(args):
    contract = args.contract
    line = ""
    while line == "":
        res = subprocess.run(
            ["forge", "inspect", contract, "mi"], capture_output=True )
        line = res.stdout.decode()
    res = json.loads(line)

    selectors = []
    for signature in res:
        selector = res[signature]
        selectors.append(bytes.fromhex(selector))

    enc = encode(["bytes4[]"], [selectors])
    print("0x" + enc.hex(), end="")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=str)
    return parser.parse_args()


def main():
    args = parse_args()
    get_selectors(args)


if __name__ == "__main__":
    main()
