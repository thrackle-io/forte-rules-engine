import argparse
import re

def set_env_variable(args):

    with open('.env', 'r') as file:
        filedata = file.read()
        pattern = "\n" + args.variable_name + r'=\S*'
        filedata = re.sub(pattern,"\n" + args.variable_name + '=' + args.value + '', filedata)

    with open('.env', 'w') as file:
        file.write(filedata)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("variable_name", type=str)
    parser.add_argument("value", type=str)
    return parser.parse_args()


def main():
    args = parse_args()
    set_env_variable(args)


if __name__ == "__main__":
    main()





