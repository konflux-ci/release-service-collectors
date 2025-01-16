#!/usr/bin/env python
"""
python lib/template.py \
    tenant \
    --git https://gitlab.cee.redhat.com/gnecasov/container-errata-templates.git \
    --branch main \
    --path RHEL/Containers/cockpit-ws-container.json
"""

import argparse
import tempfile
import sys
from os import environ
from pathlib import Path
from subprocess import run


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["managed", "tenant"], help="Mode in which the script is called. It does not have any impact for this script.")
    parser.add_argument("--git", required=True, help="SSH clone string for a git repository")
    parser.add_argument("--branch", required=True, help="Branch name to be cloned, it can be a branch or a SHA.")
    parser.add_argument("--path", required=True, help="Path to the file in the git repository hat will be templated, relative to the root of the repository, so 'config/' refers to the file 'config/myfile' in the root of the repository. Absolute paths are not allowed.")
    args = parser.parse_args(argv)

    if Path(args.path).is_absolute():
        print("ERROR: path provided is absolute, it must be relative.")
        exit(1)

    tmpdir = tempfile.mkdtemp()
    final_path = (Path(tmpdir) / args.path).resolve()
    if not final_path.is_relative_to(tmpdir):
        print("ERROR: the resulting path is not contained within the repository. Do not use '..' to escalate directories.")
        exit(1)

    git_cmd = ["git", "clone", args.git, "--branch", args.branch, "--depth", "1", tmpdir]
    cmd = run(git_cmd, capture_output=True)
    if cmd.returncode != 0:
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{cmd.stdout.decode("utf-8").strip("\n")}'")
        print(f"Stderr: '{cmd.stderr.decode("utf-8").strip("\n")}'")
        exit(cmd.returncode)

    if not final_path.exists() or not final_path.is_file():
        print("ERROR: file does not exist or is not a file.")
        exit(1)

    with open(final_path, "r") as fd:
        content = fd.read()

        # Needed to avoid templating JSON brackets, we only want to template {VAR_NAME}
        content = content.replace("{\n", "{{\n")
        content = content.replace("\n}", "\n}}")
        content = content.replace("{\"", "{{\"")
        content = content.replace("\"}", "\"}}")
        content = content.replace("{ ", "{{ ")
        content = content.replace(" }", " }}")

        try:
            print(content.format(**environ))
        except KeyError as err:
            print(f"ERROR: variable '{err.args[0]}' to be templated not found in the environment.")
            exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
