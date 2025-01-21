#!/usr/bin/env python
"""
python lib/get_cve.py \
    tenant \
    --git https://gitlab.cee.redhat.com/gnecasov/container-errata-templates.git \
    --branch main \

    git clone https://github.com/openshift/contra-lib.git --branch master --depth 1 "/tmp/1"

"""

import argparse
import os
import tempfile
import re
import subprocess

pattern = r'^fix\(CVE-'


def find_cve():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "mode",
            choices=["managed", "tenant"],
            help="Mode in which the script is called. It does not have any impact for this script.")
    parser.add_argument("--git", required=True, help="SSH clone string for a git repository")
    parser.add_argument("--branch", required=True, help="Branch name to be cloned, it can be a branch or a SHA.")
    args = vars(parser.parse_args())
    return git_log_titles(args['git'], args['branch'])


def git_log_titles(git_url, branch):
    tmpdir = tempfile.mkdtemp()
    git_cmd = ["git", "clone", git_url, "--branch", branch, tmpdir]
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)

    os.chdir(tmpdir)

    git_cmd = ["git", "log", "--pretty=format:%s:"]
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)
    list_of_commit_titles = result.stdout.splitlines()
    return find_log_titles(list_of_commit_titles)


def find_log_titles(commit_titles):
    matching_titles = []
    for title in commit_titles:
        if re.match(pattern, title):
            matching_titles.append(title)
    return matching_titles


if __name__ == "__main__":
    print(find_cve())
