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

pattern = r'CVE-\d+-\d+|CVE-\d+'


def find_cve():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "mode",
            choices=["managed", "tenant"],
            help="Mode in which the script is called. It does not have any impact for this script.")
    parser.add_argument("--git", required=True, help="SSH clone string for a git repository")
    parser.add_argument("--branch", required=True, help="Branch name to be cloned, it can be a branch or a SHA.")
    args = vars(parser.parse_args())
    cves = git_log_titles(args['git'], args['branch'])
    return create_json_record(cves, "my-component")


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

    git_cmd = ["git", "log", "--oneline"]
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)
    return find_log_titles(result.stdout)


def find_log_titles(commit_titles):
    matching_titles = []
    matching_titles = re.findall(pattern, commit_titles)
    return matching_titles


def create_json_record(cves, component):
    """
    {
        "cves":  [
            { "key": "CVE-3444", "component": "my-component" },
            { "key": "CVE-3445", "component": "my-component" }
        ]
    }
    """
    data = {
        "cves": 
             [{ "key": cve, "component": component }  for cve in cves]
    }                         
    return data

if __name__ == "__main__":
    print(find_cve())
