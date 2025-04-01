#!/usr/bin/env python
"""
python lib/cve.py \
    tenant \
    --release release.json \
    --previousRelease previous_release.json 
"""


import argparse
import os
import tempfile
import re
import subprocess
import json

pattern = r'CVE-\d+-\d+|CVE-\d+'

def find_cve():
    file_not_exists = 0
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "mode",
            choices=["managed", "tenant"],
            help="Mode in which the script is called. It does not have any impact for this script.")
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file', required=True)
    args = vars(parser.parse_args())

    if not os.path.isfile(args['release']):
        print(f"ERROR: Path to release file {args['release']} doesn't exists")
        file_not_exists = 1
    if not os.path.isfile(args['previousRelease']):
        print(f"ERROR: Path to previousRelease file {args['previousRelease']} doesn't exists")
        file_not_exists = 1
    if file_not_exists:
        exit(1)

    return components_info(args['release'], args['previousRelease'])


def read_json(file):
    data = {}    

    if os.path.getsize(file) > 0:
        with open(file, 'r') as f:
            data = json.load(f)
        return data


def get_component_names(data_list):
    component_list = []
    for component_info in data_list:
        for key, value in component_info.items():
            if (key == "name"):
                component_list.append(value)
    return component_list


def get_component_detail(data_list, component):
    found = 0
    for component_info in data_list:
        for key, value in component_info.items():
            if (key == "name") and (value == component):
                found = 1
            if (key == "source"):
                return(value["git"]["url"],value["git"]["revision"])
    return([])


def components_info(release, previousRelease):
    current_component_list = []
    prev_component_list = []
    cves = {}
    data_release = read_json(release)
    data_prev_release = read_json(previousRelease)

    if data_release:
        current_component_list = data_release['spec']['components']
    else:
        print(f"Empty release file {release}")
        exit(0)

    if data_prev_release:
        prev_component_list = data_prev_release['spec']['components']

    current_components = get_component_names(current_component_list)
    prev_components = get_component_names(prev_component_list)
     
    for component in current_components:
        (url_current, revision_current) = get_component_detail(current_component_list, component)
        if component in prev_components:
            (url_prev, revision_prev) = get_component_detail(prev_component_list, component)
            cves[component] = git_log_titles_per_component(url_current, revision_current, revision_prev)
        else:
            cves[component] = git_log_titles_per_component(url_current, revision_current, "")
    return create_cves_record(cves)



def git_log_titles_per_component(git_url, revision_current, revision_prev):
    tmpdir = tempfile.mkdtemp()
    git_cmd = ["git", "clone", git_url, tmpdir]
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{result.stdout}'")
        print(f"Stderr: '{result.stderr}'")
        exit(result.returncode)

    os.chdir(tmpdir)

    if revision_prev:
        git_cmd = ["git", "log", f"{revision_prev}..{revision_current}"]
    else:
        git_cmd = ["git", "log"]
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


def create_cves_record(cves):
    """
    Input: cves (dictonary)
    {
      'comp1': ['CVE-1', 'CVE-3'], 
      'comp2': ['CVE-2', 'CVE-4']
    }
    Output:
    {
        "releaseNotes": {
            "cves":  [
                { "key": "CVE-1", "component": "comp1" },
                { "key": "CVE-3", "component": "comp1" },
                { "key": "CVE-2", "component": "comp2" },
                { "key": "CVE-4", "component": "comp2" },
            ]
        }
    }
    or empty when no cves
    {"releaseNotes": {"cves": []}}
    """

    result = {"releaseNotes": {"cves": []}}
    
    if cves:
    
        for comp_name, keys in cves.items():
            for key in keys:
                result["releaseNotes"]["cves"].append({
                    "key": key,
                    "component": comp_name
                })
        
    return result
    

if __name__ == "__main__":
    print(find_cve())
