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
import sys

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
        log(f"ERROR: Path to release file {args['release']} doesn't exists")
        file_not_exists = 1
    if not os.path.isfile(args['previousRelease']):
        log(f"ERROR: Path to previousRelease file {args['previousRelease']} doesn't exists")
        file_not_exists = 1
    if file_not_exists:
        exit(1)

    return components_info(args['release'], args['previousRelease'])


def read_json(file):
    if os.path.getsize(file) > 0:
        with open(file, 'r') as f:
            data = json.load(f)
        return data


def get_component_names(data_list):
    component_list = []
    for component_info in data_list:
        log(f"component_info: {component_info}")
        for key, value in component_info.items():
            if (key == "name"):
                component_list.append(value)
    return component_list


def get_component_info_key(source_git_info, key):
    if "source" in source_git_info:
        source = source_git_info["source"]
        if "git" in source:
            gitsource = source_git_info["source"]["git"]
            if key in source["git"]:
                return gitsource[key]
            else:
                log(f"Error: missing '{key}' key in {gitsource}")
                exit(1)
        else:
            log(f"Error: missing 'git' key in {source}")
            exit(1)
    else:
        log(f"Error: missing 'source' key in {source_git_info}")
        exit(1)


def get_component_detail(data_list, component):
    log(f"looking for component detail: {component}")
    for component_info in data_list:
        log(f"component_info: {components_info}")
        if component == component_info["name"]:
            return (get_component_info_key(component_info, "url"),
                    get_component_info_key(component_info, "revision"))
    log(f"WARNING: unable to find component detail for component {component}")
    return([])


def get_snapshot_data(namespace, snapshot):
    cmd = ["kubectl", "get", "snapshot", snapshot, "-n", namespace, "-ojson"]
    try:
        cmd_str = " ".join(cmd)
        log(f"Running {cmd_str}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        log(f"Command {cmd_str} failed, check exception for details")
        raise
    except Exception as exc:
        log("Unknown error occurred")
        raise RuntimeError from exc

    log(result.stdout)
    return json.loads(result.stdout)


def log(message):
    print(message, file=sys.stderr)


def get_snapshot_name(data_release):
    if "spec" in data_release:
        spec = data_release["spec"]
        if "snapshot" in spec:
            return spec["snapshot"]
        else:
            log(f"Error: missing 'snapshot' key in {spec}")
            exit(1)
    else:
        log(f"Error: missing 'spec' key in {data_release}")
        exit(1)


def get_snapshot_namespace(data_release):
    if "metadata" in data_release:
        metadata = data_release["metadata"]
        if "namespace" in metadata:
            return metadata["namespace"]
        else:
            log(f"Error: missing 'namespace' key in {metadata}")
            exit(1)
    else:
        log(f"Error: missing 'metadata' key in {data_release}")
        exit(1)


def components_info(release, previousRelease):
    prev_component_list = []
    cves = {}
    data_release = read_json(release)
    data_prev_release = read_json(previousRelease)

    if data_release:
        snapshot_name = get_snapshot_name(data_release)
        snapshot_ns = get_snapshot_namespace(data_release)
        snapshot_data = get_snapshot_data(snapshot_ns, snapshot_name)
        current_component_list = snapshot_data['spec']['components']
    else:
        log(f"Empty release file {release}")
        exit(1)

    if data_prev_release:
        snapshot_prev_release_name = get_snapshot_name(data_prev_release)
        snapshot_prev_release_data = get_snapshot_data(snapshot_ns, snapshot_prev_release_name)
        prev_component_list = snapshot_prev_release_data['spec']['components']

    current_components = get_component_names(current_component_list)
    log(f"current_components: {current_components}")
    prev_components = get_component_names(prev_component_list)
    log(f"prev_components: {prev_components}")

    for component in current_components:
        (url_current, revision_current) = get_component_detail(current_component_list, component)
        log(f"url_current: {url_current}")
        log(f"revision_current: {revision_current}")
        if component in prev_components:
            (url_prev, revision_prev) = get_component_detail(prev_component_list, component)
            log(f"url_prev: {url_prev}")
            log(f"revision_prev: {revision_prev}")
            cves[component] = git_log_titles_per_component(url_current, revision_current, revision_prev)
        else:
            cves[component] = git_log_titles_per_component(url_current, revision_current, "")
    return create_cves_record(cves)


def git_log_titles_per_component(git_url, revision_current, revision_prev):
    tmpdir = tempfile.mkdtemp()
    git_cmd = ["git", "clone", git_url, tmpdir]
    cmd_str = " ".join(git_cmd)
    log(f"Running {cmd_str}")
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        log("Something went wrong during the git operation, details below:")
        log(f"Command: '{' '.join(git_cmd)}'")
        log(f"Stdout: '{result.stdout}'")
        log(f"Stderr: '{result.stderr}'")
        exit(result.returncode)

    log(f"Stdout: '{result.stdout}'")
    os.chdir(tmpdir)

    if revision_prev and revision_current != revision_prev:
        git_cmd = ["git", "log", f"{revision_prev}..{revision_current}"]
    else:
        git_cmd = ["git", "show", "--quiet", f"{revision_current}"]

    cmd_str = " ".join(git_cmd)
    log(f"Running {cmd_str}")
    result = subprocess.run(git_cmd, check=True, capture_output=True, text=True)
    if result.returncode != 0:
        log("Something went wrong during the git operation, details below:")
        log(f"Command: '{' '.join(git_cmd)}'")
        log(f"Stdout: '{result.stdout}'")
        log(f"Stderr: '{result.stderr}'")
        exit(result.returncode)

    log(f"Stdout: '{result.stdout}'")
    return find_log_titles(result.stdout)


def find_log_titles(commit_titles):
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

    result = {
        "releaseNotes": {
            "cves": [
            ]
        }
    }

    if cves:

        log(f"Found CVEs: {cves}")
        for comp_name, keys in cves.items():
            for key in keys:
                result["releaseNotes"]["cves"].append({
                    "key": key,
                    "component": comp_name
                })

    return result


if __name__ == "__main__":
    return_cves = find_cve()
    print(json.dumps(return_cves))
