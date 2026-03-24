#!/usr/bin/env python
"""
Single Component Simple JIRA Collector

This collector scans commit messages for JIRA issue keys and filters them
by specified project key prefixes.

The component is identified via the Snapshot's label:
  appstudio.openshift.io/component

Usage:
    python lib/single-component-simplejira.py \
        tenant \
        --release release.json \
        --previousRelease previous_release.json \
        --jiraProjectKey HUM \
        --jiraProjectKey ABC \
        --jiraServer issues.redhat.com
"""

import argparse
import atexit
import base64
import os
import shutil
import tempfile
import re
import subprocess
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

# Cache for cloned repositories: maps git_url to tmpdir path
_repo_cache = {}


def clear_repo_cache():
    """Clear the repository cache. Useful for testing."""
    global _repo_cache
    _repo_cache = {}


def cleanup_repo_cache():
    """Remove all cached repository directories from disk."""
    global _repo_cache
    for url, tmpdir in _repo_cache.items():
        if os.path.exists(tmpdir):
            log(f"Cleaning up cached repo: {tmpdir}")
            shutil.rmtree(tmpdir, ignore_errors=True)
    _repo_cache = {}


# Register cleanup on exit to free disk space
atexit.register(cleanup_repo_cache)


def find_jira_issues():
    file_not_exists = 0
    parser = argparse.ArgumentParser(
        description="Single Component Simple JIRA Collector - scans commit messages for JIRA issues"
    )
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file', required=True)
    parser.add_argument('--secretName', help="Secret name to use for SSH authentication", required=False)
    parser.add_argument(
        '--jiraProjectKey',
        action='append',
        dest='jiraProjectKeys',
        help="JIRA project key prefix to filter issues (e.g., 'HUM' to match 'HUM-1234'). Can be specified multiple times.",
        required=True
    )
    parser.add_argument(
        '--jiraServer',
        help="JIRA server hostname (e.g., 'issues.redhat.com'). Included in output for issue tracking.",
        required=True
    )
    args = vars(parser.parse_args())

    if not os.path.isfile(args['release']):
        log(f"ERROR: Path to release file {args['release']} doesn't exists")
        file_not_exists = 1
    if not os.path.isfile(args['previousRelease']):
        log(f"ERROR: Path to previousRelease file {args['previousRelease']} doesn't exists")
        file_not_exists = 1
    if file_not_exists:
        exit(1)

    secret_data = {}
    if args['secretName']:
        namespace = json.loads(Path(args['release']).read_text())['metadata']['namespace']
        secret_data = get_secret_data(namespace, args['secretName'])

    jira_project_keys = args['jiraProjectKeys']
    jira_server = args['jiraServer']
    return single_component_info(args['release'], args['previousRelease'], secret_data, jira_project_keys, jira_server)


def get_secret_data(namespace, secret):
    log(f"Getting secret: {secret}")
    cmd = ["kubectl", "get", "secret", secret, "-n", namespace, "-ojson"]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)

    secret_data = json.loads(result.stdout)
    return secret_data["data"]


def read_json(file):
    if os.path.getsize(file) > 0:
        with open(file, 'r') as f:
            data = json.load(f)
        return data


def get_component_info_key(source_git_info, key, required=True):
    """Get a key from the component's source.git section."""
    if "source" in source_git_info:
        source = source_git_info["source"]
        if "git" in source:
            gitsource = source_git_info["source"]["git"]
            if key in source["git"]:
                return gitsource[key]
            else:
                if required:
                    log(f"Error: missing '{key}' key in {gitsource}")
                    exit(1)
                return None
        else:
            if required:
                log(f"Error: missing 'git' key in {source}")
                exit(1)
            return None
    else:
        if required:
            log(f"Error: missing 'source' key in {source_git_info}")
            exit(1)
        return None


def get_component_detail(data_list, component):
    """Get component details including url, revision, and optional context."""
    log(f"looking for component detail: {component}")
    for component_info in data_list:
        log(f"component_info: {component_info}")
        if component == component_info["name"]:
            url = get_component_info_key(component_info, "url")
            revision = get_component_info_key(component_info, "revision")
            context = get_component_info_key(component_info, "context", required=False)
            return (url, revision, context)
    log(f"WARNING: unable to find component detail for component {component}")
    return None


def get_snapshot_data(namespace, snapshot):
    cmd = ["kubectl", "get", "snapshot", snapshot, "-n", namespace, "-ojson"]
    cmd_str = " ".join(cmd)
    try:
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


def get_single_component_from_snapshot(snapshot_data):
    """Extract the single component name from snapshot labels."""
    labels = snapshot_data.get("metadata", {}).get("labels", {})

    snapshot_type = labels.get("test.appstudio.openshift.io/type", "")
    component_name = labels.get("appstudio.openshift.io/component", "")

    log(f"Snapshot type label: {snapshot_type}")
    log(f"Component label: {component_name}")

    if snapshot_type == "component" and component_name:
        return component_name

    return None


def single_component_info(release, previousRelease, secret_data, jira_project_keys, jira_server):
    """Process JIRA issues for only the single component that triggered the build."""
    jira_issues = {}
    data_release = read_json(release)
    data_prev_release = read_json(previousRelease)

    if not data_release:
        log(f"Empty release file {release}")
        exit(1)

    snapshot_name = get_snapshot_name(data_release)
    snapshot_ns = get_snapshot_namespace(data_release)
    snapshot_data = get_snapshot_data(snapshot_ns, snapshot_name)
    current_component_list = snapshot_data['spec']['components']

    single_component = get_single_component_from_snapshot(snapshot_data)

    if not single_component:
        log("WARNING: Snapshot does not have single component labels.")
        log("Expected labels: test.appstudio.openshift.io/type=component and appstudio.openshift.io/component=<name>")
        log("Returning empty JIRA issues list.")
        return create_jira_record({}, jira_server)

    log(f"Single component mode: processing only component '{single_component}'")

    filtered_current = [c for c in current_component_list if c.get("name") == single_component]

    if not filtered_current:
        log(f"ERROR: Component '{single_component}' not found in snapshot components")
        log(f"Available components: {[c.get('name') for c in current_component_list]}")
        exit(1)

    prev_component_list = []
    if data_prev_release:
        snapshot_prev_release_name = get_snapshot_name(data_prev_release)
        snapshot_prev_release_data = get_snapshot_data(snapshot_ns, snapshot_prev_release_name)
        prev_component_list = snapshot_prev_release_data['spec']['components']

    filtered_prev = [c for c in prev_component_list if c.get("name") == single_component]
    prev_component_names = [c.get("name") for c in filtered_prev]

    component = single_component
    detail = get_component_detail(filtered_current, component)
    if not detail:
        log(f"ERROR: Could not get details for component {component}")
        exit(1)

    url_current, revision_current, context = detail
    log(f"url_current: {url_current}")
    log(f"revision_current: {revision_current}")
    log(f"context: {context}")

    if component in prev_component_names:
        prev_detail = get_component_detail(filtered_prev, component)
        if prev_detail:
            url_prev, revision_prev, prev_context = prev_detail
            log(f"url_prev: {url_prev}")
            log(f"revision_prev: {revision_prev}")
            # Use previous context as fallback if current context is missing
            effective_context = context if context else prev_context
            if effective_context and not context:
                log(f"Using previous release context as fallback: {effective_context}")
            jira_issues[component] = git_log_jira_issues_per_component(
                url_current, revision_current, revision_prev, secret_data, effective_context, jira_project_keys
            )
        else:
            jira_issues[component] = git_log_jira_issues_per_component(
                url_current, revision_current, "", secret_data, context, jira_project_keys
            )
    else:
        jira_issues[component] = git_log_jira_issues_per_component(
            url_current, revision_current, "", secret_data, context, jira_project_keys
        )

    return create_jira_record(jira_issues, jira_server)


def clone_repo_if_needed(git_url, secret_data):
    """Clone a repository if not already cached. Returns the path to the cloned repo."""
    if git_url in _repo_cache:
        log(f"Using cached clone for {git_url}")
        return _repo_cache[git_url]

    tmpdir = tempfile.mkdtemp()
    git_env = os.environ.copy()
    clone_url = git_url
    git_parts = urlparse(git_url)
    git_matcher = git_parts.path[1:].replace("/", ".")

    if git_matcher in secret_data:
        clone_url = f"git@{git_parts.netloc}:{git_parts.path[1:]}"

        priv_key = base64.standard_b64decode(secret_data[git_matcher])
        fd = tempfile.TemporaryFile()
        fd.write(priv_key)
        os.chmod(fd.name, 0o600)
        git_env["GIT_SSH_COMMAND"] = f"ssh -i {fd.name} -o IdentitiesOnly=yes"

    git_cmd = [
        "git", "clone",
        "--filter=blob:none",
        "--no-checkout",
        clone_url,
        tmpdir
    ]

    cmd_str = " ".join(git_cmd)
    log(f"Running {cmd_str}")
    result = subprocess.run(git_cmd, check=False, capture_output=True, text=True, env=git_env)
    if result.returncode != 0:
        log("Something went wrong during the git operation, details below:")
        log(f"Command: '{' '.join(git_cmd)}'")
        log(f"Stdout: '{result.stdout}'")
        log(f"Stderr: '{result.stderr}'")
        exit(result.returncode)

    log(f"Stdout: '{result.stdout}'")
    _repo_cache[git_url] = tmpdir
    return tmpdir


def git_log_jira_issues_per_component(git_url, revision_current, revision_prev, secret_data, context, jira_project_keys):
    """Get JIRA issues from git log for a component."""
    repo_dir = clone_repo_if_needed(git_url, secret_data)
    os.chdir(repo_dir)

    if revision_prev and revision_current != revision_prev:
        git_cmd = ["git", "log", "--format=%s%n%b", f"{revision_prev}..{revision_current}"]
    else:
        git_cmd = ["git", "show", "--quiet", "--format=%s%n%b", f"{revision_current}"]

    if context:
        log(f"Filtering git log to context path: {context}")
        git_cmd.extend(["--", context])

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
    return find_jira_issues_in_text(result.stdout, jira_project_keys)


def find_jira_issues_in_text(text, jira_project_keys):
    """Find JIRA issue keys in text that match the specified project keys.
    
    Only matches issues prefixed with "Fixes" or "Fixed" to avoid false positives
    from URLs or casual mentions (e.g., "I looked at http://jira.com/HUM-730").
    
    Args:
        text: The text to search (commit messages)
        jira_project_keys: List of JIRA project keys to filter by (e.g., ['HUM', 'ABC'])
    
    Returns:
        List of unique matching JIRA issue keys (e.g., ['HUM-1234', 'ABC-5678'])
    """
    all_matches = []
    for key in jira_project_keys:
        pattern = rf'(?i:Fixes|Fixed)\s+({re.escape(key)}-\d+)\b'
        matches = re.findall(pattern, text)
        all_matches.extend(matches)
    unique_matches = list(dict.fromkeys(all_matches))
    return unique_matches


def create_jira_record(jira_issues, jira_server):
    """
    Input: jira_issues (dictionary), jira_server (string)
    {
      'comp1': ['HUM-1234', 'HUM-5678'],
    }
    Output:
    {
        "releaseNotes": {
            "issues": {
                "fixed": [
                    { "id": "HUM-1234", "component": "comp1", "source": "issues.redhat.com" },
                    { "id": "HUM-5678", "component": "comp1", "source": "issues.redhat.com" },
                ]
            }
        }
    }
    or empty when no issues
    {"releaseNotes": {"issues": {"fixed": []}}}
    """

    result = {
        "releaseNotes": {
            "issues": {
                "fixed": []
            }
        }
    }

    if jira_issues:
        log(f"Found JIRA issues: {jira_issues}")
        for comp_name, keys in jira_issues.items():
            for key in keys:
                result["releaseNotes"]["issues"]["fixed"].append({
                    "id": key,
                    "component": comp_name,
                    "source": jira_server
                })

    return result


if __name__ == "__main__":
    return_jira = find_jira_issues()
    print(json.dumps(return_jira))
