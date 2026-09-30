#!/usr/bin/env python
# @ai-rules:
# 1. [Pattern]: Uses Jira Cloud API v3 with Basic auth (email:token).
# 2. [Constraint]: CVE ID field is customfield_10667 on Cloud.
# 3. [Gotcha]: Fields param is comma-separated string, not JSON array.
"""
$ python lib/jira.py <tenant/managed> \
  --url https://redhat.atlassian.net \
  --query 'project = KONFLUX AND status = "NEW" AND fixVersion = CY25Q1' \
  --secretName jira-collectors-secret \
  --limit 50 \
  --release release.json \
  --previousRelease previous_release.json

output:
{
  "releaseNotes": {
    "issues": {
      "fixed": [
        { "id": "CPAAS-1234", "source": "redhat.atlassian.net", "summary": "summary 1..", "cveid": "CVE-2345" },
        { "id": "CPAAS-5678", "source": "redhat.atlassian.net", "summary": "summary 2..", "cveid": "CVE-2349" }
      ]
    }
  }
}
"""

import argparse
import base64
import ipaddress
import json
import os
import socket
import sys
import subprocess
import requests
from urllib.parse import urlparse


def read_json(file_name):
    if os.path.getsize(file_name) > 0:
        with open(file_name, 'r') as f:
            data = json.load(f)
        return data
    else:
        print(f"Error: Empty file {file_name}")
        exit(1)


def get_release_namespace(data_release):
    if "namespace" not in data_release['metadata']:
        print("Error: resource does not contain the '.metadata.namespace' key")
        exit(1)

    return data_release['metadata']['namespace']


def get_namespace_from_release(release_json_file):

    data_release = read_json(release_json_file)

    if not data_release:
        log(f"Empty release file {release_json_file}")
        exit(0)

    ns = get_release_namespace(data_release)
    log(f"Namespace extracted from file {release_json_file}: {ns}")
    return ns


def search_issues():
    parser = argparse.ArgumentParser(description='Get all issues from Jira query')
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-u', '--url', help='URL to Jira', required=True)
    parser.add_argument('-q', '--query', help='Jira qrl query', required=True)
    parser.add_argument('-s', '--secretName', help='Name of k8s secret that holds JIRA credentials with email and apitoken keys', required=True)
    parser.add_argument('-l', '--limit', help='Limit of JIRA issues to retrieve', required=False, default=500)
    parser.add_argument('-r', '--release', help='Path to current release file. Not used, supported to align the interface.', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file. Not used, supported to align the interface.', required=False)
    args = vars(parser.parse_args())

    args['url'] = validate_jira_url(args['url'])
    namespace = get_namespace_from_release(args['release'])
    email, api_token = get_secret_data(namespace, args['secretName'])

    issues = query_jira(args['url'], args['query'], email, api_token, int(args['limit']))

    # source needs to not have the https:// prefix
    return create_json_record(issues, args['url'].replace("https://",""))


def log(message):
    print(message, file=sys.stderr)


_DISALLOWED_JIRA_HOST_SUFFIXES = (".local", ".internal", ".localdomain", ".cluster.local", ".svc")


def validate_jira_url(url):
    """
    Reject a --url value that isn't a plausible external Jira instance, so
    the Basic-auth credentials this script sends can't be redirected to an
    arbitrary or cluster-internal host (SSRF / credential exfiltration).
    """
    parsed = urlparse(url)

    if parsed.scheme != "https":
        print(f"Error: --url must use https, got '{parsed.scheme or url}'")
        exit(1)

    if parsed.username or parsed.password:
        print("Error: --url must not contain embedded userinfo (e.g. user:pass@host)")
        exit(1)

    hostname = parsed.hostname
    if not hostname:
        print("Error: --url does not contain a valid hostname")
        exit(1)

    try:
        ipaddress.ip_address(hostname)
        print("Error: --url must be a hostname, not a raw IP address")
        exit(1)
    except ValueError:
        pass  # not an IP literal, as expected for a real Jira hostname

    if hostname == "localhost" or hostname.endswith(_DISALLOWED_JIRA_HOST_SUFFIXES):
        print(f"Error: --url host '{hostname}' is not a permitted external Jira host")
        exit(1)

    # A public-looking hostname can still be configured (or, via DNS
    # rebinding, re-configured after this check) to resolve to a
    # private/loopback/link-local address. Resolve it now and reject any
    # such address.
    #
    # This narrows but does not eliminate a rebinding attacker: requests/
    # urllib3 performs its own independent lookup when it actually
    # connects, moments later. Closing that fully would mean pinning the
    # connection to this resolved address (custom HTTPAdapter or an
    # extra dependency), which isn't worth it here: whoever can set
    # --url is, in every real deployment, the same party who already
    # owns --secretName's k8s Secret and therefore already has
    # namespace-level RBAC to run arbitrary pipelines/pods with the same
    # network reach directly -- rebinding this request wouldn't grant
    # them a capability they don't already have.
    try:
        resolved_addrs = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except OSError as exc:
        print(f"Error: unable to resolve --url host '{hostname}': {exc}")
        exit(1)

    for addr in resolved_addrs:
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            print(f"Error: --url host '{hostname}' resolves to a private/internal address ({addr}), which is not permitted")
            exit(1)

    return url


def create_json_record(issues, url):
    """
    {
      "releaseNotes": {
         "issues": {
            "fixed": [
               { "id": "CPAAS-1234", "source": "redhat.atlassian.net" },
               { "id": "CPAAS-5678", "source": "redhat.atlassian.net" }
            ]
         }
      }
    }
    """

    fixed_issues = [
        {
            "id": item.get('key'),
            "source": url,
            "summary": item.get('summary'),
            "cveid": item.get('cveid') if item.get('cveid') else None
        }
        for item in issues
    ]

    data = {
        "releaseNotes": {
            "issues": {
                "fixed": fixed_issues
            }
        }
    }
    return data


def get_secret_data(namespace, secret_name):
    """
    Retrieve Jira Cloud credentials from a Kubernetes secret.

    The secret must contain:
      - 'email': Service account email for Jira Cloud
      - 'apitoken': API token generated at id.atlassian.com

    Returns:
        tuple: (email, api_token) for Basic auth
    """
    log(f"Getting secret: {secret_name}")
    cmd = ["kubectl", "get", "secret", secret_name, "-n", namespace, "-ojson"]
    try:
        cmd_str = " ".join(cmd)
        log(f"Running '{cmd_str}'")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        log(f"Command '{cmd_str}' failed, check exception for details")
        raise
    except Exception as exc:
        log(f"Warning: Unknown error occurred when running command '{cmd_str}'")
        raise RuntimeError from exc

    secret_data = json.loads(result.stdout)

    if "email" not in secret_data["data"]:
        print("Error: secret does not contain the 'email' key")
        exit(1)
    if "apitoken" not in secret_data["data"]:
        print("Error: secret does not contain the 'apitoken' key")
        exit(1)

    email = base64.b64decode(secret_data["data"]["email"]).decode("utf-8").strip()
    api_token = base64.b64decode(secret_data["data"]["apitoken"]).decode("utf-8").strip()

    return (email, api_token)


def query_jira(jira_domain_url, jql_query, email, api_token, max_results):
    """
    Query Jira Cloud API v3 for issues matching the JQL query.

    Uses GET /rest/api/3/search/jql with Basic auth (email:token).
    Cloud custom field for CVE ID: customfield_10667

    Paginates using nextPageToken from the response until all results
    are retrieved or max_results is reached.
    """
    # Strip trailing slash to avoid double-slash in URL
    base_url = jira_domain_url.rstrip('/')
    url = f'{base_url}/rest/api/3/search/jql'

    # Fields as comma-separated string (Cloud v3 requirement)
    # customfield_10667 = CVE ID on Jira Cloud (was customfield_12324749 on Server)
    fields = 'summary,status,assignee,customfield_10667'

    list_issues = []
    next_page_token = None
    while True:
        params = {
            'jql': jql_query,
            'fields': fields
        }
        if next_page_token:
            params['nextPageToken'] = next_page_token

        response = requests.get(
            url,
            params=params,
            auth=(email, api_token),
        )

        if response.status_code != 200:
            print(f"ERROR: Failed to retrieve data. HTTP Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            exit(1)

        data = response.json()
        for issue in data['issues']:
            list_issues.append({
                "key": issue["key"],
                "summary": issue["fields"].get("summary"),
                "cveid": issue["fields"].get("customfield_10667")
            })

        next_page_token = data.get('nextPageToken')
        if not next_page_token:
            break

        if len(list_issues) >= max_results:
            break

        log(f"Fetched {len(list_issues)} issues so far, retrieving next page...")

    log(f"Total issues fetched: {len(list_issues)}")
    if len(list_issues) > max_results:
        log(f"Trimmed issues to {max_results} as it was requested by the `--limit` parameter.")
        list_issues = list_issues[:max_results]

    return list_issues


if __name__ == "__main__":
    return_issues = search_issues()
    print(json.dumps(return_issues))
