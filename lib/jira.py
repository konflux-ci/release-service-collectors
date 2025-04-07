#!/usr/bin/env python
"""
python lib/get_issue.py \
    tenant \
     --url https://issues.redhat.com \
     --query 'project = KONFLUX AND status = "NEW"' \
     --credentials-file ../cred-file.json \
     --release release.json \
     --previousRelease previous_release.json

output:
{
  "releaseNotes": {
    "issues": {
      "fixed": [
        { "id": "CPAAS-1234", "source": "issues.redhat.com" },
        { "id": "CPAAS-5678", "source": "issues.redhat.com" }
      ]
    }
  }
}
"""

import argparse
import base64
import json
import os
import sys
import subprocess
import requests


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
    parser.add_argument('-s', '--secretName', help='Name of k8s secret that holds JIRA credentials with an apitoken key', required=True)
    parser.add_argument('-r', '--release', help='Path to current release file. Not used, supported to align the interface.', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file. Not used, supported to align the interface.', required=False)
    args = vars(parser.parse_args())

    namespace = get_namespace_from_release(args['release'])
    credentials = get_secret_data(namespace, args['secretName'])

    issues =  query_jira(args['url'], args['query'], credentials)

    # source needs to not have the https:// prefix
    return create_json_record(issues, args['url'].replace("https://",""))


def log(message):
    print(message, file=sys.stderr)


def create_json_record(issues, url):
    """
    {
      "releaseNotes": {
         "issues": {
            "fixed": [
               { "id": "CPAAS-1234", "source": "issues.redhat.com" },
               { "id": "CPAAS-5678", "source": "issues.redhat.com" }
            ]
         }
      }
    }
    """
    data = {
      "releaseNotes": {
         "issues": {
            "fixed":
                [{ "id": issue, "source": url }  for issue in issues]
         }
      }
    }
    return data


def get_secret_data(namespace, secret_name):
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
    if "apitoken" not in secret_data["data"]:
        print("Error: secret does not contain the 'apitoken' key")
        exit(1)

    secret = secret_data["data"]["apitoken"]

    return base64.b64decode(secret).decode("utf-8")


def query_jira(jira_domain_url, jql_query, api_token):

    # Define the endpoint URL
    url = f'{jira_domain_url}/rest/api/2/search'

    # Define your JQL query and other parameters
    # example of jql query:
    # 'project = "KONFLUX" AND status = "To Do"'
    start_at = 0
    max_results = 50
    fields = ['summary', 'status', 'assignee']

    # Construct the JSON payload
    data = {
        'jql': jql_query,
        'startAt': start_at,
        'maxResults': max_results,
        'fields': fields
    }

    # Create the headers
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + api_token
    }

    response = requests.post(
        url,
        headers=headers,
        data=json.dumps(data),
    )

    # Check the response
    list_issues = []
    if response.status_code == 200:
        issues = response.json()['issues']
        for issue in issues:
            list_issues.append(issue["key"])
    else:
        print(f"ERROR: Failed to retrieve data. HTTP Status Code: {response.status_code}")
        exit(1)

    return list_issues


if __name__ == "__main__":
    return_issues = search_issues()
    print(json.dumps(return_issues))
