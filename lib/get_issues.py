#!/usr/bin/env python
"""
python lib/get_issue.py \
    tenant \
     --url https://issues.redhat.com \
    --query 'project = KONFLUX AND status = "NEW"' \
     --credentials-file ../cred-file.json
"""

import argparse
import json
import os
import requests


def search_issues():
    parser = argparse.ArgumentParser(description='Get all issues from Jira query')
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-u', '--url', help='URL to Jira', required=True)
    parser.add_argument('-q', '--query', help='Jira qrl query', required=True)
    parser.add_argument('-c', '--credentials-file', help='Path to credentials file', required=True)
    args = vars(parser.parse_args())

    if (not os.path.isfile(args['credentials_file'])):
        print(f"ERROR: Path to credentials file {args['credentials_file']} doesn't exists")
        exit(1)

    return query_jira(args['url'], args['query'], args['credentials_file'])


def parse_credentials_file(credentials_file):
    """
    format credentials file:
    {
         "api_token": "token_id"
    }
    """
    # Open and read the JSON file
    with open(credentials_file, 'r') as file:
        data = json.load(file)
    return data


def query_jira(jira_domain_url, jql_query, credentials_file):
    credentials = parse_credentials_file(credentials_file)
    api_token = credentials["api_token"]

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
    return_list_issues = search_issues()
    print(return_list_issues)
