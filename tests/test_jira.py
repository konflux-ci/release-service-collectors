import os
import pytest
import requests
import subprocess
from collections import namedtuple

import lib.jira
from lib.jira import query_jira, get_namespace_from_release, get_secret_data, create_json_record


MockResponse = namedtuple('MockResponse', ['status_code', 'json'])


def mock_isfile(file):
    return True


def test_get_namespace_from_release(monkeypatch):
    with open("release.json", "w") as release_file:
        release_file.write('{"apiVersion":"appstudio.redhat.com/v1alpha1","kind":"Release",'
                           '"metadata":{"generateName":"manual-collectors-","namespace":'
                           '"dev-release-team-tenant"},''"spec":{"gracePeriodDays":7,'
                           '"releasePlan":"trusted-artifacts-rp-collectors","snapshot":'
                           '"trusted-artifacts-poc-7jtjm"}}')
    results = get_namespace_from_release("release.json")
    assert results == "dev-release-team-tenant"


def mock_empty_query_jira(url, query, file):
    return []


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def mock_get_namespace_from_release(release):
    return "dev-release-team-tenant"


def test_get_secret_data(monkeypatch):
    mock_secret_json = ('{"kind":"Secret","apiVersion":"v1","metadata":{"name":"jira-collectors-secret","namespace":'
                        '"dev-release-team-tenant","labels":{"konflux-ci.dev/collector":"jira-collector"}},'
                        '"data":{"apitoken":"c2NvdHRvCg=="},"type":"Opaque"}')
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout=mock_secret_json, stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    result = get_secret_data("dev-release-team-tenant", "jira-collectors-secret")
    assert result == "scotto\n"

# empty response data
mock_reponse_data_empty = {'issues': []}


def test_query_jira_empty_response(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)
    monkeypatch.setattr(lib.jira, 'query_jira', mock_empty_query_jira)

    def mock_post(url, headers, data):
        # Simulating a successful response with no issues (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_empty)

    monkeypatch.setattr(requests, 'post', mock_post)
    result = query_jira("https://mock-domain.com", "project = TEST", "abcdef")
    assert result == []


def mock_fail_query_jira(url, query, file):
    exit(1)


mock_reponse_data_failure = {'issues': []}


# Test case for failed API response
def test_query_jira_failure(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)
    monkeypatch.setattr(lib.jira, 'query_jira', mock_fail_query_jira)

    def mock_post(url, headers, data):
        # Simulate a failed response (HTTP 500)
        return MockResponse(status_code=500, json=lambda: mock_reponse_data_failure)

    monkeypatch.setattr(requests, 'post', mock_post)
    with pytest.raises(SystemExit):
        query_jira("https://mock-domain.com", "project = TEST", "abcdef")


mock_reponse_data_success = {
       'issues': [
          {"key": "KONFLUX-1", 'fields': {'summary': 'summary 1', 'customfield_12324749': 'CVE-1234'}},
          {"key": "KONFLUX-2", 'fields': {'summary': 'summary 2', 'customfield_12324749': 'CVE-2324'}}
       ]
}

mock_query_reuslt_data_success = [
    {'key': 'KONFLUX-1', 'summary': 'summary 1', 'cveid': 'CVE-1234'},
    {'key': 'KONFLUX-2', 'summary': 'summary 2', 'cveid': 'CVE-2324'}
]


expected_result = {
    "releaseNotes": {
        "issues": {
            "fixed": [
                { "id": "KONFLUX-1", "source": "mock-domain.com", "summary": "summary 1", "cveid": "CVE-1234" },
                { "id": "KONFLUX-2", "source": "mock-domain.com", "summary": "summary 2", "cveid": "CVE-2324" }             
            ]
        }
    }
}
# Test case for successful API response
def test_query_jira_success(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)

    def mock_post(url, headers, data):
        # Simulate a successful response (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_success)

    monkeypatch.setattr(requests, 'post', mock_post)

    result = query_jira("https://mock-domain.com", "project = TEST", "abcdef")
    assert result == [{'key': 'KONFLUX-1', 'summary': 'summary 1', 'cveid': 'CVE-1234'},
                      {'key': 'KONFLUX-2', 'summary': 'summary 2', 'cveid': 'CVE-2324'}
                     ]


# Test create json record
def test_create_json_record(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)

    result = create_json_record(mock_query_reuslt_data_success, "mock-domain.com")
    assert result == expected_result