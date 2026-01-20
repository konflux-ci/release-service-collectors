import os
import pytest
import requests
import subprocess
from collections import namedtuple

import lib.jira
from lib.jira import query_jira, get_secret_data, create_json_record, interpolate_query


MockResponse = namedtuple('MockResponse', ['status_code', 'json'])


def mock_isfile(file):
    return True


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


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

    def mock_post(url, headers, data):
        # Simulating a successful response with no issues (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_empty)

    monkeypatch.setattr(requests, 'post', mock_post)
    result = query_jira("https://mock-domain.com", "project = TEST", "abcdef")
    assert result == []


mock_reponse_data_failure = {'issues': []}


# Test case for failed API response
def test_query_jira_failure(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)

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


@pytest.mark.parametrize(
    'response_data,expected',
    [
        (
            {
                'issues': [
                    {"key": "KONFLUX-1", 'fields': {'summary': 'summary 1', 'customfield_12324749': 'CVE-1234'}},
                    {"key": "KONFLUX-2", 'fields': {'summary': 'summary 2', 'customfield_12324749': 'CVE-2324'}}
                ]
            },
            [
                {'key': 'KONFLUX-1', 'summary': 'summary 1', 'cveid': 'CVE-1234'},
                {'key': 'KONFLUX-2', 'summary': 'summary 2', 'cveid': 'CVE-2324'}
            ]
        ),
        
        (
            {
                'issues': [
                    {"key": "KONFLUX-1", 'fields': {'summary': 'summary "1"', 'customfield_12324749': 'CVE-1234'}},
                    {"key": "KONFLUX-2", 'fields': {'summary': 'summary "2"', 'customfield_12324749': 'CVE-2324'}}
                ]
            },
            [
                {'key': 'KONFLUX-1', 'summary': 'summary \"1\"', 'cveid': 'CVE-1234'},
                {'key': 'KONFLUX-2', 'summary': 'summary \"2\"', 'cveid': 'CVE-2324'}
            ]
        ),       
    ]
)

# Test case for successful API response
def test_query_jira_success(monkeypatch, response_data, expected):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)

    def mock_post(url, headers, data):
        # Simulate a successful response (HTTP 200)
        return MockResponse(status_code=200, json=lambda: response_data)

    monkeypatch.setattr(requests, 'post', mock_post)

    result = query_jira("https://mock-domain.com", "project = TEST", "abcdef")
    assert result == expected


    
@pytest.mark.parametrize(
    "query_data,expected",
    [
        (
            [{'key': 'KONFLUX-1', 'summary': 'summary 1', 'cveid': 'CVE-1234'},
            {'key': 'KONFLUX-2', 'summary': 'summary 2', 'cveid': 'CVE-2324'}
            ],
            {
            "releaseNotes": {
                    "issues": {
                        "fixed": [
                            { "id": "KONFLUX-1", "source": "mock-domain.com", "summary": "summary 1", "cveid": "CVE-1234" },
                            { "id": "KONFLUX-2", "source": "mock-domain.com", "summary": "summary 2", "cveid": "CVE-2324" }             
                        ]
                }
                }
            }
        ),
        (
            [{'key': 'KONFLUX-1', 'summary': 'summary \"1\"', 'cveid': 'CVE-1234'},
            {'key': 'KONFLUX-2', 'summary': 'summary \"2\"', 'cveid': 'CVE-2324'}
            ],
            {
            "releaseNotes": {
                    "issues": {
                        "fixed": [
                            { "id": "KONFLUX-1", "source": "mock-domain.com", "summary": "summary \"1\"", "cveid": "CVE-1234" },
                            { "id": "KONFLUX-2", "source": "mock-domain.com", "summary": "summary \"2\"", "cveid": "CVE-2324" }             
                        ]
                }
                }
            }
        ),       
    ],
)
def test_create_json_record(query_data, expected):
    result = create_json_record(query_data, "mock-domain.com")
    assert result == expected


@pytest.mark.parametrize(
    "query,release_data,expected",
    [
        # Success case: single variable
        (
            'project = CPAAS AND fixVersion = "{{ spec.data.releaseNotes.product_version }}"',
            {"spec": {"data": {"releaseNotes": {"product_version": "2.1.1"}}}},
            'project = CPAAS AND fixVersion = "2.1.1"'
        ),
        # Success case: multiple variables
        (
            'project = {{ spec.data.project }} AND fixVersion = "{{ spec.data.version }}"',
            {"spec": {"data": {"project": "KONFLUX", "version": "3.0.0"}}},
            'project = KONFLUX AND fixVersion = "3.0.0"'
        ),
        # Edge case: no variables (passthrough)
        (
            'project = CPAAS AND status = Done',
            {"spec": {"data": {}}},
            'project = CPAAS AND status = Done'
        ),
        # Edge case: nested access
        (
            'fixVersion = "{{ spec.data.releaseNotes.product_version }}"',
            {"spec": {"data": {"releaseNotes": {"product_version": "1.0.0-rc1"}}}},
            'fixVersion = "1.0.0-rc1"'
        ),
    ]
)
def test_interpolate_query(query, release_data, expected):
    result = interpolate_query(query, release_data)
    assert result == expected


def test_interpolate_query_undefined_exits():
    """When a variable is undefined, exit with error."""
    query = 'fixVersion = "{{ spec.data.missing }}"'
    release_data = {"spec": {"data": {}}}
    with pytest.raises(SystemExit):
        interpolate_query(query, release_data)
