import os
import pytest
import requests
from collections import namedtuple

import lib.get_issues
from lib.get_issues import query_jira, parse_credentials_file


MockResponse = namedtuple('MockResponse', ['status_code', 'json'])


def mock_isfile(file):
    return True


def mock_parse_credentials_file(file):
    data = {
        "api_token": "mock_api_token_key",
    }
    return data


def test_parse_credentials_file(monkeypatch):
    monkeypatch.setitem(globals(), 'parse_credentials_file', mock_parse_credentials_file)
    results = parse_credentials_file('file')
    assert results == {
        "api_token": "mock_api_token_key",
    }
    assert results["api_token"] == "mock_api_token_key"


def mock_empty_query_jira(url, query, file):
    return []


# empty response data
mock_reponse_data_empty = {'issues': []}


def test_query_jira_empty_response(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.get_issues, 'parse_credentials_file', mock_parse_credentials_file)
    monkeypatch.setattr(lib.get_issues, 'query_jira', mock_empty_query_jira)

    def mock_post(url, headers, data):
        # Simulating a successful response with no issues (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_empty)

    monkeypatch.setattr(requests, 'post', mock_post)
    result = query_jira("https://mock-domain.com", "project = TEST", "mock_credentials_file.json")
    assert result == []


def mock_fail_query_jira(url, query, file):
    exit(1)


mock_reponse_data_failure = {'issues': []}


# Test case for failed API response
def test_query_jira_failure(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.get_issues, 'parse_credentials_file', mock_parse_credentials_file)
    monkeypatch.setattr(lib.get_issues, 'query_jira', mock_fail_query_jira)

    def mock_post(url, headers, data):
        # Simulate a failed response (HTTP 500)
        return MockResponse(status_code=500, json=lambda: mock_reponse_data_failure)

    monkeypatch.setattr(requests, 'post', mock_post)
    with pytest.raises(SystemExit):
        query_jira("https://mock-domain.com", "project = TEST", "mock_credentials_file.json")


mock_reponse_data_success = {
                'issues': [
                    {"key": "KONFLUX-1"},
                    {"key": "KONFLUX-2"}
                ]
            }


# Test case for successful API response
def test_query_jira_success(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.get_issues, 'parse_credentials_file', mock_parse_credentials_file)

    def mock_post(url, headers, data):
        # Simulate a successful response (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_success)

    monkeypatch.setattr(requests, 'post', mock_post)

    result = query_jira("https://mock-domain.com", "project = TEST", "mock_credentials_file.json")

    assert result == ["KONFLUX-1", "KONFLUX-2"]
