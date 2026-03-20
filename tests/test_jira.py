import os
import pytest
import requests
import subprocess
from collections import namedtuple

import lib.jira
from lib.jira import query_jira, get_namespace_from_release, get_secret_data, create_json_record


MockResponse = namedtuple('MockResponse', ['status_code', 'json', 'text'])


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


def mock_empty_query_jira(url, query, email, api_token, max_results):
    return []


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def mock_get_namespace_from_release(release):
    return "dev-release-team-tenant"


def test_get_secret_data(monkeypatch):
    # email: test@example.com (base64: dGVzdEBleGFtcGxlLmNvbQ==)
    # apitoken: scotto (base64: c2NvdHRv)
    mock_secret_json = ('{"kind":"Secret","apiVersion":"v1","metadata":{"name":"jira-collectors-secret","namespace":'
                        '"dev-release-team-tenant","labels":{"konflux-ci.dev/collector":"jira-collector"}},'
                        '"data":{"email":"dGVzdEBleGFtcGxlLmNvbQ==","apitoken":"c2NvdHRv"},"type":"Opaque"}')
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout=mock_secret_json, stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    email, api_token = get_secret_data("dev-release-team-tenant", "jira-collectors-secret")
    assert email == "test@example.com"
    assert api_token == "scotto"


# empty response data
mock_reponse_data_empty = {'issues': []}


def test_query_jira_empty_response(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)
    monkeypatch.setattr(lib.jira, 'query_jira', mock_empty_query_jira)

    def mock_get(url, params, auth):
        # Simulating a successful response with no issues (HTTP 200)
        return MockResponse(status_code=200, json=lambda: mock_reponse_data_empty, text="")

    monkeypatch.setattr(requests, 'get', mock_get)
    result = query_jira("https://mock-domain.com", "project = TEST", "test@example.com", "abcdef", 50)
    assert result == []


def mock_fail_query_jira(url, query, email, api_token, max_results):
    exit(1)


mock_reponse_data_failure = {'issues': []}


# Test case for failed API response
def test_query_jira_failure(monkeypatch):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)
    monkeypatch.setattr(lib.jira, 'query_jira', mock_fail_query_jira)

    def mock_get(url, params, auth):
        # Simulate a failed response (HTTP 500)
        return MockResponse(status_code=500, json=lambda: mock_reponse_data_failure, text="Internal Server Error")

    monkeypatch.setattr(requests, 'get', mock_get)
    with pytest.raises(SystemExit):
        query_jira("https://mock-domain.com", "project = TEST", "test@example.com", "abcdef", 50)


# Cloud uses customfield_10667 for CVE ID (was customfield_12324749 on Server)
@pytest.mark.parametrize(
    'response_data,expected',
    [
        (
            {
                'issues': [
                    {"key": "KONFLUX-1", 'fields': {'summary': 'summary 1', 'customfield_10667': 'CVE-1234'}},
                    {"key": "KONFLUX-2", 'fields': {'summary': 'summary 2', 'customfield_10667': 'CVE-2324'}}
                ]
            },
            [
                {'key': 'KONFLUX-1', 'summary': 'summary 1', 'cveid': 'CVE-1234'},
                {'key': 'KONFLUX-2', 'summary': 'summary 2', 'cveid': 'CVE-2324'}
            ]
        )
    ]
)


# Test case for successful API response
def test_query_jira_success(monkeypatch, response_data, expected):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)

    def mock_get(url, params, auth):
        # Simulate a successful response (HTTP 200)
        return MockResponse(status_code=200, json=lambda: response_data, text="")

    monkeypatch.setattr(requests, 'get', mock_get)

    result = query_jira("https://mock-domain.com", "project = TEST", "test@example.com", "abcdef", 50)
    assert result == expected

@pytest.mark.parametrize(
    'n_pages,n_issues_page,max_results,n_calls,n_results',
    [
        (1, 25, 10, 1, 10), # We want 10 results, we get returned 25
        (1, 1, 10, 1, 1), # We want 10 results, but there is only one returned
        (100, 100, 1, 1, 1), # There are a lot of pages, but we only want the first result
        (10, 10, 100, 10, 100), # There are a lot of pages, and we want all of them
        (10, 10, 75, 8, 75) # We want half a page for the last one
    ]
)
def test_query_jira_pagination(monkeypatch, n_pages, n_issues_page, max_results, n_calls, n_results):
    """Test that query_jira follows nextPageToken to fetch all pages.

    The first two arguments control the generation of the return data: number of pages
    and number of issues per page. The max_results represents the --limit parameter.
    The n_results and n_calls are controls to check how many things got actually returned
    from the function and how many times a call was issues to Jira.
    """
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)

    pages = []
    for page_n in range(n_pages):
        page = {"issues": [], "nextPageToken": "abc"}
        if page_n == n_pages - 1: # If this is the last page, delete the nextPageToken
            del page["nextPageToken"]

        for issues_per_page in range(n_issues_page):
            page["issues"].append({"key": "KONFLUX-1", 'fields': {'summary': 'summary 1', 'customfield_10667': 'CVE-1234'}})
        pages.append(page)

    call_count = {'n': 0}
    def mock_get(url, params, auth):
        page = pages[call_count['n']]
        call_count['n'] += 1
        return MockResponse(status_code=200, json=lambda: page, text="")

    monkeypatch.setattr(requests, 'get', mock_get)

    result = query_jira("https://mock-domain.com", "project = TEST", "test@example.com", "abcdef", max_results)
    assert len(result) == n_results
    assert call_count['n'] == n_calls



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
def test_create_json_record(monkeypatch, query_data, expected ):
    monkeypatch.setattr(os.path, 'isfile', mock_isfile)
    monkeypatch.setattr(lib.jira, 'get_namespace_from_release', mock_get_namespace_from_release)

    result = create_json_record(query_data, "mock-domain.com")
    assert result == expected
