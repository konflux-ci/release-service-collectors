import pytest
import subprocess
from lib.cve import create_cves_record
from lib.cve import git_log_titles_per_component

mock_input =  {'comp1': ['CVE-1', 'CVE-3'],'comp2': ['CVE-2', 'CVE-4']}
mock_result_good = {"releaseNotes": {"cves": [{"key": "CVE-1", "component": "comp1"},
                                              {"key": "CVE-3", "component": "comp1"},
                                              {"key": "CVE-2", "component": "comp2"},
                                              {"key": "CVE-4", "component": "comp2"}]}
                    }

mock_reponse_data_empty = []
mock_cve_result_empty = {"releaseNotes": {"cves": []}}


mock_list_titles_1 = [
    "Add memory requirements",
    "fix(XX-3444): test1",
    "fix(XX-3445): test2",
    "feat(XX-3446): test3",
]

mock_list_titles_2 = [
    "Add memory requirements",
    "fix(CVE-3444): test1",
    "fix(CVE-3445): test2",
    "feat(CVE-3446-222): test3",
]

mock_titels2_result = [ "CVE-3444", "CVE-3445", "CVE-3446-222" ]


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_git_log_success(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout="\n".join(mock_list_titles_2), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    res = git_log_titles_per_component("https://mock-domain.com", "12345677", "23456677")
    assert res == mock_titels2_result


def test_git_log_empty_success(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout="\n".join(mock_list_titles_1), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    result = git_log_titles_per_component("https://mock-domain.com", "12345677", "23456677")
    assert result == mock_reponse_data_empty


def test_git_log_fail(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=128, stdout="\n".join(mock_list_titles_2), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    with pytest.raises(SystemExit):
        git_log_titles_per_component("https://mock-domain.com", "12345677", "23456677")


def test_create_json_record(monkeypatch):
    res = create_cves_record(mock_input)
    assert res == mock_result_good


def test_create_json_empty_record(monkeypatch):
    res = create_cves_record(mock_reponse_data_empty)
    assert res == mock_cve_result_empty
