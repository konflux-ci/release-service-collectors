import pytest
import subprocess
from lib.get_cve import git_log_titles

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
    "feat(CVE-3446): test3",
]

mock_result_good = [
    "fix(CVE-3444): test1",
    "fix(CVE-3445): test2"
]
mock_reponse_data_empty = []


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_git_log_success(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout="\n".join(mock_list_titles_2), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    res = git_log_titles("https://mock-domain.com", "main")
    assert res == mock_result_good


def test_git_log_iempty_success(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=0, stdout="\n".join(mock_list_titles_1), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    result = git_log_titles("https://mock-domain.com", "main")
    assert result == mock_reponse_data_empty


def test_git_log_fail(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output=True, text=True):
        return MockCompletedProcess(returncode=128, stdout="\n".join(mock_list_titles_2), stderr="")
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    with pytest.raises(SystemExit):
        git_log_titles("https://mock-domain.com", "main")
