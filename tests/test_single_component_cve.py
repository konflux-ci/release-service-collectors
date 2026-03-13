import importlib
import pytest
import subprocess

# Import module with hyphens in name using importlib
single_component_cve = importlib.import_module("lib.single-component-cve")

single_component_info = single_component_cve.single_component_info
create_cves_record = single_component_cve.create_cves_record
git_log_titles_per_component = single_component_cve.git_log_titles_per_component
get_single_component_from_snapshot = single_component_cve.get_single_component_from_snapshot
clear_repo_cache = single_component_cve.clear_repo_cache
cleanup_repo_cache = single_component_cve.cleanup_repo_cache


@pytest.fixture(autouse=True)
def reset_repo_cache():
    """Clear the repo cache before each test to ensure isolation."""
    clear_repo_cache()
    yield
    cleanup_repo_cache()


class MockCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_get_single_component_from_snapshot_with_labels():
    """Test extraction of component name from snapshot with proper labels."""
    snapshot_data = {
        "metadata": {
            "labels": {
                "test.appstudio.openshift.io/type": "component",
                "appstudio.openshift.io/component": "my-component"
            }
        }
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result == "my-component"


def test_get_single_component_from_snapshot_missing_type_label():
    """Test that None is returned when type label is missing."""
    snapshot_data = {
        "metadata": {
            "labels": {
                "appstudio.openshift.io/component": "my-component"
            }
        }
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result is None


def test_get_single_component_from_snapshot_wrong_type():
    """Test that None is returned when type is not 'component'."""
    snapshot_data = {
        "metadata": {
            "labels": {
                "test.appstudio.openshift.io/type": "group",
                "appstudio.openshift.io/component": "my-component"
            }
        }
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result is None


def test_get_single_component_from_snapshot_missing_component_label():
    """Test that None is returned when component label is missing."""
    snapshot_data = {
        "metadata": {
            "labels": {
                "test.appstudio.openshift.io/type": "component"
            }
        }
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result is None


def test_get_single_component_from_snapshot_no_labels():
    """Test that None is returned when no labels exist."""
    snapshot_data = {
        "metadata": {}
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result is None


def test_create_cves_record_single_component():
    """Test CVE record creation for a single component."""
    cves = {'my-component': ['CVE-2024-1234', 'CVE-2024-5678']}
    result = create_cves_record(cves)

    expected = {
        "releaseNotes": {
            "cves": [
                {"key": "CVE-2024-1234", "component": "my-component"},
                {"key": "CVE-2024-5678", "component": "my-component"},
            ]
        }
    }
    assert result == expected


def test_create_cves_record_empty():
    """Test CVE record creation with no CVEs."""
    result = create_cves_record({})
    expected = {"releaseNotes": {"cves": []}}
    assert result == expected


def test_git_log_titles_single_component(monkeypatch):
    """Test git log processing for a single component."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        if "clone" in cmd:
            assert "--filter=blob:none" in cmd
            assert "--no-checkout" in cmd
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            assert "--format=%s%n%b" in cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="fix: CVE-2024-1234 security patch\nfeat: add new feature\nfix: CVE-2024-5678 another fix",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    titles = git_log_titles_per_component(git_url, revision_current, revision_prev, secret_data)
    assert "CVE-2024-1234" in titles
    assert "CVE-2024-5678" in titles
    assert len(titles) == 2


def test_git_log_with_context_filter(monkeypatch):
    """Test git log filters commits by context (subdirectory) path."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    context = "components/my-app"
    captured_cmd = []

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal captured_cmd
        if "clone" in cmd:
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            captured_cmd = cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="fix: CVE-2024-1234 security patch",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    titles = git_log_titles_per_component(git_url, revision_current, revision_prev, secret_data, context)

    # Verify the context path was added to git log command
    assert "--" in captured_cmd
    assert context in captured_cmd
    assert "CVE-2024-1234" in titles


def test_git_log_without_context(monkeypatch):
    """Test git log works without context (no path filter)."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    captured_cmd = []

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal captured_cmd
        if "clone" in cmd:
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            captured_cmd = cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="fix: CVE-2024-5678 another fix",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    titles = git_log_titles_per_component(git_url, revision_current, revision_prev, secret_data, context=None)

    # Verify no path filter was added
    assert "--" not in captured_cmd
    assert "CVE-2024-5678" in titles


def test_single_component_only_clones_once(monkeypatch):
    """Test that single component mode only clones the repo once."""
    git_url = "https://example.com/monorepo"
    secret_data = {}
    clone_count = 0

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal clone_count
        if "clone" in cmd:
            clone_count += 1
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd or "show" in cmd:
            return MockCompletedProcess(returncode=0, stdout="CVE-9999 fixed", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    # Process one component
    git_log_titles_per_component(git_url, "rev1", "rev0", secret_data)

    assert clone_count == 1, f"Expected 1 clone for single component, but got {clone_count}"
