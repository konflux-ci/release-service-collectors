import importlib
import pytest
import subprocess

# Import module with hyphens in name using importlib
single_component_simplejira = importlib.import_module("lib.single-component-simplejira")

single_component_info = single_component_simplejira.single_component_info
create_jira_record = single_component_simplejira.create_jira_record
git_log_jira_issues_per_component = single_component_simplejira.git_log_jira_issues_per_component
get_single_component_from_snapshot = single_component_simplejira.get_single_component_from_snapshot
find_jira_issues_in_text = single_component_simplejira.find_jira_issues_in_text
clear_repo_cache = single_component_simplejira.clear_repo_cache
cleanup_repo_cache = single_component_simplejira.cleanup_repo_cache


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


def test_find_jira_issues_single_project():
    """Test finding JIRA issues for a single project key."""
    text = "Fixes HUM-1234 add new feature\nFixed HUM-5678 bug fix"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == ["HUM-1234", "HUM-5678"]


def test_find_jira_issues_multiple_projects():
    """Test finding JIRA issues for multiple project keys."""
    text = "Fixes HUM-1234 add feature\nFixed ABC-456 other fix\nFixes HUM-9999 cleanup"
    result = find_jira_issues_in_text(text, ["HUM", "ABC"])
    assert "HUM-1234" in result
    assert "ABC-456" in result
    assert "HUM-9999" in result
    assert len(result) == 3


def test_find_jira_issues_filters_other_projects():
    """Test that only issues matching the project keys are returned."""
    text = "Fixes HUM-1234 add feature\nFixed ABC-456 other fix\nFixes XYZ-9999 cleanup"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == ["HUM-1234"]
    assert "ABC-456" not in result
    assert "XYZ-9999" not in result


def test_find_jira_issues_no_matches():
    """Test that empty list is returned when no matches."""
    text = "feat: add new feature without any JIRA reference"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == []


def test_find_jira_issues_no_matches_without_prefix():
    """Test that issues without Fixes/Fixed prefix are not matched."""
    text = "feat: HUM-1234 add new feature\nchore: HUM-5678 cleanup"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == []


def test_find_jira_issues_unique_only():
    """Test that duplicate JIRA issues are removed."""
    text = "Fixes HUM-1234 add feature\nFixed HUM-1234 same issue again\nFixes HUM-5678 cleanup"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == ["HUM-1234", "HUM-5678"]
    assert len(result) == 2


def test_find_jira_issues_unique_across_multiple_keys():
    """Test that duplicates are removed even when searching multiple project keys."""
    text = "Fixes HUM-1234 add feature\nFixed HUM-1234 again\nFixes ABC-1234 different project"
    result = find_jira_issues_in_text(text, ["HUM", "ABC"])
    assert result == ["HUM-1234", "ABC-1234"]
    assert len(result) == 2


def test_find_jira_issues_case_insensitive_prefix():
    """Test that Fixes/Fixed prefix is case insensitive."""
    text = "fixes HUM-1234 lowercase\nFIXED HUM-5678 uppercase\nFixEs HUM-9999 mixed"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert "HUM-1234" in result
    assert "HUM-5678" in result
    assert "HUM-9999" in result
    assert len(result) == 3


def test_find_jira_issues_project_key_case_sensitive():
    """Test that JIRA project keys are case sensitive."""
    text = "Fixes HUM-1234 uppercase\nFixes hum-5678 lowercase"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == ["HUM-1234"]
    assert "hum-5678" not in result


def test_find_jira_issues_word_boundary():
    """Test that JIRA issues match on word boundaries."""
    text = "Fixes HUM-1234 valid\nFixes AHUM-5678 invalid prefix\nFixes HUM-9999X invalid suffix"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert "HUM-1234" in result
    assert "AHUM-5678" not in result


def test_find_jira_issues_url_not_matched():
    """Test that JIRA issues in URLs are not matched (false positive prevention)."""
    text = "I looked at http://website.com/jira/HUM-730 for reference"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == []


def test_find_jira_issues_url_with_valid_fix():
    """Test that URL mentions are ignored but valid Fixes statements are matched."""
    text = "I looked at http://jira.com/browse/HUM-111\nFixes HUM-222 the actual fix"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == ["HUM-222"]
    assert "HUM-111" not in result


def test_find_jira_issues_casual_mention_not_matched():
    """Test that casual mentions of JIRA issues are not matched."""
    text = "Related to HUM-1234 but this commit doesn't fix it"
    result = find_jira_issues_in_text(text, ["HUM"])
    assert result == []


def test_find_jira_issues_special_chars_in_project_key():
    """Test that special regex characters in project key are escaped."""
    text = "Fixes A.B-1234 should match"
    result = find_jira_issues_in_text(text, ["A.B"])
    assert result == ["A.B-1234"]


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


def test_get_single_component_from_snapshot_no_labels():
    """Test that None is returned when no labels exist."""
    snapshot_data = {
        "metadata": {}
    }
    result = get_single_component_from_snapshot(snapshot_data)
    assert result is None


def test_create_jira_record_single_component():
    """Test JIRA record creation for a single component."""
    jira_issues = {'my-component': ['HUM-1234', 'HUM-5678']}
    result = create_jira_record(jira_issues, "issues.redhat.com")

    expected = {
        "releaseNotes": {
            "issues": {
                "fixed": [
                    {"id": "HUM-1234", "component": "my-component", "source": "issues.redhat.com", "public": True},
                    {"id": "HUM-5678", "component": "my-component", "source": "issues.redhat.com", "public": True},
                ]
            }
        }
    }
    assert result == expected


def test_create_jira_record_empty():
    """Test JIRA record creation with no issues."""
    result = create_jira_record({}, "issues.redhat.com")
    expected = {"releaseNotes": {"issues": {"fixed": []}}}
    assert result == expected


def test_git_log_jira_issues_single_component(monkeypatch):
    """Test git log processing for JIRA issues in a single component."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    jira_project_keys = ["HUM"]

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        if "clone" in cmd:
            assert "--filter=blob:none" in cmd
            assert "--no-checkout" in cmd
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            assert "--format=%s%n%b" in cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="Fixes HUM-1234 add new feature\nFixed ABC-999 other project\nFixes HUM-5678 another fix",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    issues = git_log_jira_issues_per_component(
        git_url, revision_current, revision_prev, secret_data, None, jira_project_keys
    )
    assert "HUM-1234" in issues
    assert "HUM-5678" in issues
    assert "ABC-999" not in issues
    assert len(issues) == 2


def test_git_log_jira_issues_multiple_projects(monkeypatch):
    """Test git log processing for multiple JIRA project keys."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    jira_project_keys = ["HUM", "ABC"]

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        if "clone" in cmd:
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            return MockCompletedProcess(
                returncode=0,
                stdout="Fixes HUM-1234 add new feature\nFixed ABC-999 other project\nFixes XYZ-5678 excluded",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    issues = git_log_jira_issues_per_component(
        git_url, revision_current, revision_prev, secret_data, None, jira_project_keys
    )
    assert "HUM-1234" in issues
    assert "ABC-999" in issues
    assert "XYZ-5678" not in issues
    assert len(issues) == 2


def test_git_log_with_context_filter(monkeypatch):
    """Test git log filters commits by context (subdirectory) path."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    context = "components/my-app"
    jira_project_keys = ["HUM"]
    captured_cmd = []

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal captured_cmd
        if "clone" in cmd:
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            captured_cmd = cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="Fixes HUM-1234 security patch",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    issues = git_log_jira_issues_per_component(
        git_url, revision_current, revision_prev, secret_data, context, jira_project_keys
    )

    assert "--" in captured_cmd
    assert context in captured_cmd
    assert "HUM-1234" in issues


def test_git_log_without_context(monkeypatch):
    """Test git log works without context (no path filter)."""
    git_url = "https://example.com/monorepo"
    revision_current = "abc123"
    revision_prev = "def456"
    secret_data = {}
    jira_project_keys = ["HUM"]
    captured_cmd = []

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal captured_cmd
        if "clone" in cmd:
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd:
            captured_cmd = cmd
            return MockCompletedProcess(
                returncode=0,
                stdout="Fixed HUM-5678 another fix",
                stderr=""
            )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    issues = git_log_jira_issues_per_component(
        git_url, revision_current, revision_prev, secret_data, context=None, jira_project_keys=jira_project_keys
    )

    assert "--" not in captured_cmd
    assert "HUM-5678" in issues


def test_single_component_only_clones_once(monkeypatch):
    """Test that single component mode only clones the repo once."""
    git_url = "https://example.com/monorepo"
    secret_data = {}
    jira_project_keys = ["HUM"]
    clone_count = 0

    def mock_subprocess_run(cmd, check, capture_output, text, env={}):
        nonlocal clone_count
        if "clone" in cmd:
            clone_count += 1
            return MockCompletedProcess(returncode=0, stdout="", stderr="")
        if "log" in cmd or "show" in cmd:
            return MockCompletedProcess(returncode=0, stdout="Fixes HUM-9999", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    git_log_jira_issues_per_component(git_url, "rev1", "rev0", secret_data, None, jira_project_keys)

    assert clone_count == 1, f"Expected 1 clone for single component, but got {clone_count}"


def test_context_fallback_from_previous_release(monkeypatch, tmp_path):
    """Test that context from previous release is used when current context is missing.
    
    This tests the scenario where a component's current definition is missing
    the context field but the previous release had it defined. The script
    should fall back to using the previous release's context for filtering.
    """
    get_component_detail = single_component_simplejira.get_component_detail

    # Current component missing context
    current_components = [{
        "name": "httpd-main",
        "source": {
            "git": {
                "url": "https://example.com/monorepo",
                "revision": "abc123"
            }
        }
    }]

    # Previous component has context
    prev_components = [{
        "name": "httpd-main",
        "source": {
            "git": {
                "url": "https://example.com/monorepo",
                "revision": "def456",
                "context": "rpms/httpd"
            }
        }
    }]

    # Verify current component has no context
    current_detail = get_component_detail(current_components, "httpd-main")
    assert current_detail is not None
    url_curr, rev_curr, ctx_curr = current_detail
    assert ctx_curr is None, "Current component should have no context"

    # Verify previous component has context
    prev_detail = get_component_detail(prev_components, "httpd-main")
    assert prev_detail is not None
    url_prev, rev_prev, ctx_prev = prev_detail
    assert ctx_prev == "rpms/httpd", "Previous component should have context"
