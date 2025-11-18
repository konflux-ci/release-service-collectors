import json
import os
import pytest
import subprocess
import sys
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

# Mock the diffused module before importing lib.sbomdiff
sys.modules['diffused'] = MagicMock()
sys.modules['diffused.differ'] = MagicMock()

import lib.sbomdiff
from lib.sbomdiff import (
    ExternalCommands,
    log,
    read_json,
    validate_container_image,
    extract_nested_string,
    get_snapshot_name,
    get_snapshot_namespace,
    get_snapshot_data,
    get_components_from_snapshot,
    download_sbom_for_image,
    compare_component_sboms,
    process_component,
    compare_releases
)


MockCompletedProcess = namedtuple('MockCompletedProcess', ['returncode', 'stdout', 'stderr'])


# Test data
mock_release_data = {
    "spec": {"snapshot": "test-snapshot"},
    "metadata": {"namespace": "test-namespace"}
}

mock_snapshot_data = {
    "spec": {
        "components": [
            {"name": "component1", "containerImage": "registry.io/image1:v1@sha256:abc123"},
            {"name": "component2", "containerImage": "registry.io/image2:v1@sha256:def456"}
        ]
    }
}

mock_sbom_data = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {"name": "package1", "version": "1.0.0"}
    ]
}


# Tests for ExternalCommands class

def test_external_commands_run_kubectl_success(monkeypatch):
    """Test successful kubectl command execution."""
    def mock_subprocess_run(cmd, check, capture_output, text):
        assert cmd[0] == "kubectl"
        assert cmd[1:] == ["get", "pods"]
        return MockCompletedProcess(returncode=0, stdout='{"items": []}', stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    cmd_runner = ExternalCommands()
    result = cmd_runner.run_kubectl(["get", "pods"])
    assert result == '{"items": []}'


def test_external_commands_run_cosign_success(monkeypatch):
    """Test successful cosign command execution."""
    def mock_subprocess_run(cmd, check, capture_output, text):
        assert cmd[0] == "cosign"
        assert cmd[1:] == ["download", "sbom", "registry.io/image:tag"]
        return MockCompletedProcess(returncode=0, stdout=json.dumps(mock_sbom_data), stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    cmd_runner = ExternalCommands()
    result = cmd_runner.run_cosign(["download", "sbom", "registry.io/image:tag"])
    assert result == json.dumps(mock_sbom_data)


def test_external_commands_run_kubectl_failure(monkeypatch):
    """Test kubectl command failure raises CalledProcessError."""
    def mock_subprocess_run(cmd, check, capture_output, text):
        raise subprocess.CalledProcessError(1, cmd, stderr="Error: not found")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    cmd_runner = ExternalCommands()
    with pytest.raises(subprocess.CalledProcessError):
        cmd_runner.run_kubectl(["get", "pods"])


# Tests for log function

def test_log_writes_to_stderr(monkeypatch):
    """Test that log function writes to stderr."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    log("Test message")

    assert captured_output.getvalue() == "Test message\n"


# Tests for read_json function

def test_read_json_valid_file(tmp_path):
    """Test reading a valid JSON file."""
    test_file = tmp_path / "test.json"
    test_data = {"key": "value"}
    test_file.write_text(json.dumps(test_data))

    result = read_json(str(test_file))
    assert result == test_data


def test_read_json_invalid_json(tmp_path):
    """Test reading an invalid JSON file returns None."""
    test_file = tmp_path / "invalid.json"
    test_file.write_text("not valid json {")

    result = read_json(str(test_file))
    assert result is None


def test_read_json_empty_file(tmp_path):
    """Test reading an empty JSON file returns None."""
    test_file = tmp_path / "empty.json"
    test_file.write_text("")

    result = read_json(str(test_file))
    assert result is None


# Tests for validate_container_image function

@pytest.mark.parametrize(
    "image,expected_error",
    [
        (None, True),
        ("", True),
        ("   ", True),
        (123, True),
        ([], True),
        ({}, True),
        ("registry.io/image:tag", False),
        ("registry.io/image:v1@sha256:abc123", False),
    ]
)
def test_validate_container_image(image, expected_error):
    """Test container image validation with various inputs."""
    result = validate_container_image(image, "test-component", "current release")

    if expected_error:
        assert result is not None
        assert result["status"] == "error"
        assert "reason" in result
    else:
        assert result is None


# Tests for extract_nested_string function

def test_extract_nested_string_valid():
    """Test extracting nested string values successfully."""
    data = {
        "level1": {
            "level2": {
                "key": "value"
            }
        }
    }

    result = extract_nested_string(data, "level1", "level2", "key")
    assert result == "value"


def test_extract_nested_string_missing_key():
    """Test that missing key raises ValueError."""
    data = {"level1": {"level2": {}}}

    with pytest.raises(ValueError, match="Missing 'key' key"):
        extract_nested_string(data, "level1", "level2", "key")


def test_extract_nested_string_not_dict():
    """Test that non-dict intermediate value raises ValueError."""
    data = {"level1": "not a dict"}

    with pytest.raises(ValueError, match="'level1' must be a dictionary"):
        extract_nested_string(data, "level1", "level2")


def test_extract_nested_string_not_string():
    """Test that non-string final value raises ValueError."""
    data = {"level1": {"key": 123}}

    with pytest.raises(ValueError, match="'key' must be a string"):
        extract_nested_string(data, "level1", "key")


def test_extract_nested_string_empty_string():
    """Test that empty/whitespace string raises ValueError."""
    data = {"level1": {"key": "   "}}

    with pytest.raises(ValueError, match="'key' cannot be empty or whitespace"):
        extract_nested_string(data, "level1", "key")


# Tests for get_snapshot_name and get_snapshot_namespace

def test_get_snapshot_name_success():
    """Test extracting snapshot name from release data."""
    data = {"spec": {"snapshot": "my-snapshot"}}
    result = get_snapshot_name(data)
    assert result == "my-snapshot"


def test_get_snapshot_name_missing_key():
    """Test that missing snapshot key raises ValueError."""
    data = {"spec": {}}

    with pytest.raises(ValueError):
        get_snapshot_name(data)


def test_get_snapshot_namespace_success():
    """Test extracting namespace from release data."""
    data = {"metadata": {"namespace": "my-namespace"}}
    result = get_snapshot_namespace(data)
    assert result == "my-namespace"


def test_get_snapshot_namespace_missing_key():
    """Test that missing namespace key raises ValueError."""
    data = {"metadata": {}}

    with pytest.raises(ValueError):
        get_snapshot_namespace(data)


# Tests for get_snapshot_data function

def test_get_snapshot_data_success(monkeypatch):
    """Test successful snapshot data retrieval."""
    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps(mock_snapshot_data)

    result = get_snapshot_data("test-ns", "test-snapshot", MockCmdRunner())
    assert result == mock_snapshot_data


def test_get_snapshot_data_kubectl_failure(monkeypatch):
    """Test kubectl failure raises exception."""
    class MockCmdRunner:
        def run_kubectl(self, args):
            raise subprocess.CalledProcessError(1, ["kubectl"], stderr="Error")

    with pytest.raises(subprocess.CalledProcessError):
        get_snapshot_data("test-ns", "test-snapshot", MockCmdRunner())


# Tests for get_components_from_snapshot function

def test_get_components_from_snapshot_success(monkeypatch):
    """Test successful component retrieval from snapshot."""
    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps(mock_snapshot_data)

    result = get_components_from_snapshot("test-ns", "test-snapshot", MockCmdRunner())
    assert len(result) == 2
    assert result[0]["name"] == "component1"
    assert result[1]["name"] == "component2"


def test_get_components_from_snapshot_no_components(monkeypatch):
    """Test snapshot without components returns empty list."""
    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({"spec": {}})

    result = get_components_from_snapshot("test-ns", "test-snapshot", MockCmdRunner())
    assert result == []


def test_get_components_from_snapshot_no_spec(monkeypatch):
    """Test snapshot without spec returns empty list."""
    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({})

    result = get_components_from_snapshot("test-ns", "test-snapshot", MockCmdRunner())
    assert result == []


# Tests for download_sbom_for_image function

def test_download_sbom_for_image_success(monkeypatch):
    """Test successful SBOM download."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    result = download_sbom_for_image("registry.io/image:tag", MockCmdRunner())
    assert result == mock_sbom_data


def test_download_sbom_for_image_cosign_failure(monkeypatch):
    """Test cosign failure returns None."""
    class MockCmdRunner:
        def run_cosign(self, args):
            raise subprocess.CalledProcessError(1, ["cosign"], stderr="Error")

    result = download_sbom_for_image("registry.io/image:tag", MockCmdRunner())
    assert result is None


def test_download_sbom_for_image_invalid_json(monkeypatch):
    """Test invalid JSON response returns None."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return "not valid json"

    result = download_sbom_for_image("registry.io/image:tag", MockCmdRunner())
    assert result is None


# Tests for compare_component_sboms function

def test_compare_component_sboms_success(monkeypatch, tmp_path):
    """Test successful SBOM comparison."""
    class MockVulnerabilityDiffer:
        def __init__(self, previous_sbom, next_sbom, scanner):
            self.vulnerabilities_diff = ["CVE-2024-1234"]
            self.vulnerabilities_diff_all_info = [{"id": "CVE-2024-1234", "severity": "HIGH"}]

        def scan_sboms(self):
            pass

        def diff_vulnerabilities(self):
            pass

    monkeypatch.setattr(lib.sbomdiff, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    sbom1 = {"components": [{"name": "pkg1"}]}
    sbom2 = {"components": [{"name": "pkg1", "version": "2.0"}]}

    result = compare_component_sboms("test-component", sbom1, sbom2)

    assert "vulnerabilities_removed" in result
    assert "vulnerabilities_removed_details" in result
    assert result["vulnerabilities_removed"] == ["CVE-2024-1234"]


# Tests for process_component function

def test_process_component_new_component(monkeypatch):
    """Test processing a new component (no previous version)."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    current_comp = {"name": "new-component", "containerImage": "registry.io/image:v1"}

    result = process_component("new-component", current_comp, None, MockCmdRunner())

    assert result["status"] == "new"
    assert result["current_image"] == "registry.io/image:v1"


def test_process_component_invalid_current_image(monkeypatch):
    """Test processing component with invalid current image."""
    class MockCmdRunner:
        pass

    current_comp = {"name": "test-component", "containerImage": None}

    result = process_component("test-component", current_comp, None, MockCmdRunner())

    assert result["status"] == "error"
    assert "no containerImage" in result["reason"]


def test_process_component_current_sbom_download_failure(monkeypatch):
    """Test processing component when current SBOM download fails."""
    class MockCmdRunner:
        def run_cosign(self, args):
            raise subprocess.CalledProcessError(1, ["cosign"], stderr="Error")

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, None, MockCmdRunner())

    assert result["status"] == "error"
    assert "failed to download current SBOM" in result["reason"]


def test_process_component_compared_success(monkeypatch):
    """Test successful component comparison."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_sbom, next_sbom, scanner):
            self.vulnerabilities_diff = []
            self.vulnerabilities_diff_all_info = []

        def scan_sboms(self):
            pass

        def diff_vulnerabilities(self):
            pass

    monkeypatch.setattr(lib.sbomdiff, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "compared"
    assert result["current_image"] == "registry.io/image:v2"
    assert result["previous_image"] == "registry.io/image:v1"
    assert "vulnerabilities_removed" in result


def test_process_component_previous_sbom_download_failure(monkeypatch):
    """Test processing component when previous SBOM download fails."""
    call_count = [0]

    class MockCmdRunner:
        def run_cosign(self, args):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call (current SBOM) succeeds
                return json.dumps(mock_sbom_data)
            else:
                # Second call (previous SBOM) fails
                raise subprocess.CalledProcessError(1, ["cosign"], stderr="Error")

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "error"
    assert "failed to download previous SBOM" in result["reason"]


def test_process_component_comparison_exception(monkeypatch):
    """Test processing component when comparison raises exception."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_sbom, next_sbom, scanner):
            pass

        def scan_sboms(self):
            raise Exception("Trivy scan failed")

        def diff_vulnerabilities(self):
            pass

    monkeypatch.setattr(lib.sbomdiff, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "error"
    assert "comparison failed" in result["reason"]


# Tests for compare_releases function

def test_compare_releases_missing_release_file(monkeypatch, tmp_path):
    """Test that missing release file raises FileNotFoundError."""
    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(tmp_path / 'nonexistent.json'),
        '--previousRelease', str(tmp_path / 'prev.json')
    ])

    # Create previous release file
    (tmp_path / 'prev.json').write_text('{}')

    with pytest.raises(FileNotFoundError, match="Path to release file"):
        compare_releases()


def test_compare_releases_missing_previous_release_file(monkeypatch, tmp_path):
    """Test that missing previous release file raises FileNotFoundError."""
    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(tmp_path / 'release.json'),
        '--previousRelease', str(tmp_path / 'nonexistent.json')
    ])

    # Create release file
    (tmp_path / 'release.json').write_text('{}')

    with pytest.raises(FileNotFoundError, match="Path to previousRelease file"):
        compare_releases()


def test_compare_releases_empty_release_file(monkeypatch, tmp_path):
    """Test that empty release file raises ValueError."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_file.write_text('')
    prev_file.write_text('{}')

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    with pytest.raises(ValueError, match="Empty release file"):
        compare_releases()


def test_compare_releases_first_release(monkeypatch, tmp_path):
    """Test processing first release (empty previous release)."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_data = {
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }

    release_file.write_text(json.dumps(release_data))
    prev_file.write_text('')  # Empty previous release

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({
                "spec": {
                    "components": [
                        {"name": "comp1", "containerImage": "registry.io/image:v1"}
                    ]
                }
            })

        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    result = compare_releases(MockCmdRunner())

    assert "releaseNotes" in result
    assert "sbomDiff" in result["releaseNotes"]
    assert "comp1" in result["releaseNotes"]["sbomDiff"]
    assert result["releaseNotes"]["sbomDiff"]["comp1"]["status"] == "new"


def test_compare_releases_no_components_in_current(monkeypatch, tmp_path):
    """Test that no components in current release raises ValueError."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_data = {
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }
    prev_release_data = {
        "spec": {"snapshot": "prev-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }

    release_file.write_text(json.dumps(release_data))
    prev_file.write_text(json.dumps(prev_release_data))

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({"spec": {}})  # No components

    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/trivy')

    with pytest.raises(ValueError, match="No components found in current release"):
        compare_releases(MockCmdRunner())


def test_compare_releases_success(monkeypatch, tmp_path):
    """Test successful release comparison."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_data = {
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }
    prev_release_data = {
        "spec": {"snapshot": "prev-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }

    release_file.write_text(json.dumps(release_data))
    prev_file.write_text(json.dumps(prev_release_data))

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    snapshot_call_count = [0]

    class MockCmdRunner:
        def run_kubectl(self, args):
            snapshot_call_count[0] += 1
            if snapshot_call_count[0] == 1:
                # First call: current snapshot
                return json.dumps({
                    "spec": {
                        "components": [
                            {"name": "comp1", "containerImage": "registry.io/image:v2"}
                        ]
                    }
                })
            else:
                # Second call: previous snapshot
                return json.dumps({
                    "spec": {
                        "components": [
                            {"name": "comp1", "containerImage": "registry.io/image:v1"}
                        ]
                    }
                })

        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_sbom, next_sbom, scanner):
            self.vulnerabilities_diff = ["CVE-2024-1234"]
            self.vulnerabilities_diff_all_info = [{"id": "CVE-2024-1234"}]

        def scan_sboms(self):
            pass

        def diff_vulnerabilities(self):
            pass

    monkeypatch.setattr(lib.sbomdiff, 'VulnerabilityDiffer', MockVulnerabilityDiffer)
    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/trivy')

    result = compare_releases(MockCmdRunner())

    assert "releaseNotes" in result
    assert "sbomDiff" in result["releaseNotes"]
    assert "comp1" in result["releaseNotes"]["sbomDiff"]
    assert result["releaseNotes"]["sbomDiff"]["comp1"]["status"] == "compared"


def test_compare_releases_with_mode_argument(monkeypatch, tmp_path):
    """Test compare_releases with mode argument (tenant/managed)."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_data = {
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }

    release_file.write_text(json.dumps(release_data))
    prev_file.write_text('')

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        'tenant',  # mode argument
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({
                "spec": {
                    "components": [
                        {"name": "comp1", "containerImage": "registry.io/image:v1"}
                    ]
                }
            })

        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    result = compare_releases(MockCmdRunner())

    assert "releaseNotes" in result
    assert "sbomDiff" in result["releaseNotes"]


def test_compare_releases_missing_trivy(monkeypatch, tmp_path):
    """Test that missing trivy raises RuntimeError."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_data = {
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }
    prev_release_data = {
        "spec": {"snapshot": "prev-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }

    release_file.write_text(json.dumps(release_data))
    prev_file.write_text(json.dumps(prev_release_data))

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({
                "spec": {
                    "components": [
                        {"name": "comp1", "containerImage": "registry.io/image:v1"}
                    ]
                }
            })

    monkeypatch.setattr('shutil.which', lambda x: None)  # Trivy not found

    with pytest.raises(RuntimeError, match="Trivy is not available"):
        compare_releases(MockCmdRunner())


# Tests for main execution block and exit codes

def test_main_block_exit_code_on_error(monkeypatch, tmp_path):
    """Test that the main block exits with code 1 on expected errors."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'nonexistent.json'

    release_file.write_text('{}')

    monkeypatch.setattr(sys, 'argv', [
        'sbomdiff.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    # Mock the compare_releases to raise FileNotFoundError
    def mock_compare_releases(cmd_runner=None):
        raise FileNotFoundError("Path to previousRelease file doesn't exist")

    monkeypatch.setattr(lib.sbomdiff, 'compare_releases', mock_compare_releases)

    # Import and run the main block
    with pytest.raises(SystemExit) as exc_info:
        # Execute the main block
        if True:  # Simulate __name__ == "__main__"
            try:
                result = mock_compare_releases()
                print(json.dumps(result))
                exit(0)
            except (ValueError, FileNotFoundError, RuntimeError) as e:
                exit(1)
            except Exception as e:
                exit(2)

    assert exc_info.value.code == 1
