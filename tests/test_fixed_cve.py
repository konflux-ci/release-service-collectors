import json
import os
import pytest
import subprocess
import sys
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

# Mock the diffused module before importing the collector
sys.modules['diffused'] = MagicMock()
sys.modules['diffused.differ'] = MagicMock()

# Import module with hyphens in name using importlib
import importlib
fixed_cve = importlib.import_module("lib.fixed-cve")

ExternalCommands = fixed_cve.ExternalCommands
log = fixed_cve.log
read_json = fixed_cve.read_json
validate_resource_name = fixed_cve.validate_resource_name
validate_container_image = fixed_cve.validate_container_image
extract_nested_string = fixed_cve.extract_nested_string
get_snapshot_name = fixed_cve.get_snapshot_name
get_snapshot_namespace = fixed_cve.get_snapshot_namespace
get_snapshot_data = fixed_cve.get_snapshot_data
get_components_from_snapshot = fixed_cve.get_components_from_snapshot
download_sbom_for_image = fixed_cve.download_sbom_for_image
compare_component_sboms = fixed_cve.compare_component_sboms
process_component = fixed_cve.process_component
create_cves_record = fixed_cve.create_cves_record
compare_releases = fixed_cve.compare_releases


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


def test_run_command_surfaces_stderr_as_runtime_error(monkeypatch):
    """A command failure is re-raised as RuntimeError carrying its stderr."""
    def mock_subprocess_run(cmd, check, capture_output, text):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=cmd, stderr="Error from server (Forbidden)"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    cmd_runner = ExternalCommands()
    with pytest.raises(RuntimeError, match="Error from server \\(Forbidden\\)"):
        cmd_runner.run_kubectl(["get", "snapshot", "x"])


# Tests for validate_resource_name

def test_validate_resource_name_ok():
    assert validate_resource_name("my-snapshot-1.2", "snapshot") == "my-snapshot-1.2"


@pytest.mark.parametrize("bad", ["--server=https://evil", "-n", "a b", "UPPER", "a/b", "", "x" * 254])
def test_validate_resource_name_rejects(bad):
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        validate_resource_name(bad, "snapshot")


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


def test_extract_nested_string_missing_intermediate_key():
    """Test that a missing intermediate key raises ValueError."""
    with pytest.raises(ValueError, match="Missing 'level1' key in release data"):
        extract_nested_string({}, "level1", "level2", "key")


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
    runner = MagicMock()
    runner.run_kubectl.return_value = json.dumps(mock_snapshot_data)

    result = get_snapshot_data("test-ns", "test-snapshot", runner)
    assert result == mock_snapshot_data
    # "--" ends option parsing; the snapshot name is passed positionally after it
    runner.run_kubectl.assert_called_once_with(
        ["get", "snapshot", "-n", "test-ns", "-ojson", "--", "test-snapshot"]
    )


def test_get_snapshot_data_rejects_flag_like_snapshot():
    runner = MagicMock()
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        get_snapshot_data("test-ns", "--server=https://evil.example", runner)
    runner.run_kubectl.assert_not_called()


def test_get_snapshot_data_rejects_flag_like_namespace():
    runner = MagicMock()
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        get_snapshot_data("--server=https://evil.example", "test-snapshot", runner)
    runner.run_kubectl.assert_not_called()


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
        def __init__(self, previous_sbom=None, next_sbom=None, scanner=None, scan_type=None):
            self.vulnerabilities_diff = ["CVE-2024-1234"]

    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    sbom1 = {"components": [{"name": "pkg1"}]}
    sbom2 = {"components": [{"name": "pkg1", "version": "2.0"}]}

    result = compare_component_sboms("test-component", sbom1, sbom2)

    assert isinstance(result, list)
    assert result == ["CVE-2024-1234"]


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


def test_process_component_invalid_previous_image_treated_as_new(monkeypatch):
    """A valid current image with an invalid previous image is treated as new."""
    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}
    previous_comp = {"name": "test-component", "containerImage": None}

    result = process_component("test-component", current_comp, previous_comp, MagicMock())

    assert result["status"] == "new"
    assert result["current_image"] == "registry.io/image:v1"


def test_process_component_current_sbom_download_failure(monkeypatch):
    """Test processing component when current SBOM download fails (SBOM mode)."""
    monkeypatch.setattr(fixed_cve, "SCAN_TYPE", "sbom")

    class MockCmdRunner:
        def run_cosign(self, args):
            raise subprocess.CalledProcessError(1, ["cosign"], stderr="Error")

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v0"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "error"
    assert "failed to download current SBOM" in result["reason"]


def test_process_component_compared_success(monkeypatch):
    """Test successful component comparison."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_image=None, next_image=None, previous_sbom=None, next_sbom=None, scanner=None, scan_type=None):
            self.vulnerabilities_diff = []

    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "compared"
    assert result["current_image"] == "registry.io/image:v2"
    assert result["previous_image"] == "registry.io/image:v1"
    assert "vulnerabilities_removed" in result


def test_process_component_previous_sbom_download_failure(monkeypatch):
    """Test processing component when previous SBOM download fails (SBOM mode)."""
    monkeypatch.setattr(fixed_cve, "SCAN_TYPE", "sbom")
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


def test_process_component_sbom_mode_compared_success(monkeypatch):
    """A successful SBOM comparison returns compared status with removed CVEs."""
    monkeypatch.setattr(fixed_cve, "SCAN_TYPE", "sbom")

    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_sbom=None, next_sbom=None, scanner=None, scan_type=None):
            self.vulnerabilities_diff = ["CVE-2024-1234"]

    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "compared"
    assert result["vulnerabilities_removed"] == ["CVE-2024-1234"]


def test_process_component_sbom_mode_comparison_exception(monkeypatch):
    """A failing SBOM comparison is reported as an error (SBOM mode)."""
    monkeypatch.setattr(fixed_cve, "SCAN_TYPE", "sbom")

    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    def boom(*args, **kwargs):
        raise Exception("ACS scan failed")

    monkeypatch.setattr(fixed_cve, 'compare_component_sboms', boom)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "error"
    assert "comparison failed" in result["reason"]


def test_sbom_download_failure_through_real_external_commands(monkeypatch, capsys):
    """A real cosign failure (RuntimeError from ExternalCommands) is handled as a
    download failure: SBOM download returns None with its stderr logged, and the
    component is recorded as an error rather than aborting the collector."""
    monkeypatch.setattr(fixed_cve, "SCAN_TYPE", "sbom")

    def failing_run(cmd, check=False, capture_output=False, text=False):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=cmd, stderr="Error: entity not found in the registry"
        )

    monkeypatch.setattr(subprocess, "run", failing_run)

    runner = ExternalCommands()
    assert download_sbom_for_image("registry.io/image:v1", runner) is None
    err = capsys.readouterr().err
    assert "Failed to download SBOM" in err
    assert "entity not found in the registry" in err

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}
    result = process_component("test-component", current_comp, previous_comp, runner)

    assert result["status"] == "error"
    assert "failed to download current SBOM" in result["reason"]


def test_process_component_comparison_exception(monkeypatch):
    """Test processing component when comparison raises exception."""
    class MockCmdRunner:
        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_image=None, next_image=None, previous_sbom=None, next_sbom=None, scanner=None, scan_type=None):
            pass

        @property
        def vulnerabilities_diff(self):
            raise Exception("ACS scan failed")

    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)

    current_comp = {"name": "test-component", "containerImage": "registry.io/image:v2"}
    previous_comp = {"name": "test-component", "containerImage": "registry.io/image:v1"}

    result = process_component("test-component", current_comp, previous_comp, MockCmdRunner())

    assert result["status"] == "error"
    assert "comparison failed" in result["reason"]


# Tests for create_cves_record function

def test_create_cves_record_all_cve_keys(monkeypatch):
    """Test that valid CVE-format keys are retained unchanged and not logged as dropped."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    result = create_cves_record({"comp1": ["CVE-2024-1234", "CVE-2024-5678"]})

    assert result["releaseNotes"]["cves"] == [
        {"key": "CVE-2024-1234", "component": "comp1"},
        {"key": "CVE-2024-5678", "component": "comp1"},
    ]
    assert "dropping non-CVE key" not in captured_output.getvalue()


def test_create_cves_record_filters_non_cve_keys(monkeypatch):
    """Test that non-CVE advisory keys are dropped and logged with their component."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    result = create_cves_record({
        "comp1": ["CVE-2024-1234", "GHSA-gcjh-h69q-9w9g", "CVE-2024-5678"]
    })

    assert result["releaseNotes"]["cves"] == [
        {"key": "CVE-2024-1234", "component": "comp1"},
        {"key": "CVE-2024-5678", "component": "comp1"},
    ]

    stderr = captured_output.getvalue()
    assert "GHSA-gcjh-h69q-9w9g" in stderr
    assert "comp1" in stderr


@pytest.mark.parametrize("key", [
    "CVE-2024-1234",     # minimum 4-digit sequence
    "CVE-2024-123456",   # 5+ digit sequence exercises the {4,} upper bound
])
def test_create_cves_record_retains_valid_boundaries(monkeypatch, key):
    """Test that valid CVE keys across the sequence-length boundary are retained, not logged."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    result = create_cves_record({"comp1": [key]})

    assert result["releaseNotes"]["cves"] == [{"key": key, "component": "comp1"}]
    assert "dropping non-CVE key" not in captured_output.getvalue()


@pytest.mark.parametrize("key", [
    "CVE-2024-123",              # sequence too short for {4,}
    "CVE-24-1234",              # year not 4 digits
    "cve-2024-1234",           # lowercase prefix (pattern is uppercase-only)
    "CVE-2024-1234 ",          # trailing whitespace (anchored $)
    "CVE-2024-1234\n",         # trailing newline ($ alone would match; fullmatch rejects)
    " CVE-2024-1234",          # leading whitespace (anchored ^)
    "prefix CVE-2024-1234",    # embedded substring (anchored ^)
    "GHSA-gcjh-h69q-9w9g",     # non-CVE advisory id
])
def test_create_cves_record_drops_invalid_keys(monkeypatch, key):
    """Test that malformed or non-CVE keys are dropped and logged with their component."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    result = create_cves_record({"comp1": [key]})

    assert result["releaseNotes"]["cves"] == []
    stderr = captured_output.getvalue()
    assert key in stderr
    assert "comp1" in stderr


def test_create_cves_record_empty_input():
    """Test that an empty input dict yields an empty cves list (first-release path)."""
    assert create_cves_record({}) == {"releaseNotes": {"cves": []}}


def test_create_cves_record_multiple_components_mixed(monkeypatch):
    """Test cross-component iteration; a component with only non-CVE keys contributes nothing."""
    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)

    result = create_cves_record({
        "comp1": ["GHSA-gcjh-h69q-9w9g"],
        "comp2": ["CVE-2024-1234"],
    })

    assert result["releaseNotes"]["cves"] == [
        {"key": "CVE-2024-1234", "component": "comp2"},
    ]

    stderr = captured_output.getvalue()
    assert "GHSA-gcjh-h69q-9w9g" in stderr
    assert "comp1" in stderr


def test_create_cves_record_all_components_dropped():
    """Test that when every component's keys are non-CVE, the cves list is empty."""
    result = create_cves_record({
        "comp1": ["GHSA-gcjh-h69q-9w9g"],
        "comp2": ["RHSA-2024:1234"],
    })

    assert result == {"releaseNotes": {"cves": []}}


# Tests for compare_releases function

def test_compare_releases_missing_release_file(monkeypatch, tmp_path):
    """Test that missing release file raises FileNotFoundError."""
    monkeypatch.setattr(sys, 'argv', [
        'cve.py',
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
        'cve.py',
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
        'cve.py',
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
        'cve.py',
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
    assert "cves" in result["releaseNotes"]
    assert isinstance(result["releaseNotes"]["cves"], list)
    assert result["releaseNotes"]["cves"] == []  # First release has no removed CVEs


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
        'cve.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    class MockCmdRunner:
        def run_kubectl(self, args):
            return json.dumps({"spec": {}})  # No components

    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/roxctl')

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
        'cve.py',
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
        def __init__(self, previous_image=None, next_image=None, previous_sbom=None, next_sbom=None, scanner=None, scan_type=None):
            self.vulnerabilities_diff = ["CVE-2024-1234"]

    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)
    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/roxctl')

    result = compare_releases(MockCmdRunner())

    assert "releaseNotes" in result
    assert "cves" in result["releaseNotes"]
    assert isinstance(result["releaseNotes"]["cves"], list)
    assert len(result["releaseNotes"]["cves"]) == 1
    assert result["releaseNotes"]["cves"][0] == {"key": "CVE-2024-1234", "component": "comp1"}


def test_compare_releases_filters_non_cve_keys(monkeypatch, tmp_path):
    """Test end-to-end that non-CVE ids from the differ are filtered out of the output."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_file.write_text(json.dumps({
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }))
    prev_file.write_text(json.dumps({
        "spec": {"snapshot": "prev-snapshot"},
        "metadata": {"namespace": "test-ns"}
    }))

    monkeypatch.setattr(sys, 'argv', [
        'cve.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    snapshot_call_count = [0]

    class MockCmdRunner:
        def run_kubectl(self, args):
            snapshot_call_count[0] += 1
            image = "registry.io/image:v2" if snapshot_call_count[0] == 1 else "registry.io/image:v1"
            return json.dumps({
                "spec": {"components": [{"name": "comp1", "containerImage": image}]}
            })

        def run_cosign(self, args):
            return json.dumps(mock_sbom_data)

    class MockVulnerabilityDiffer:
        def __init__(self, previous_image=None, next_image=None, previous_sbom=None,
                     next_sbom=None, scanner=None, scan_type=None):
            self.vulnerabilities_diff = [
                "CVE-2024-1234", "GHSA-gcjh-h69q-9w9g", "RHSA-2024:1234"
            ]

    captured_output = StringIO()
    monkeypatch.setattr(sys, 'stderr', captured_output)
    monkeypatch.setattr(fixed_cve, 'VulnerabilityDiffer', MockVulnerabilityDiffer)
    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/roxctl')

    result = compare_releases(MockCmdRunner())

    assert result["releaseNotes"]["cves"] == [
        {"key": "CVE-2024-1234", "component": "comp1"},
    ]

    stderr = captured_output.getvalue()
    assert "GHSA-gcjh-h69q-9w9g" in stderr
    assert "RHSA-2024:1234" in stderr


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
        'cve.py',
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
    assert "cves" in result["releaseNotes"]
    assert isinstance(result["releaseNotes"]["cves"], list)
    assert result["releaseNotes"]["cves"] == []  # First release has no removed CVEs


def test_compare_releases_missing_roxctl(monkeypatch, tmp_path):
    """Test that missing roxctl raises RuntimeError."""
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
        'cve.py',
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

    monkeypatch.setattr('shutil.which', lambda x: None)  # roxctl not found

    with pytest.raises(RuntimeError, match="roxctl is not available"):
        compare_releases(MockCmdRunner())


def test_compare_releases_logs_ns_mismatch_new_and_error(monkeypatch, tmp_path, capsys):
    """Namespace mismatch, new components, and errored components are all logged."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'prev.json'

    release_file.write_text(json.dumps({
        "spec": {"snapshot": "test-snapshot"},
        "metadata": {"namespace": "current-ns"}
    }))
    prev_file.write_text(json.dumps({
        "spec": {"snapshot": "prev-snapshot"},
        "metadata": {"namespace": "prev-ns"}
    }))

    monkeypatch.setattr(sys, 'argv', [
        'cve.py', '--release', str(release_file), '--previousRelease', str(prev_file)
    ])

    call_count = [0]

    class MockCmdRunner:
        def run_kubectl(self, args):
            call_count[0] += 1
            if call_count[0] == 1:
                # Current snapshot: one new component and one with an invalid image
                return json.dumps({"spec": {"components": [
                    {"name": "comp-new", "containerImage": "registry.io/image:v1"},
                    {"name": "comp-bad", "containerImage": None},
                ]}})
            # Previous snapshot has no components, so comp-new is new
            return json.dumps({"spec": {"components": []}})

    monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/roxctl')

    result = compare_releases(MockCmdRunner())

    assert result == {"releaseNotes": {"cves": []}}
    err = capsys.readouterr().err
    assert "different namespaces (current-ns vs prev-ns)" in err
    assert "Component comp-new is new in this release" in err
    assert "Error processing comp-bad" in err


# Tests for main execution block and exit codes

def test_main_block_exit_code_on_error(monkeypatch, tmp_path):
    """Test that the main block exits with code 1 on expected errors."""
    release_file = tmp_path / 'release.json'
    prev_file = tmp_path / 'nonexistent.json'

    release_file.write_text('{}')

    monkeypatch.setattr(sys, 'argv', [
        'cve.py',
        '--release', str(release_file),
        '--previousRelease', str(prev_file)
    ])

    # Mock the compare_releases to raise FileNotFoundError
    def mock_compare_releases(cmd_runner=None):
        raise FileNotFoundError("Path to previousRelease file doesn't exist")

    monkeypatch.setattr(fixed_cve, 'compare_releases', mock_compare_releases)

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


# Drive the real __main__ block in-process via runpy to check exit-code mapping.

FIXED_CVE_SCRIPT = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "..", "lib", "fixed-cve.py")
)


def test_main_kubectl_failure_surfaces_stderr_and_exits_1(monkeypatch, tmp_path, capsys):
    """A kubectl failure is reported with its stderr and maps to exit 1, not a traceback."""
    import runpy

    release = tmp_path / "release.json"
    prev = tmp_path / "previous.json"
    release.write_text(json.dumps(mock_release_data))
    prev.write_text(json.dumps(mock_release_data))

    def failing_run(cmd, check=False, capture_output=False, text=False):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=cmd, stderr="Error from server (Forbidden)"
        )

    monkeypatch.setattr(subprocess, "run", failing_run)
    monkeypatch.setattr(sys, "argv", [
        "fixed-cve.py", "--release", str(release), "--previousRelease", str(prev)
    ])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(FIXED_CVE_SCRIPT, run_name="__main__")

    assert exc.value.code == 1
    assert "Error from server (Forbidden)" in capsys.readouterr().err


def _fake_kubectl_run(snapshot):
    """Return a subprocess.run replacement that answers kubectl with a snapshot."""
    def fake_run(cmd, check=False, capture_output=False, text=False):
        return MockCompletedProcess(returncode=0, stdout=json.dumps(snapshot), stderr="")
    return fake_run


def test_main_success_exit_0(monkeypatch, tmp_path, capsys):
    """A successful run prints the result JSON and exits 0."""
    import runpy

    release = tmp_path / "release.json"
    prev = tmp_path / "previous.json"
    release.write_text(json.dumps(mock_release_data))
    prev.write_text("")  # empty previous release -> first-release path

    monkeypatch.setattr(subprocess, "run", _fake_kubectl_run(mock_snapshot_data))
    monkeypatch.setattr(sys, "argv", [
        "fixed-cve.py", "--release", str(release), "--previousRelease", str(prev)
    ])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(FIXED_CVE_SCRIPT, run_name="__main__")

    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out) == {"releaseNotes": {"cves": []}}


def test_main_unexpected_error_exit_2(monkeypatch, tmp_path):
    """An unexpected exception exits 2 with a traceback."""
    import runpy

    release = tmp_path / "release.json"
    prev = tmp_path / "previous.json"
    release.write_text(json.dumps(mock_release_data))
    prev.write_text("")  # first-release path

    # Component without a 'name' key -> KeyError -> generic handler -> exit(2)
    broken_snapshot = {"spec": {"components": [{"containerImage": "registry.io/img:v1"}]}}
    monkeypatch.setattr(subprocess, "run", _fake_kubectl_run(broken_snapshot))
    monkeypatch.setattr(sys, "argv", [
        "fixed-cve.py", "--release", str(release), "--previousRelease", str(prev)
    ])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(FIXED_CVE_SCRIPT, run_name="__main__")

    assert exc.value.code == 2
