import importlib
import json
import os
import sys
from collections import namedtuple
from unittest.mock import MagicMock

import pytest

# Mock the diffused module before importing the collector
sys.modules['diffused'] = MagicMock()
sys.modules['diffused.report'] = MagicMock()

# Import module (no hyphen in the name, but keep the importlib pattern for consistency)
cve = importlib.import_module("lib.cve")

ExternalCommands = cve.ExternalCommands
read_json = cve.read_json
validate_resource_name = cve.validate_resource_name
extract_nested_string = cve.extract_nested_string
get_snapshot_name = cve.get_snapshot_name
get_snapshot_namespace = cve.get_snapshot_namespace
get_components_from_snapshot = cve.get_components_from_snapshot
validate_container_image = cve.validate_container_image
scan_component = cve.scan_component
collect = cve.collect


MockCompletedProcess = namedtuple('MockCompletedProcess', ['returncode', 'stdout', 'stderr'])


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

# A trimmed ACS raw_result with a couple of vulnerability entries.
mock_raw_result = {
    "result": {
        "summary": {"CRITICAL": 1, "IMPORTANT": 1},
        "vulnerabilities": [
            {
                "cveId": "CVE-2024-1234",
                "cveSeverity": "IMPORTANT",
                "cveCVSS": 7.5,
                "cveInfo": "https://access.redhat.com/security/cve/CVE-2024-1234",
                "advisoryId": "RHSA-2024:1234",
                "advisoryInfo": "https://access.redhat.com/errata/RHSA-2024:1234",
                "componentName": "some-package",
                "componentVersion": "1.0.0-1.el8",
                "componentFixedVersion": "0:1.0.0-2.el8",
            },
            {
                "cveId": "CVE-2024-5678",
                "cveSeverity": "CRITICAL",
                "cveCVSS": 9.1,
                "cveInfo": "https://access.redhat.com/security/cve/CVE-2024-5678",
                "advisoryId": "",
                "advisoryInfo": "",
                "componentName": "another-package",
                "componentVersion": "2.0.0",
                "componentFixedVersion": "",
            },
        ],
    }
}


# ExternalCommands

def test_run_kubectl_success(monkeypatch):
    def mock_subprocess_run(cmd, check, capture_output, text):
        assert cmd[0] == "kubectl"
        assert cmd[1:] == ["get", "pods"]
        return MockCompletedProcess(returncode=0, stdout='{"items": []}', stderr="")

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)
    assert ExternalCommands().run_kubectl(["get", "pods"]) == '{"items": []}'


def test_run_command_surfaces_stderr_as_runtime_error(monkeypatch):
    import subprocess

    def mock_subprocess_run(cmd, check, capture_output, text):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=cmd, stderr="Error from server (Forbidden)"
        )

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)
    with pytest.raises(RuntimeError, match="Error from server \\(Forbidden\\)"):
        ExternalCommands().run_kubectl(["get", "snapshot", "x"])


# validate_resource_name

def test_validate_resource_name_ok():
    assert validate_resource_name("my-snapshot-1.2", "snapshot") == "my-snapshot-1.2"


@pytest.mark.parametrize("bad", ["--server=https://evil", "-n", "a b", "UPPER", "a/b", "", "x" * 254])
def test_validate_resource_name_rejects(bad):
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        validate_resource_name(bad, "snapshot")


# read_json

def test_read_json_valid(tmp_path):
    f = tmp_path / "data.json"
    f.write_text(json.dumps({"a": 1}))
    assert read_json(str(f)) == {"a": 1}


def test_read_json_invalid(tmp_path):
    f = tmp_path / "data.json"
    f.write_text("not json")
    assert read_json(str(f)) is None


# extract_nested_string / snapshot accessors

def test_get_snapshot_name_and_namespace():
    assert get_snapshot_name(mock_release_data) == "test-snapshot"
    assert get_snapshot_namespace(mock_release_data) == "test-namespace"


def test_extract_nested_string_missing_key():
    with pytest.raises(ValueError):
        extract_nested_string({"spec": {}}, "spec", "snapshot")


def test_extract_nested_string_missing_intermediate_key():
    with pytest.raises(ValueError, match="Missing 'spec' key"):
        extract_nested_string({}, "spec", "snapshot")


def test_extract_nested_string_intermediate_not_dict():
    with pytest.raises(ValueError, match="must be a dictionary"):
        extract_nested_string({"spec": "oops"}, "spec", "snapshot")


def test_extract_nested_string_not_a_string():
    with pytest.raises(ValueError, match="must be a string"):
        extract_nested_string({"spec": {"snapshot": 123}}, "spec", "snapshot")


def test_extract_nested_string_empty():
    with pytest.raises(ValueError, match="cannot be empty"):
        extract_nested_string({"spec": {"snapshot": "  "}}, "spec", "snapshot")


# get_snapshot_data / get_components_from_snapshot

def test_get_snapshot_data_parses_kubectl_output():
    runner = MagicMock()
    runner.run_kubectl.return_value = json.dumps(mock_snapshot_data)
    data = cve.get_snapshot_data("ns", "snap", runner)
    assert data == mock_snapshot_data
    # "--" ends option parsing; the snapshot name is passed positionally after it
    runner.run_kubectl.assert_called_once_with(
        ["get", "snapshot", "-n", "ns", "-ojson", "--", "snap"]
    )


def test_get_snapshot_data_rejects_flag_like_snapshot():
    runner = MagicMock()
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        cve.get_snapshot_data("ns", "--server=https://evil.example", runner)
    runner.run_kubectl.assert_not_called()


def test_get_snapshot_data_rejects_flag_like_namespace():
    runner = MagicMock()
    with pytest.raises(ValueError, match="must be a DNS-1123 name"):
        cve.get_snapshot_data("--server=https://evil.example", "snap", runner)
    runner.run_kubectl.assert_not_called()


def test_get_components_from_snapshot_returns_components():
    runner = MagicMock()
    runner.run_kubectl.return_value = json.dumps(mock_snapshot_data)
    components = get_components_from_snapshot("ns", "snap", runner)
    assert [c["name"] for c in components] == ["component1", "component2"]


def test_get_components_from_snapshot_no_components():
    runner = MagicMock()
    runner.run_kubectl.return_value = json.dumps({"spec": {}})
    assert get_components_from_snapshot("ns", "snap", runner) == []


# validate_container_image

def test_validate_container_image_ok():
    assert validate_container_image("registry.io/img:v1", "comp") == "registry.io/img:v1"


@pytest.mark.parametrize("bad", [None, "", "   ", 123])
def test_validate_container_image_fails_closed(bad):
    with pytest.raises(ValueError):
        validate_container_image(bad, "comp")


# scan_component

def test_scan_component_passes_through_and_tags(monkeypatch):
    report = MagicMock()
    report.raw_result = mock_raw_result
    scan_report = MagicMock(return_value=report)
    monkeypatch.setattr(cve, "ScanReport", scan_report)

    records = scan_component("my-component", "registry.io/img:v1")

    # the scan target/scanner/type must be exactly what we intend to run
    scan_report.assert_called_once_with(
        image="registry.io/img:v1", scanner="acs", scan_type="image"
    )
    assert len(records) == 2
    # original scanner fields are preserved verbatim, plus konfluxComponent is added
    assert records[0]["cveId"] == "CVE-2024-1234"
    assert records[0]["advisoryId"] == "RHSA-2024:1234"
    assert records[0]["konfluxComponent"] == "my-component"
    assert all(r["konfluxComponent"] == "my-component" for r in records)


def test_scan_component_preserves_unexpected_fields(monkeypatch):
    report = MagicMock()
    report.raw_result = {"result": {"vulnerabilities": [{"cveId": "CVE-1", "newAcsField": "x"}]}}
    monkeypatch.setattr(cve, "ScanReport", MagicMock(return_value=report))

    records = scan_component("comp", "img")
    assert records == [{"cveId": "CVE-1", "newAcsField": "x", "konfluxComponent": "comp"}]


def test_scan_component_no_vulnerabilities(monkeypatch):
    # clean / unsupported image: ACS returns a "result" with a summary and no
    # "vulnerabilities" key (real shape observed from a Fedora image scan)
    report = MagicMock()
    report.raw_result = {"result": {"summary": {
        "CRITICAL": 0, "IMPORTANT": 0, "LOW": 0, "MODERATE": 0,
        "TOTAL-COMPONENTS": 0, "TOTAL-VULNERABILITIES": 0,
    }}}
    monkeypatch.setattr(cve, "ScanReport", MagicMock(return_value=report))

    assert scan_component("comp", "img") == []


@pytest.mark.parametrize("raw", [{}, {"result": None}, {"result": "oops"}, {"summary": {}}])
def test_scan_component_fails_closed_on_malformed_result(monkeypatch, raw):
    # a successful (non-None) response that is not a scan report must fail closed,
    # not be reported as a clean image
    report = MagicMock()
    report.raw_result = raw
    monkeypatch.setattr(cve, "ScanReport", MagicMock(return_value=report))

    with pytest.raises(RuntimeError, match="missing 'result' object"):
        scan_component("comp", "img")


def test_scan_component_fails_closed(monkeypatch):
    # ScanReport.raw_result raises on scan failure (e.g. ACS unreachable)
    report = MagicMock()
    type(report).raw_result = property(lambda self: (_ for _ in ()).throw(RuntimeError("ACS unreachable")))
    monkeypatch.setattr(cve, "ScanReport", MagicMock(return_value=report))

    with pytest.raises(RuntimeError, match="ACS unreachable"):
        scan_component("comp", "img")


# collect

def _patch_collect(monkeypatch, argv, release_exists=True, components=None, roxctl=True):
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(cve.os.path, "isfile", lambda p: release_exists)
    monkeypatch.setattr(cve, "read_json", lambda p: mock_release_data)
    monkeypatch.setattr(
        cve, "get_components_from_snapshot",
        lambda ns, name, runner: components if components is not None else mock_snapshot_data["spec"]["components"]
    )
    monkeypatch.setattr(cve.shutil, "which", lambda c: "/usr/bin/roxctl" if roxctl else None)


def test_collect_aggregates_all_components(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "tenant", "--release", "r.json"])

    calls = []

    def fake_scan(name, image):
        calls.append((name, image))
        return [{"cveId": f"CVE-{name}", "konfluxComponent": name}]

    monkeypatch.setattr(cve, "scan_component", fake_scan)

    result = collect(cmd_runner=MagicMock())
    comps = {r["konfluxComponent"] for r in result["cves"]}
    assert comps == {"component1", "component2"}
    assert len(result["cves"]) == 2
    # each component is scanned with its own containerImage
    assert calls == [
        ("component1", "registry.io/image1:v1@sha256:abc123"),
        ("component2", "registry.io/image2:v1@sha256:def456"),
    ]


def test_collect_defaults_cmd_runner(monkeypatch):
    # when no cmd_runner is passed, collect() builds its own ExternalCommands
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json"])
    monkeypatch.setattr(cve, "scan_component", lambda name, image: [])
    built = MagicMock()
    monkeypatch.setattr(cve, "ExternalCommands", MagicMock(return_value=built))

    result = collect()
    assert result == {"cves": []}
    cve.ExternalCommands.assert_called_once_with()


def test_collect_empty_release_file(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json"])
    monkeypatch.setattr(cve, "read_json", lambda p: {})
    with pytest.raises(ValueError, match="Empty release file"):
        collect(cmd_runner=MagicMock())


def test_collect_runs_without_previous_release(monkeypatch):
    # previousRelease is accepted but never read; collection still happens
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json", "--previousRelease", "prev.json"])
    monkeypatch.setattr(cve, "scan_component", lambda name, image: [])

    result = collect(cmd_runner=MagicMock())
    assert result == {"cves": []}


def test_collect_missing_release_file(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "--release", "nope.json"], release_exists=False)
    with pytest.raises(FileNotFoundError):
        collect(cmd_runner=MagicMock())


def test_collect_no_components(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json"], components=[])
    with pytest.raises(ValueError, match="No components"):
        collect(cmd_runner=MagicMock())


def test_collect_roxctl_missing(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json"], roxctl=False)
    with pytest.raises(RuntimeError, match="roxctl"):
        collect(cmd_runner=MagicMock())


def test_collect_fails_closed_on_scan_error(monkeypatch):
    _patch_collect(monkeypatch, ["cve.py", "--release", "r.json"])

    def boom(name, image):
        raise RuntimeError("ACS unreachable")

    monkeypatch.setattr(cve, "scan_component", boom)
    with pytest.raises(RuntimeError, match="ACS unreachable"):
        collect(cmd_runner=MagicMock())


def test_collect_fails_closed_on_missing_image(monkeypatch):
    _patch_collect(
        monkeypatch, ["cve.py", "--release", "r.json"],
        components=[{"name": "component1"}]  # no containerImage
    )
    with pytest.raises(ValueError, match="containerImage"):
        collect(cmd_runner=MagicMock())


# __main__ entry block (executed in-process via runpy to drive the exit codes)

CVE_SCRIPT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib", "cve.py"))


def _fake_kubectl_run(snapshot):
    """Return a subprocess.run replacement that answers kubectl with a snapshot."""
    def fake_run(cmd, check=False, capture_output=False, text=False):
        return MockCompletedProcess(returncode=0, stdout=json.dumps(snapshot), stderr="")
    return fake_run


def _run_main(monkeypatch, argv):
    import runpy
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(CVE_SCRIPT, run_name="__main__")
    return exc.value.code


def test_main_success_exit_0(monkeypatch, tmp_path, capsys):
    release = tmp_path / "release.json"
    release.write_text(json.dumps(mock_release_data))

    monkeypatch.setattr("subprocess.run", _fake_kubectl_run(mock_snapshot_data))
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/roxctl")
    report = MagicMock()
    report.raw_result = mock_raw_result
    sys.modules['diffused.report'].ScanReport = MagicMock(return_value=report)

    code = _run_main(monkeypatch, ["cve.py", "tenant", "--release", str(release)])
    assert code == 0
    # the result is printed to stdout as JSON
    stdout = capsys.readouterr().out
    assert json.loads(stdout)["cves"]


def test_main_expected_error_exit_1(monkeypatch):
    # missing release file -> FileNotFoundError -> exit(1)
    code = _run_main(monkeypatch, ["cve.py", "--release", "/no/such/file.json"])
    assert code == 1


def test_main_unexpected_error_exit_2(monkeypatch, tmp_path):
    release = tmp_path / "release.json"
    release.write_text(json.dumps(mock_release_data))

    # component without a 'name' key -> KeyError -> generic handler -> exit(2)
    broken_snapshot = {"spec": {"components": [{"containerImage": "registry.io/img:v1"}]}}
    monkeypatch.setattr("subprocess.run", _fake_kubectl_run(broken_snapshot))
    monkeypatch.setattr("shutil.which", lambda c: "/usr/bin/roxctl")

    code = _run_main(monkeypatch, ["cve.py", "--release", str(release)])
    assert code == 2
