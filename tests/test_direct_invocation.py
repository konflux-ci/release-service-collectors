"""Guards against a regression where collectors could not be run the way
release-service-catalog actually runs them: `python3 "lib/<type>.py" ...`
(see tasks/collectors/run-collectors/run-collectors.yaml in
release-service-catalog). In that mode only this file's own directory is on
sys.path, not the repo root, so a package-qualified `from lib.git_safety
import ...` raises ModuleNotFoundError before argument parsing even starts.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_direct(script, *args):
    return subprocess.run(
        [sys.executable, f"lib/{script}", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_gitlog_cve_runs_directly_without_module_not_found():
    result = _run_direct("gitlog-cve.py", "tenant", "--release", "/tmp/does-not-exist.json",
                          "--previousRelease", "/tmp/does-not-exist-2.json")
    assert "ModuleNotFoundError" not in result.stderr
    assert "doesn't exists" in result.stderr


def test_single_component_cve_runs_directly_without_module_not_found():
    result = _run_direct("single-component-cve.py", "tenant", "--release", "/tmp/does-not-exist.json",
                          "--previousRelease", "/tmp/does-not-exist-2.json")
    assert "ModuleNotFoundError" not in result.stderr
    assert "doesn't exists" in result.stderr


def test_single_component_simplejira_runs_directly_without_module_not_found():
    result = _run_direct("single-component-simplejira.py", "tenant", "--release", "/tmp/does-not-exist.json",
                          "--previousRelease", "/tmp/does-not-exist-2.json",
                          "--jiraProjectKey", "HUM", "--jiraServer", "issues.redhat.com")
    assert "ModuleNotFoundError" not in result.stderr
    assert "doesn't exists" in result.stderr


def test_convertyaml_runs_directly_without_module_not_found():
    result = _run_direct("convertyaml.py", "tenant", "--git", "just-a-string-without-scheme",
                          "--branch", "main", "--path", "a.yaml")
    assert "ModuleNotFoundError" not in result.stderr
    # Reaches our validation logic instead of crashing on import.
    assert "ERROR:" in result.stdout
