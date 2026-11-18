#!/usr/bin/env python
"""
CVE Collector for Release Service

This script scans the container image(s) of the current release with Red Hat
Advanced Cluster Security (RHACS) through diffused-lib. Unlike the fixed-cve
collector, this is not a diff: only the current image is scanned.

The scan is filtered to the Critical/Important CVEs that carry an RHSA advisory,
grouped per RHSA with each RHSA's released_on date fetched from the Red Hat
Security Data API, and emitted as a compact summary. The raw scan never leaves
the collector, so the large per-component vulnerability list is not persisted
anywhere.

Usage:
    python lib/cve.py --release release.json
    python lib/cve.py tenant --release release.json
    python lib/cve.py managed --release release.json

Arguments:
    mode                   (Optional) Either 'tenant' or 'managed' (currently has no impact)
    --release, -r          Path to current release JSON file
    --previousRelease, -p  (Optional) Path to previous release JSON file; accepted
                           for invocation compatibility but ignored (this is a
                           single-image scan, not a diff)

Output Format:
    {
        "rhsa": {
            "CRITICAL": [
                {
                    "advisory": "RHSA-2024:1234",
                    "released_on": "2024-08-03T14:37:22Z",
                    "cves": ["CVE-2024-1234", "CVE-2024-1235"],
                    "components": ["my-component", "other-component"]
                }
            ],
            "IMPORTANT": [ ... ]
        }
    }

    Both buckets ("CRITICAL" and "IMPORTANT") are always present (empty list when
    nothing is found). Each RHSA appears once, in the bucket of the most severe CVE
    severity present for it; CVE ids and Konflux components are deduped and sorted;
    released_on is copied verbatim from the Security Data API.

Notes:
    - Fail-closed: any scan failure (including ACS being unreachable) or a missing
      container image fails the whole collector with a non-zero exit code. A
      release must not pass security gating on an image that could not be scanned.

Dependencies:
    - kubectl: Must be available in PATH and configured with cluster access
    - roxctl: Must be pre-installed in the container image (ACS CLI)
    - diffused-lib: Must be pre-installed in the container image
      (https://pypi.org/project/diffused-lib/)

Example:
    python lib/cve.py tenant --release /path/to/current-release.json

Exit Codes:
    0 - Success: Scan completed successfully
    1 - Expected error: Invalid input, missing files, or known failure conditions
    2 - Unexpected error: Unhandled exception occurred (includes stack trace)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Optional, Dict, Any, List

import requests
from diffused.report import ScanReport  # type: ignore[import-untyped]

# Kubernetes resource names and namespaces are DNS-1123 (sub)domains; anything else is
# rejected so a value like "--server=https://evil" cannot be parsed by kubectl as a flag.
DNS1123_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")

# CVE severities that gate a release; membership is the gating filter, the rank picks the bucket.
SEVERITY_RANK = {"CRITICAL": 2, "IMPORTANT": 1}

# Red Hat Security Data API CSAF index; supports a comma-separated rhsa_ids batch lookup.
CSAF_INDEX_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"

# Exact RHSA id form; RHBA/RHEA/empty advisories do not gate.
RHSA_RE = re.compile(r"^RHSA-\d{4}:\d+$")


def log(message: str) -> None:
    """Log a message to stderr."""
    print(message, file=sys.stderr)


def validate_resource_name(value: str, kind: str) -> str:
    """Validate a kubectl resource name/namespace as a DNS-1123 name.

    Guards against argument injection: a snapshot or namespace that starts with '-'
    would otherwise be parsed by kubectl as a flag (e.g. '--server=...').
    """
    if not value or len(value) > 253 or not DNS1123_NAME.fullmatch(value):
        raise ValueError(f"invalid {kind} {value!r}: must be a DNS-1123 name")
    return value


class ExternalCommands:
    """
    Wrapper for external command execution.

    This class encapsulates all external command calls (kubectl) to make the code
    testable by allowing these dependencies to be mocked.
    """

    def _run_command(self, command: str, args: List[str]) -> str:
        """Execute external command and return stdout.

        On failure, surface the command's stderr (which carries the useful API
        message, e.g. "Error from server (Forbidden)") as a RuntimeError so it is
        logged and maps to the expected-error exit code instead of a bare traceback.
        """
        cmd = [command] + args
        log(f"Running {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            raise RuntimeError(f"{command} failed (exit {e.returncode}): {stderr}") from e
        return result.stdout

    def run_kubectl(self, args: List[str]) -> str:
        """Execute kubectl command."""
        return self._run_command("kubectl", args)


def read_json(file: str) -> Optional[Any]:
    """Read JSON data from a file, or None if empty."""
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None


def extract_nested_string(data: Dict[str, Any], *keys: str) -> str:
    """
    Extract and validate a nested string value from a dictionary.

    Args:
        data: Dictionary to extract from
        *keys: Sequence of keys to traverse (e.g., "spec", "snapshot")

    Returns:
        str: The extracted string value

    Raises:
        ValueError: If keys are missing, intermediate values aren't dicts,
                   final value isn't a string, or string is empty
    """
    current = data
    for i, key in enumerate(keys[:-1]):
        if key not in current:
            raise ValueError(f"Missing '{key}' key in release data")
        current = current[key]
        if not isinstance(current, dict):
            raise ValueError(f"'{key}' must be a dictionary, got {type(current).__name__}")

    final_key = keys[-1]
    if final_key not in current:
        raise ValueError(f"Missing '{final_key}' key")

    value = current[final_key]
    if not isinstance(value, str):
        raise ValueError(f"'{final_key}' must be a string, got {type(value).__name__}")

    if not value.strip():
        raise ValueError(f"'{final_key}' cannot be empty or whitespace")

    return value


def get_snapshot_name(data_release: Dict[str, Any]) -> str:
    """Extract the snapshot name from release data."""
    return extract_nested_string(data_release, "spec", "snapshot")


def get_snapshot_namespace(data_release: Dict[str, Any]) -> str:
    """Extract the namespace from release data."""
    return extract_nested_string(data_release, "metadata", "namespace")


def get_snapshot_data(namespace: str, snapshot: str, cmd_runner: Optional[ExternalCommands] = None) -> Dict[str, Any]:
    """Retrieve snapshot data from Kubernetes using kubectl."""
    cmd_runner = cmd_runner or ExternalCommands()
    validate_resource_name(namespace, "namespace")
    validate_resource_name(snapshot, "snapshot")
    # "--" ends option parsing so the snapshot name can never be read as a flag
    output = cmd_runner.run_kubectl(["get", "snapshot", "-n", namespace, "-ojson", "--", snapshot])
    log(f"Retrieved snapshot {snapshot} successfully ({len(output)} bytes)")
    return json.loads(output)


def get_components_from_snapshot(
    namespace: str, snapshot_name: str, cmd_runner: Optional[ExternalCommands] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve the list of components from a Kubernetes snapshot.

    Args:
        namespace: Kubernetes namespace containing the snapshot
        snapshot_name: Name of the snapshot resource
        cmd_runner: ExternalCommands instance for running kubectl (defaults to new instance)

    Returns:
        list: List of component dictionaries from snapshot.spec.components,
              or empty list if no components found

    Raises:
        subprocess.CalledProcessError: If kubectl command fails
        json.JSONDecodeError: If snapshot data is invalid JSON
    """
    log(f"Retrieving components for snapshot {snapshot_name} in namespace {namespace}")

    snapshot_data = get_snapshot_data(namespace, snapshot_name, cmd_runner)

    if "spec" not in snapshot_data or "components" not in snapshot_data["spec"]:
        log(f"Error: No components found in snapshot {snapshot_name}")
        return []

    return snapshot_data["spec"]["components"]


def validate_container_image(container_image: Any, component_name: str) -> str:
    """
    Validate a component's containerImage and return it.

    Raises:
        ValueError: If the containerImage is missing or not a non-empty string.
                    Fail-closed: a component we cannot scan must not be skipped.
    """
    if not container_image or not isinstance(container_image, str) or not container_image.strip():
        raise ValueError(f"missing or invalid containerImage for component {component_name}")
    return container_image


def scan_component(component_name: str, container_image: str) -> List[Dict[str, Any]]:
    """
    Scan a single component image with ACS and return its vulnerabilities.

    Each returned record is the scanner's vulnerability entry passed through
    verbatim with the owning "konfluxComponent" added, so extra fields the scanner
    may report are preserved for downstream tasks.

    Raises:
        RuntimeError: If the scan fails (e.g. ACS unreachable). Propagated so the
                      collector fails closed.
    """
    log(f"Scanning image for component {component_name} using diffused-lib")

    report = ScanReport(image=container_image, scanner="acs", scan_type="image")
    raw_result = report.raw_result

    # A successful ACS scan always returns a "result" object; a clean or unsupported
    # image still has one (with a summary and no "vulnerabilities" key). Its absence
    # means the response is not a scan report, so fail closed rather than report zero
    # CVEs for an image that was never actually scanned.
    if not isinstance(raw_result.get("result"), dict):
        raise RuntimeError(
            f"unexpected ACS scan result for image {container_image}: missing 'result' object"
        )
    vulnerabilities = raw_result["result"].get("vulnerabilities", [])

    return [{**vulnerability, "konfluxComponent": component_name} for vulnerability in vulnerabilities]


def collect(cmd_runner: Optional[ExternalCommands] = None) -> Dict[str, Any]:
    """
    Scan the current release's component images and collect all vulnerabilities.

    This function:
    1. Parses command-line arguments
    2. Validates the release file exists
    3. Retrieves snapshot components from Kubernetes
    4. Scans each component image with ACS via diffused-lib
    5. Returns all vulnerabilities found, tagged with their Konflux component

    Args:
        cmd_runner: ExternalCommands instance for external command execution (defaults to new instance)

    Returns:
        dict: {"cves": [ { "konfluxComponent": ..., <scanner fields> }, ... ]}

    Raises:
        FileNotFoundError: If the release file doesn't exist
        ValueError: If the release file is invalid or a component cannot be scanned
        RuntimeError: If a scan fails, roxctl is unavailable, or a kubectl command fails
        json.JSONDecodeError: If kubectl returns output that is not valid JSON
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    parser = argparse.ArgumentParser(description='Scan the current release images for CVEs using diffused-lib')
    parser.add_argument(
        "mode",
        nargs='?',
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument(
        '-p', '--previousRelease',
        help='Path to previous release file (accepted for compatibility; ignored)'
    )
    args = parser.parse_args()

    # Validate input file exists
    if not os.path.isfile(args.release):
        raise FileNotFoundError(f"Path to release file {args.release} doesn't exist")

    # Read release file
    data_release = read_json(args.release)
    if not data_release:
        raise ValueError(f"Empty release file {args.release}")

    # Get snapshot information from current release
    snapshot_name = get_snapshot_name(data_release)
    snapshot_ns = get_snapshot_namespace(data_release)
    log(f"Current snapshot: {snapshot_name} (namespace: {snapshot_ns})")

    # Get components from the current snapshot
    current_components = get_components_from_snapshot(snapshot_ns, snapshot_name, cmd_runner)
    if not current_components:
        raise ValueError("No components found in current release")

    log(f"Found {len(current_components)} components in current release")

    # Verify roxctl is available
    if not shutil.which("roxctl"):
        raise RuntimeError("roxctl is not available. Please ensure it is pre-installed in the container image.")

    # Scan each component image and collect all vulnerabilities
    cves: List[Dict[str, Any]] = []
    for component in current_components:
        comp_name = component['name']
        container_image = validate_container_image(component.get('containerImage'), comp_name)
        log(f"Processing component: {comp_name}")
        cves.extend(scan_component(comp_name, container_image))

    return {"cves": cves}


def gating_records(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep the Critical/Important CVE records that reference an RHSA advisory.

    Filtering is per-CVE on the ACS cveSeverity (not the errata severity). The
    advisoryId is normalized (whitespace stripped). Records with an empty, RHBA, or
    RHEA advisory id are ignored (not gating). A record whose advisoryId looks like an
    RHSA but is malformed raises ValueError (fail closed) rather than being silently
    dropped, which could hide a gating advisory.
    """
    records: List[Dict[str, Any]] = []
    for record in cves:
        if record.get("cveSeverity") not in SEVERITY_RANK:
            continue
        advisory = record.get("advisoryId")
        if not isinstance(advisory, str):
            continue
        advisory = advisory.strip()
        if RHSA_RE.match(advisory):
            records.append({**record, "advisoryId": advisory})
        elif advisory.upper().startswith("RHSA"):
            raise ValueError(f"malformed RHSA advisory id: {advisory!r}")
        # Empty / RHBA / RHEA / other non-RHSA ids are intentionally ignored.
    return records


def fetch_errata(rhsas: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Fetch Security Data API index entries for the given RHSAs, keyed by RHSA id.

    One batched, unauthenticated request to the CSAF index. Fails closed: a missing
    RHSA (the API answers 200 with [] or omits the entry) raises RuntimeError naming
    the absent ids, because an absent RHSA means lag or a bug (public RHSA is in the
    index). A transport failure (timeout, connection, or TLS error) is likewise
    surfaced as a RuntimeError so it maps to the expected-error exit code rather than
    a traceback.
    """
    if not rhsas:
        return {}
    unique = sorted(set(rhsas))
    url = f"{CSAF_INDEX_URL}?rhsa_ids={','.join(unique)}"
    try:
        response = requests.get(url, timeout=60)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Security Data API request failed for {url}: {e}") from e
    if response.status_code != 200:
        raise RuntimeError(f"Security Data API returned {response.status_code} for {url}")
    entries = response.json()
    if not isinstance(entries, list):
        raise ValueError(f"unexpected Security Data API response: {str(entries)[:200]}")
    # Index by RHSA id; skip entries without a usable id so a malformed object does not
    # raise KeyError. A gating RHSA that is absent is caught by the missing-id check below.
    by_rhsa = {
        entry["RHSA"]: entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("RHSA"), str) and entry["RHSA"]
    }
    missing = [rhsa for rhsa in unique if rhsa not in by_rhsa]
    if missing:
        raise RuntimeError(f"no Security Data API entry for: {', '.join(missing)}")
    return by_rhsa


def _released_on(entry: Dict[str, Any]) -> str:
    """Return the released_on string from a Security Data API entry, verbatim."""
    value = entry.get("released_on")
    if not isinstance(value, str) or not value:
        raise ValueError(f"{entry.get('RHSA')}: missing released_on")
    return value


def build_rhsa_summary(
    records: List[Dict[str, Any]], errata: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Group gating records by RHSA into the {"rhsa": ...} summary.

    Each RHSA appears once, in the bucket of the most severe cveSeverity present for
    it (CRITICAL if any gating CRITICAL CVE references it, else IMPORTANT). CVE ids
    and Konflux components are deduped and sorted; released_on is copied verbatim from
    the errata entry.
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for record in records:
        advisory = record["advisoryId"]
        rank = SEVERITY_RANK[record["cveSeverity"]]
        entry = grouped.setdefault(advisory, {"rank": rank, "cves": set(), "components": set()})
        entry["rank"] = max(entry["rank"], rank)
        cve_id = record.get("cveId")
        if cve_id:
            entry["cves"].add(cve_id)
        component = record.get("konfluxComponent")
        if component:
            entry["components"].add(component)

    buckets: Dict[str, List[Dict[str, Any]]] = {"CRITICAL": [], "IMPORTANT": []}
    for advisory in sorted(grouped):
        data = grouped[advisory]
        bucket = "CRITICAL" if data["rank"] == SEVERITY_RANK["CRITICAL"] else "IMPORTANT"
        buckets[bucket].append({
            "advisory": advisory,
            "released_on": _released_on(errata[advisory]),
            "cves": sorted(data["cves"]),
            "components": sorted(data["components"]),
        })
    return {"rhsa": buckets}


def summarize(cves: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Filter a raw scan (list of CVE records) into the RHSA summary.

    Keeps Critical/Important-with-RHSA records, fetches each RHSA's released_on from
    the Security Data API, and groups them into
    {"rhsa": {"CRITICAL": [...], "IMPORTANT": [...]}}.
    """
    records = gating_records(cves)
    errata = fetch_errata([record["advisoryId"] for record in records])
    summary = build_rhsa_summary(records, errata)
    log(
        f"Filtered scan: {len(summary['rhsa']['CRITICAL'])} CRITICAL, "
        f"{len(summary['rhsa']['IMPORTANT'])} IMPORTANT RHSAs"
    )
    return summary


if __name__ == "__main__":
    try:
        result = collect()
        summary = summarize(result["cves"])
        print(json.dumps(summary))
        log("Completed scanning release")
        exit(0)
    except (ValueError, FileNotFoundError, RuntimeError, json.JSONDecodeError) as e:
        log(f"ERROR: {e}")
        exit(1)
    except Exception as e:
        log(f"UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        exit(2)
