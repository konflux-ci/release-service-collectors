#!/usr/bin/env python
"""
SBOM Diff Collector for Release Service

This script compares Software Bill of Materials (SBOMs) between consecutive releases
to identify changes in vulnerabilities. It retrieves container images from Kubernetes
snapshots, downloads their SBOMs using cosign, and uses Trivy + diffused-lib to
analyze vulnerability differences.

Usage:
    python lib/sbomdiff.py --release release.json --previousRelease previous_release.json
    python lib/sbomdiff.py tenant --release release.json --previousRelease previous_release.json
    python lib/sbomdiff.py managed --release release.json --previousRelease previous_release.json

Arguments:
    mode                    (Optional) Either 'tenant' or 'managed' (currently has no impact)
    --release, -r          Path to current release JSON file
    --previousRelease, -p  Path to previous release JSON file

Output Format:
    {
        "releaseNotes": {
            "sbomDiff": {
                "component-name": {
                    "status": "compared",  # or "new" or "error"
                    "vulnerabilities_removed": [...],
                    "vulnerabilities_removed_details": [...],
                    "current_image": "registry/image:tag@sha256:...",
                    "previous_image": "registry/image:tag@sha256:..."
                }
            }
        }
    }

Status values:
    - "compared": Successfully compared SBOMs between releases
    - "new": Component is new in this release (no previous version)
    - "error": Failed to process component (see "reason" field)

Dependencies:
    - kubectl: Must be available in PATH and configured with cluster access
    - cosign: Must be available in PATH for downloading SBOMs
    - trivy: Must be pre-installed in the container image
    - diffused-lib: Must be pre-installed in the container image

Example:
    python lib/sbomdiff.py tenant \\
        --release /path/to/current-release.json \\
        --previousRelease /path/to/previous-release.json

Exit Codes:
    0 - Success: SBOM comparison completed successfully
    1 - Expected error: Invalid input, missing files, or known failure conditions
    2 - Unexpected error: Unhandled exception occurred (includes stack trace)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Optional, Dict, Any, List

from diffused.differ import VulnerabilityDiffer  # type: ignore[import-untyped]


def log(message: str) -> None:
    """Log a message to stderr."""
    print(message, file=sys.stderr)


class ExternalCommands:
    """
    Wrapper for external command execution.

    This class encapsulates all external command calls (kubectl, cosign, trivy)
    to make the code testable by allowing these dependencies to be mocked.
    """

    def _run_command(self, command: str, args: List[str]) -> str:
        """Execute external command and return stdout."""
        cmd = [command] + args
        log(f"Running {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout

    def run_kubectl(self, args: List[str]) -> str:
        """Execute kubectl command."""
        return self._run_command("kubectl", args)

    def run_cosign(self, args: List[str]) -> str:
        """Execute cosign command."""
        return self._run_command("cosign", args)


def read_json(file: str) -> Optional[Any]:
    """Read JSON data from a file, or None if empty."""
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None


def validate_container_image(container_image: Any, component_name: str, context: str) -> Optional[Dict[str, str]]:
    """
    Validate a containerImage field and return error information if invalid.

    Args:
        container_image: The containerImage value to validate
        component_name: Name of the component (for logging)
        context: Context string (e.g., "current release", "previous release")

    Returns:
        dict or None: Error dict with status and reason if invalid, None if valid

    Example:
        >>> validate_container_image(None, "my-app", "current release")
        {'status': 'error', 'reason': 'no containerImage in current release'}

        >>> validate_container_image("registry/image:v1", "my-app", "current release")
        None
    """
    if not container_image:
        log(f"WARNING: No containerImage found for component {component_name} in {context}")
        return {
            "status": "error",
            "reason": f"no containerImage in {context}"
        }

    if not isinstance(container_image, str) or not container_image.strip():
        log(f"WARNING: Invalid containerImage for component {component_name} in {context}: {container_image}")
        return {
            "status": "error",
            "reason": "invalid containerImage (must be non-empty string)"
        }

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
    output = cmd_runner.run_kubectl(["get", "snapshot", snapshot, "-n", namespace, "-ojson"])
    log(f"Retrieved snapshot {snapshot} successfully ({len(output)} bytes)")
    return json.loads(output)


def get_components_from_snapshot(namespace: str, snapshot_name: str, cmd_runner: Optional[ExternalCommands] = None) -> List[Dict[str, Any]]:
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


def download_sbom_for_image(container_image: str, cmd_runner: Optional[ExternalCommands] = None) -> Optional[Dict[str, Any]]:
    """
    Download SBOM for a container image using cosign.

    Returns None on failure to allow processing to continue for other components.
    """
    cmd_runner = cmd_runner or ExternalCommands()
    log(f"Downloading SBOM for image: {container_image}")

    try:
        output = cmd_runner.run_cosign(["download", "sbom", container_image])
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        log(f"Failed to download SBOM for {container_image}: {e.stderr or e}")
    except (json.JSONDecodeError, Exception) as e:
        log(f"Failed to process SBOM for {container_image}: {e}")
    return None


def compare_component_sboms(component_name: str, sbom_current: Dict[str, Any], sbom_previous: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two SBOMs using diffused-lib to identify removed vulnerabilities.

    Creates temporary files to store SBOMs, which are automatically cleaned up.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        current_path = os.path.join(tmpdir, 'current_sbom.json')
        previous_path = os.path.join(tmpdir, 'previous_sbom.json')

        with open(current_path, 'w') as f:
            json.dump(sbom_current, f)
        with open(previous_path, 'w') as f:
            json.dump(sbom_previous, f)

        log(f"Comparing SBOMs for component {component_name} using diffused-lib")

        differ = VulnerabilityDiffer(
            previous_sbom=previous_path,
            next_sbom=current_path,
            scanner='trivy'
        )
        differ.scan_sboms()
        differ.diff_vulnerabilities()

        return {
            "vulnerabilities_removed": differ.vulnerabilities_diff,
            "vulnerabilities_removed_details": differ.vulnerabilities_diff_all_info
        }


def process_component(
    comp_name: str,
    current_comp: Dict[str, Any],
    previous_comp: Optional[Dict[str, Any]],
    cmd_runner: ExternalCommands
) -> Dict[str, Any]:
    """
    Process a single component comparison.

    Returns a dict with the comparison result for the component.
    """
    current_image = current_comp.get('containerImage')

    # Validate current containerImage
    validation_error = validate_container_image(current_image, comp_name, "current release")
    if validation_error:
        return validation_error

    log(f"Processing component: {comp_name}")

    # Download SBOM for current component
    current_sbom = download_sbom_for_image(current_image, cmd_runner)
    if not current_sbom:
        log(f"WARNING: Could not download SBOM for current component {comp_name}")
        return {
            "status": "error",
            "reason": "failed to download current SBOM",
            "current_image": current_image
        }

    # Handle new component (no previous version)
    if not previous_comp:
        log(f"Component {comp_name} is new in this release")
        return {"status": "new", "current_image": current_image}

    # Validate and process previous component
    previous_image = previous_comp.get('containerImage')
    validation_error = validate_container_image(previous_image, comp_name, "previous release")
    if validation_error:
        # If previous image is invalid, treat component as new
        return {"status": "new", "current_image": current_image}

    # Download SBOM for previous component
    previous_sbom = download_sbom_for_image(previous_image, cmd_runner)
    if not previous_sbom:
        log(f"WARNING: Could not download SBOM for previous component {comp_name}")
        return {
            "status": "error",
            "reason": "failed to download previous SBOM",
            "current_image": current_image,
            "previous_image": previous_image
        }

    # Compare the two SBOMs
    try:
        diff_result = compare_component_sboms(comp_name, current_sbom, previous_sbom)
        return {
            **diff_result,
            "status": "compared",
            "current_image": current_image,
            "previous_image": previous_image
        }
    except Exception as e:
        log(f"ERROR: Failed to compare SBOMs for component {comp_name}: {e}")
        return {
            "status": "error",
            "reason": f"comparison failed: {str(e)}",
            "current_image": current_image,
            "previous_image": previous_image
        }


def compare_releases(cmd_runner: Optional[ExternalCommands] = None) -> Dict[str, Any]:
    """
    Main function to compare SBOMs between two releases.

    This function:
    1. Parses command-line arguments
    2. Validates input files exist
    3. Retrieves snapshot information from Kubernetes
    4. Downloads SBOMs for all components using cosign
    5. Compares SBOMs using Trivy and diffused-lib
    6. Returns structured results

    Args:
        cmd_runner: ExternalCommands instance for external command execution (defaults to new instance)

    Command-line Arguments:
        mode: Either 'tenant' or 'managed' (currently unused)
        --release, -r: Path to current release JSON file
        --previousRelease, -p: Path to previous release JSON file

    Returns:
        dict: Structured diff results in the format:
            {
                "releaseNotes": {
                    "sbomDiff": {
                        "component-name": {
                            "status": "compared|new|error",
                            "vulnerabilities_removed": [...],  # only if status=="compared"
                            "vulnerabilities_removed_details": [...],  # only if status=="compared"
                            "current_image": "...",
                            "previous_image": "...",  # only if status=="compared" or previous image exists
                            "reason": "..."  # only if status=="error"
                        }
                    }
                }
            }

    Raises:
        FileNotFoundError: If release files don't exist
        ValueError: If release files are invalid or missing required fields
        RuntimeError: If required dependencies cannot be installed
        subprocess.CalledProcessError: If kubectl or cosign commands fail

    Special Cases:
        - If previousRelease is empty, treats all components as new (first release)
        - All components are included in output, even if they fail processing
        - Components are marked with appropriate status:
            * "compared": Successfully compared with previous release
            * "new": Component didn't exist in previous release
            * "error": Failed to process (missing image, download failed, comparison failed)
        - Processing continues for all components even if some fail
    """
    if cmd_runner is None:
        cmd_runner = ExternalCommands()

    parser = argparse.ArgumentParser(description='Compare SBOMs between releases using diffused-lib')
    parser.add_argument(
        "mode",
        nargs='?',
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-r', '--release', help='Path to current release file', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file', required=True)
    args = parser.parse_args()

    # Validate input files exist
    if not os.path.isfile(args.release):
        raise FileNotFoundError(f"Path to release file {args.release} doesn't exist")
    if not os.path.isfile(args.previousRelease):
        raise FileNotFoundError(f"Path to previousRelease file {args.previousRelease} doesn't exist")

    # Read release files
    data_release = read_json(args.release)
    data_prev_release = read_json(args.previousRelease)

    if not data_release:
        raise ValueError(f"Empty release file {args.release}")

    # Get snapshot information from current release
    snapshot_name = get_snapshot_name(data_release)
    snapshot_ns = get_snapshot_namespace(data_release)

    if not data_prev_release:
        log(f"Empty previous release file {args.previousRelease} - this is the first release")
        # Get components from current release and mark them all as new
        current_components = get_components_from_snapshot(snapshot_ns, snapshot_name, cmd_runner)
        component_diffs = {}
        for current_comp in current_components:
            comp_name = current_comp['name']
            component_diffs[comp_name] = process_component(comp_name, current_comp, None, cmd_runner)
        return {"releaseNotes": {"sbomDiff": component_diffs}}

    snapshot_prev_name = get_snapshot_name(data_prev_release)
    snapshot_prev_ns = get_snapshot_namespace(data_prev_release)

    log(f"Current snapshot: {snapshot_name} (namespace: {snapshot_ns})")
    log(f"Previous snapshot: {snapshot_prev_name} (namespace: {snapshot_prev_ns})")

    # Verify both snapshots are in the same namespace for efficiency
    if snapshot_ns != snapshot_prev_ns:
        log(f"WARNING: Current and previous releases are in different namespaces ({snapshot_ns} vs {snapshot_prev_ns})")

    # Get components from both snapshots
    current_components = get_components_from_snapshot(snapshot_ns, snapshot_name, cmd_runner)
    previous_components = get_components_from_snapshot(snapshot_prev_ns, snapshot_prev_name, cmd_runner)

    if not current_components:
        raise ValueError("No components found in current release")

    # Create a map of component name to component data for previous release
    previous_components_map = {comp['name']: comp for comp in previous_components}

    log(f"Found {len(current_components)} components in current release")
    log(f"Found {len(previous_components)} components in previous release")

    # Verify trivy is available
    if not shutil.which("trivy"):
        raise RuntimeError("Trivy is not available. Please ensure it is pre-installed in the container image.")

    # Compare SBOMs for each component
    component_diffs = {}

    for current_comp in current_components:
        comp_name = current_comp['name']
        previous_comp = previous_components_map.get(comp_name)
        component_diffs[comp_name] = process_component(comp_name, current_comp, previous_comp, cmd_runner)

    return {"releaseNotes": {"sbomDiff": component_diffs}}


if __name__ == "__main__":
    try:
        result = compare_releases()
        print(json.dumps(result))
        log("Completed comparing SBOMs")
        exit(0)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log(f"ERROR: {e}")
        exit(1)
    except Exception as e:
        log(f"UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        exit(2)
