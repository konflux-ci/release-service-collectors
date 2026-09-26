import argparse
import json
import os
import tempfile
import yaml
from pathlib import Path
from subprocess import run


"""
python lib/convertyaml.py \
    tenant \
    --git https://gitlab.cee.redhat.com/gnecasov/container-errata-templates.git \
    --branch main \
    --path RHEL/XXXXX.yaml
    --release release.json \
    --previousRelease previous_release.json 
"""


def read_parameters():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument("--git", required=True, help="SSH clone string for a git repository")
    parser.add_argument("--branch", required=True, help="Branch name to be cloned, it can be a branch or a SHA.")
    parser.add_argument(
        "--path",
        required=True,
        help="Path to the file in the git repository hat will be templated, relative to the root of the repository, " +
        "so 'config/' refers to the file 'config/myfile' in the root of the repository. Absolute paths are not allowed.")
    parser.add_argument('-r', '--release', help='Path to current release file. Not used, supported to align the interface.', required=False)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file. Not used, supported to align the interface.', required=False)
    args = vars(parser.parse_args())

    if Path(args['path']).is_absolute():
        print("ERROR: path provided is absolute, it must be relative.")
        exit(1)

    tmpdir = tempfile.mkdtemp()

    git_cmd = ["git", "clone", args['git'], "--branch", args['branch'], "--depth", "1", tmpdir]
    cmd = run(git_cmd, capture_output=True)
    if cmd.returncode != 0:
        stdout = cmd.stdout.decode('utf-8').strip('\n')
        stderr = cmd.stderr.decode('utf-8').strip('\n')
        print("Something went wrong clonning, details below:")
        print(f"Command: '{' '.join(git_cmd)}'")
        print(f"Stdout: '{stdout}'")
        print(f"Stderr: '{stderr}'")
        exit(cmd.returncode)

    # The clone above can place a symlink at (or above) the requested path,
    # so containment has to be checked against what git actually wrote to
    # disk, not against the path as it looked before the clone ran.
    final_path = safe_resolve(tmpdir, args['path'])
    return convert_yaml_to_json(final_path)


def safe_resolve(base_dir, relative_path):
    """Resolve `relative_path` under `base_dir` and reject it if it escapes
    `base_dir`, whether via '..' segments or a symlink (in the final
    component or in any parent directory)."""
    base_real = Path(base_dir).resolve(strict=True)
    candidate = base_real / relative_path

    if candidate.is_symlink():
        print("ERROR: the resulting path is a symlink, which is not allowed.")
        exit(1)

    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        # Covers both a missing file (FileNotFoundError, a subclass of
        # OSError) and a symlink loop (plain OSError/ELOOP), which a
        # cloned repository can equally place on this path.
        print("ERROR: file does not exist or is not a file.")
        exit(1)

    if not resolved.is_relative_to(base_real):
        print("ERROR: the resulting path is not contained within the repository. Do not use '..' to escalate directories.")
        exit(1)

    if not resolved.is_file():
        print("ERROR: file does not exist or is not a file.")
        exit(1)

    return resolved


def convert_yaml_to_json(yaml_file):
    try:
        # O_NOFOLLOW is defense in depth against the final path component
        # being swapped for a symlink between the safe_resolve() check and
        # this open() call.
        fd = os.open(yaml_file, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        print(f"ERROR: unable to open file: {e}")
        exit(1)
    try:
        with os.fdopen(fd, 'r') as yaml_in:
            yaml_data = yaml.safe_load(yaml_in)
        new_data = { "releaseNotes": yaml_data }
        return json.dumps(new_data)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML format: {e}")
        exit(1)


if __name__ == "__main__":
    print(read_parameters())

