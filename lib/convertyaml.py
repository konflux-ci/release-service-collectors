import argparse
import json
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
    final_path = (Path(tmpdir) / args['path']).resolve()
    if not final_path.is_relative_to(tmpdir):
        print("ERROR: the resulting path is not contained within the repository. Do not use '..' to escalate directories.")
        exit(1)

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

    if not final_path.exists() or not final_path.is_file():
        print("ERROR: file does not exist or is not a file.")
        exit(1)
    return convert_yaml_to_json(final_path)


def convert_yaml_to_json(yaml_file):
    try:
        with open(yaml_file, 'r') as yaml_in:
            yaml_data = yaml.safe_load(yaml_in)
        new_data = { "releaseNotes": yaml_data }
        return json.dumps(new_data)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML format: {e}")
        exit(1)


if __name__ == "__main__":
    print(read_parameters())

