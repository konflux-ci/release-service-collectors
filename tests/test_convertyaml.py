import json
import pytest
import sys
import tempfile
import yaml

from lib import convertyaml


mock_yaml_content = """synopsis: |
  {% if advisory.spec.type == "RHSA" %} RHSA {% endif %}
solution: |
  {% if advisory.spec.type == "RHSA" %} RHSA {% endif %}
description: |
  {{Problem_description}}
"""

expected_mock_json = { "releaseNotes": { "synopsis": 
    "{% if advisory.spec.type == \"RHSA\" %} RHSA {% endif %}\n",
    "solution": "{% if advisory.spec.type == \"RHSA\" %} RHSA {% endif %}\n",
    "description": "{{Problem_description}}\n"}}


def test_yaml_file_to_json_valid(tmp_path):

    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text(mock_yaml_content)  # Write to temp file

    result = convertyaml.convert_yaml_to_json(str(yaml_file))
    assert json.loads(result) == expected_mock_json


def test_yaml_file_to_json_invalid(tmp_path):
    invalid_yaml = """
    synopsis: "title
    solution: 30
    """  # Missing closing quote for "title"

    yaml_file = tmp_path / "invalid.yaml"
    yaml_file.write_text(invalid_yaml)

    with pytest.raises(SystemExit) as exc_info:
        convertyaml.convert_yaml_to_json(str(yaml_file))
        assert exc_info.value.code == 1


@pytest.mark.parametrize("malicious_git", [
    "-oProxyCommand=touch /tmp/pwned",
    "ext::sh -c touch /tmp/pwned",
    "just-a-string-without-scheme",
])
def test_read_parameters_rejects_unsafe_git_url(monkeypatch, malicious_git):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("git clone must not run for an unvalidated URL")

    monkeypatch.setattr(convertyaml, "run", fail_if_called)
    monkeypatch.setattr(sys, "argv", [
        "convertyaml.py", "tenant",
        "--git", malicious_git,
        "--branch", "main",
        "--path", "notes.yaml",
    ])

    with pytest.raises(SystemExit):
        convertyaml.read_parameters()

