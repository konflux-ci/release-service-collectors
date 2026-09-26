import json
import pytest
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


def test_safe_resolve_valid_nested_path(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "file.yaml").write_text("key: value\n")

    resolved = convertyaml.safe_resolve(str(tmp_path), "sub/file.yaml")
    assert resolved == (tmp_path / "sub" / "file.yaml").resolve()


def test_safe_resolve_rejects_dotdot_escape(tmp_path):
    outside = tmp_path.parent / "outside-dotdot.yaml"
    outside.write_text("secret: value\n")
    try:
        with pytest.raises(SystemExit):
            convertyaml.safe_resolve(str(tmp_path), "../outside-dotdot.yaml")
    finally:
        outside.unlink()


def test_safe_resolve_rejects_symlinked_file(tmp_path):
    outside = tmp_path.parent / "outside-secret.yaml"
    outside.write_text("secret: value\n")
    (tmp_path / "file.yaml").symlink_to(outside)

    try:
        with pytest.raises(SystemExit):
            convertyaml.safe_resolve(str(tmp_path), "file.yaml")
    finally:
        outside.unlink()


def test_safe_resolve_rejects_symlinked_parent_directory(tmp_path):
    outside_dir = tmp_path.parent / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "file.yaml").write_text("secret: value\n")
    (tmp_path / "sub").symlink_to(outside_dir)

    try:
        with pytest.raises(SystemExit):
            convertyaml.safe_resolve(str(tmp_path), "sub/file.yaml")
    finally:
        (outside_dir / "file.yaml").unlink()
        outside_dir.rmdir()


def test_safe_resolve_rejects_missing_file(tmp_path):
    with pytest.raises(SystemExit):
        convertyaml.safe_resolve(str(tmp_path), "does-not-exist.yaml")


def test_safe_resolve_rejects_symlink_loop(tmp_path):
    # The loop must be in an intermediate directory component: if the
    # final path component were itself a symlink, is_symlink() would
    # reject it earlier without ever reaching resolve()/ELOOP.
    sub = tmp_path / "sub"
    sub2 = tmp_path / "sub2"
    sub.symlink_to(sub2)
    sub2.symlink_to(sub)

    with pytest.raises(SystemExit):
        convertyaml.safe_resolve(str(tmp_path), "sub/file.yaml")


def test_convert_yaml_to_json_rejects_symlink(tmp_path):
    outside = tmp_path.parent / "outside-open.yaml"
    outside.write_text(mock_yaml_content)
    symlink_path = tmp_path / "link.yaml"
    symlink_path.symlink_to(outside)

    try:
        with pytest.raises(SystemExit):
            convertyaml.convert_yaml_to_json(str(symlink_path))
    finally:
        outside.unlink()
