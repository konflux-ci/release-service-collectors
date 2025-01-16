import tempfile
from pathlib import Path
from subprocess import run

import pytest

from lib import template

@pytest.fixture(scope="module")
def git_repository():
    git_folder = tempfile.mkdtemp()
    (Path(git_folder) / "README.md").write_text("# Hello")
    (Path(git_folder) / "template.json").write_text('{"message": "{ENV_VAR}"}')

    run(["git", "init", git_folder, "--initial-branch", "main"], check=True)
    run(["git", "-C", git_folder, "add", "."], check=True)
    run(["git", "-C", git_folder, "commit", "-m", "Initial commit"], check=True)

    return git_folder

def test_error_path_outside_repository(git_repository):
    with pytest.raises(SystemExit):
        template.main([
            "tenant",
            "--git", git_repository,
            "--branch", "main",
            "--path", "../LICENSE",
        ])

def test_error_absolute(git_repository):
    with pytest.raises(SystemExit):
        template.main([
            "managed",
            "--git", git_repository,
            "--branch", "main",
            "--path", "/LICENSE",
        ])

def test_correct(capsys, git_repository):
    template.main([
        "managed",
        "--git", git_repository,
        "--branch", "main",
        "--path", "README.md",
    ])

    captured = capsys.readouterr()
    assert "# Hello" in captured.out

def test_error_key_templating(git_repository):
    with pytest.raises(SystemExit):
        template.main([
            "managed",
            "--git", git_repository,
            "--branch", "main",
            "--path", "template.json",
        ])

def test_correct_key_templating(monkeypatch, capsys, git_repository):
    monkeypatch.setenv("ENV_VAR", "Template me please")
    template.main([
        "managed",
        "--git", git_repository,
        "--branch", "main",
        "--path", "template.json",
    ])

    captured = capsys.readouterr()
    assert "Template me please" in captured.out

def test_error_non_existent_file(git_repository):
    with pytest.raises(SystemExit):
        template.main([
            "tenant",
            "--git", git_repository,
            "--branch", "main",
            "--path", "NON_EXISTENT",
        ])

def test_error_non_existent_repository():
    with pytest.raises(SystemExit):
        template.main([
            "managed",
            "--git", "/tmp/non-existent-repository",
            "--branch", "main",
            "--path", "LICENSE",
        ])

def test_error_non_existing_branch(git_repository):
    with pytest.raises(SystemExit):
        template.main([
            "tenant",
            "--git", git_repository,
            "--branch", "non-existent",
            "--path", "LICENSE",
        ])
