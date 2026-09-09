import pytest

from lib.git_safety import git_clone_cmd, validate_git_url, validate_revision


@pytest.mark.parametrize("url", [
    "https://github.com/org/repo.git",
    "ssh://git@github.com/org/repo.git",
    "git://github.com/org/repo.git",
])
def test_validate_git_url_accepts_allowed_schemes(url):
    validate_git_url(url)  # must not raise


@pytest.mark.parametrize("url", [
    "",
    "-oProxyCommand=touch /tmp/pwned",
    "--upload-pack=touch /tmp/pwned",
    "ext::sh -c touch /tmp/pwned",
    "file:///etc/passwd",
    "ftp://example.com/repo.git",
    "javascript:alert(1)",
    "just-a-string",
])
def test_validate_git_url_rejects_unsafe_values(url):
    with pytest.raises(ValueError):
        validate_git_url(url)


@pytest.mark.parametrize("revision", [
    "-oProxyCommand=touch /tmp/pwned",
    "--upload-pack=touch /tmp/pwned",
    "",
])
def test_validate_revision_rejects_option_like_values(revision):
    with pytest.raises(ValueError):
        validate_revision(revision)


@pytest.mark.parametrize("revision", ["main", "abc1234", "v1.0.0"])
def test_validate_revision_accepts_normal_refs(revision):
    validate_revision(revision)  # must not raise


def test_git_clone_cmd_uses_separator_and_restricts_protocols():
    cmd = git_clone_cmd("https://example.com/org/repo.git", "/tmp/dest")
    assert cmd[0] == "git"
    assert "protocol.ext.allow=never" in cmd
    assert "protocol.file.allow=never" in cmd
    assert cmd.index("--") < cmd.index("https://example.com/org/repo.git")
    assert cmd[-2:] == ["https://example.com/org/repo.git", "/tmp/dest"]


def test_git_clone_cmd_extra_args_precede_separator():
    cmd = git_clone_cmd("https://example.com/org/repo.git", "/tmp/dest", extra_args=["--depth", "1"])
    assert cmd.index("--depth") < cmd.index("--")
    assert cmd.index("--") < cmd.index("https://example.com/org/repo.git")
