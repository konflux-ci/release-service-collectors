"""Shared safeguards against git argument injection (FIND-001).

Collector scripts build `git clone`/`git log`/`git show` argv from
tenant-controlled values (Snapshot component `source.git.url`/`revision`,
or collector CLI parameters). A value starting with `-` is parsed by git as
an option instead of a positional argument, and schemes such as `ext::` or
`file::` let git's remote helpers execute arbitrary programs or read
arbitrary local paths. Every caller-supplied value must be validated with
`validate_git_url` before it reaches a git argv, and clone/log/show
invocations must use the sentinels below.
"""

from urllib.parse import urlparse

ALLOWED_GIT_URL_SCHEMES = {"https", "ssh", "git"}

# Disables git's `ext::`/`file::` remote helpers so a validated URL still
# can't be abused to spawn a process or read an arbitrary local path.
RESTRICTED_PROTOCOL_ARGS = [
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
]


def validate_git_url(git_url):
    """Raise ValueError unless git_url is an explicit https/ssh/git URL with a host.

    Call this on every tenant-controlled URL *before* it is used to derive
    any other value (e.g. an SSH clone string rewritten from it), since
    downstream code trusts that the netloc/path came from a safe URL.
    """
    if not git_url or git_url.startswith("-"):
        raise ValueError(f"invalid git URL: {git_url!r}")
    parts = urlparse(git_url)
    if parts.scheme not in ALLOWED_GIT_URL_SCHEMES or not parts.netloc:
        raise ValueError(
            f"git URL must use one of {sorted(ALLOWED_GIT_URL_SCHEMES)} scheme with a host: {git_url!r}"
        )


def git_clone_cmd(clone_url, dest, extra_args=None):
    """Build a `git clone` argv, restricting protocol helpers and using `--`
    so clone_url can never be parsed as an option by git.

    clone_url must already be derived from a URL that passed
    `validate_git_url` (either that URL itself, or a value rewritten from
    its validated netloc/path, e.g. an scp-like SSH clone string).
    """
    cmd = ["git", *RESTRICTED_PROTOCOL_ARGS, "clone"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["--", clone_url, dest])
    return cmd


def validate_revision(revision, label="revision"):
    """Raise ValueError if revision looks like a git option rather than a ref/SHA.

    `git log`/`git show` parse a leading `-` as an option regardless of a
    preceding `--`/`--end-of-options` marker (git rejects those revisions
    outright rather than treating them as positionals), so option-like
    revisions must be rejected before they reach the argv.
    """
    if not revision or revision.startswith("-"):
        raise ValueError(f"invalid {label}: {revision!r}")
