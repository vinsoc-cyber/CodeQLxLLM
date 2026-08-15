"""#158: ``--local-path`` must never be silently ignored.

``repos/<lang>/<name>`` is reused only when it already resolves to the
requested ``--local-path``; a symlink to a different target or an unrelated
real directory fails loudly instead of analyzing the wrong tree.
"""

import argparse

import pytest

from vuln_hunter_x.cli.commands import _wire_local_path, cmd_verify


@pytest.fixture()
def workspace(tmp_path):
    repos_dir = tmp_path / "repos"
    src_a = tmp_path / "checkout-a"
    src_b = tmp_path / "checkout-b"
    src_a.mkdir()
    src_b.mkdir()
    return repos_dir, src_a, src_b


def test_creates_symlink_when_absent(workspace):
    repos_dir, src_a, _ = workspace
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None
    link = repos_dir / "python" / "foo"
    assert link.is_symlink()
    assert link.resolve() == src_a.resolve()


def test_reuses_matching_symlink(workspace):
    repos_dir, src_a, _ = workspace
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None
    # Second wiring to the same target is a silent no-op.
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None


def test_errors_on_symlink_to_different_target(workspace):
    repos_dir, src_a, src_b = workspace
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None

    error = _wire_local_path(repos_dir, "python", "foo", src_b.resolve())

    assert error is not None
    assert str(src_a.resolve()) in error and str(src_b.resolve()) in error
    # The stale link is left in place for the user to inspect, not repointed.
    assert (repos_dir / "python" / "foo").resolve() == src_a.resolve()


def test_errors_on_unrelated_real_directory(workspace):
    repos_dir, _, src_b = workspace
    real_dir = repos_dir / "python" / "foo"
    real_dir.mkdir(parents=True)

    error = _wire_local_path(repos_dir, "python", "foo", src_b.resolve())

    assert error is not None
    assert "already exists" in error


def test_reuses_real_directory_that_is_the_requested_source(workspace):
    """Passing --local-path repos/<lang>/<name> itself must not error."""
    repos_dir, _, _ = workspace
    real_dir = repos_dir / "python" / "foo"
    real_dir.mkdir(parents=True)
    assert _wire_local_path(repos_dir, "python", "foo", real_dir.resolve()) is None


def test_repoints_dangling_symlink(workspace, tmp_path):
    repos_dir, src_a, src_b = workspace
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None
    src_a.rmdir()  # the old checkout disappears -> link dangles

    assert _wire_local_path(repos_dir, "python", "foo", src_b.resolve()) is None
    assert (repos_dir / "python" / "foo").resolve() == src_b.resolve()


def test_cmd_verify_fails_loudly_on_mismatched_name(workspace, tmp_path, monkeypatch, capsys):
    """Integration: `verify --local-path B --name foo` after `foo` was wired
    to A must error out instead of silently verifying A (#158)."""
    repos_dir, src_a, src_b = workspace
    monkeypatch.chdir(tmp_path)
    assert _wire_local_path(repos_dir, "python", "foo", src_a.resolve()) is None

    args = argparse.Namespace(
        local_path=src_b,
        lang="python",
        name="foo",
        config=None,
    )
    rc = cmd_verify(args)

    assert rc == 1
    err = capsys.readouterr().err
    assert "Refusing" in err
    # The link still points at the original target.
    assert (repos_dir / "python" / "foo").resolve() == src_a.resolve()
