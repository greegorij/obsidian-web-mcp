"""Git operations for MCP vault writes — auto-commit to keep tracking consistent.

Context (PDCA-014): MCP vault_write/move/delete previously left files in the
working tree without git tracking. vault-sync-vps.timer then aborted on
"untracked files would be overwritten" during pull from GitHub, diverging VPS
state from Mac for hours.

Mac-side hook (~/.claude/hooks/block_mcp_vault_write_from_desktop.py) blocks
MCP writes from Claude Code CLI. But Chat / iPhone / Claude Desktop GUI reach
the MCP server directly and can't be blocked client-side — so the VPS must
auto-commit to keep tracking in sync regardless of caller.

This module is fail-open: any git error is logged but never raises; MCP tool
responses are never blocked by a commit failure. Worst case: a write succeeds
but commit fails → untracked file → manual cleanup needed (same as before the
patch, but now we at least log it).
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Iterable

from . import config

logger = logging.getLogger(__name__)

GIT_TIMEOUT = 10  # seconds per git command


def _run_git(args: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run git command, return (returncode, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"git {args[0]} timed out after {GIT_TIMEOUT}s")
        return -1, "", "timeout"
    except Exception as e:
        logger.error(f"git {args[0]} failed: {e}")
        return -1, "", str(e)


def commit_vault_change(
    paths: Iterable[str],
    operation: str,
    extra_msg: str | None = None,
) -> bool:
    """Stage paths and create a commit. Fail-open (logs errors, never raises).

    Args:
        paths: relative vault paths (as passed to vault_write etc.)
        operation: short label ("write", "move", "delete", "batch_frontmatter")
        extra_msg: optional extra context for commit message body

    Returns:
        True if commit created, or if nothing to commit (both are OK).
        False on git error (state may be inconsistent — see logs).
    """
    vault_path = Path(config.VAULT_PATH).resolve()
    path_list = [p for p in paths if p]
    if not path_list:
        logger.warning(
            f"commit_vault_change called with no paths (operation={operation})"
        )
        return True

    # git add --all handles new files, modifications, and deletions uniformly
    add_code, _, add_err = _run_git(
        ["add", "--all", "--"] + path_list, vault_path
    )
    if add_code != 0:
        logger.error(f"git add failed for {path_list}: {add_err}")
        return False

    # Check if there's anything to commit
    # exit 0 = no staged changes, exit 1 = has staged changes, other = error
    diff_code, _, _ = _run_git(
        ["diff", "--cached", "--quiet"], vault_path
    )
    if diff_code == 0:
        logger.debug(f"no changes to commit for {path_list} ({operation})")
        return True
    elif diff_code != 1:
        logger.warning(f"git diff --cached unexpected exit {diff_code}")

    # Build commit message
    file_summary = ", ".join(path_list[:3])
    if len(path_list) > 3:
        file_summary += f" (+{len(path_list) - 3} more)"
    message = f"mcp: {operation}: {file_summary}"
    if extra_msg:
        message += f"\n\n{extra_msg}"

    commit_code, commit_out, commit_err = _run_git(
        ["commit", "-m", message], vault_path
    )
    if commit_code != 0:
        # Defensive: catch "nothing to commit" even though check above covers it
        combined = (commit_err + commit_out).lower()
        if "nothing to commit" in combined:
            return True
        logger.error(f"git commit failed ({operation}): {commit_err or commit_out}")
        return False

    logger.info(f"MCP auto-commit: {operation} {file_summary}")
    return True
