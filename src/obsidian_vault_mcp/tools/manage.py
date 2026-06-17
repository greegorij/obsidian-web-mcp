"""Management tools for the Obsidian vault MCP server."""

import logging

from ..git_ops import commit_vault_change
from ..vault import delete_path, list_directory, move_path
from . import json_utils as json

logger = logging.getLogger(__name__)


def vault_list(
    path: str = "",
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> str:
    """List directory contents in the vault."""
    try:
        items = list_directory(
            path,
            depth=depth,
            include_files=include_files,
            include_dirs=include_dirs,
            pattern=pattern,
        )
        return json.dumps({"items": items, "total": len(items)})
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_list invalid path: {path}")
        return json.dumps({"error": "Invalid path", "path": path})
    except FileNotFoundError:
        return json.dumps({"error": f"Directory not found: {path}"})
    except Exception:
        logger.exception(f"vault_list unexpected error: {path}")
        return json.dumps({"error": "Internal error listing directory", "path": path})


def vault_move(source: str, destination: str, create_dirs: bool = True) -> str:
    """Move a file or directory within the vault."""
    try:
        moved = move_path(source, destination, create_dirs=create_dirs)
        commit_vault_change([source, destination], "move")
        return json.dumps({"source": source, "destination": destination, "moved": moved})
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_move invalid path: {source} -> {destination}")
        return json.dumps({"error": "Invalid path", "source": source, "destination": destination})
    except Exception:
        logger.exception(f"vault_move unexpected error: {source} -> {destination}")
        return json.dumps({"error": "Internal error moving path", "source": source, "destination": destination})


def vault_delete(path: str, confirm: bool = False) -> str:
    """Delete a file by moving it to .trash/ in the vault."""
    if not confirm:
        return json.dumps(
            {
                "error": "Set confirm=true to execute deletion. Files are moved to .trash/, not hard deleted.",
                "path": path,
            }
        )

    try:
        deleted = delete_path(path)
        commit_vault_change([path], "delete")
        return json.dumps({"path": path, "deleted": deleted})
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_delete invalid path: {path}")
        return json.dumps({"error": "Invalid path", "path": path})
    except Exception:
        logger.exception(f"vault_delete unexpected error: {path}")
        return json.dumps({"error": "Internal error deleting file", "path": path})
