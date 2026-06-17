"""Read tools for the Obsidian vault MCP server."""

import logging

import frontmatter

from ..vault import read_file
from . import json_utils as json

logger = logging.getLogger(__name__)


def vault_read(path: str) -> str:
    """Read a file from the vault, returning content, metadata, and parsed frontmatter."""
    try:
        content, metadata = read_file(path)

        fm_data = None
        try:
            post = frontmatter.loads(content)
            if post.metadata:
                fm_data = post.metadata
        except Exception:  # noqa: S110  # brak/uszkodzony frontmatter jest dozwolony — fm_data zostaje None
            pass

        return json.dumps(
            {
                "path": path,
                "content": content,
                "metadata": metadata,
                "frontmatter": fm_data,
            }
        )
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny w logach serwisu.
        logger.exception(f"vault_read invalid content: {path}")
        return json.dumps({"error": "Invalid file content", "path": path})
    except FileNotFoundError:
        return json.dumps({"error": "File not found", "path": path})
    except Exception:
        logger.exception(f"vault_read unexpected error: {path}")
        return json.dumps({"error": "Internal error reading file", "path": path})


def vault_batch_read(paths: list[str], include_content: bool = True) -> str:
    """Read multiple files from the vault in one call."""
    results = []
    found = 0
    missing = 0

    for path in paths:
        try:
            content, metadata = read_file(path)

            fm_data = None
            try:
                post = frontmatter.loads(content)
                if post.metadata:
                    fm_data = post.metadata
            except Exception:  # noqa: S110  # brak/uszkodzony frontmatter jest dozwolony — fm_data zostaje None
                pass

            entry = {
                "path": path,
                "metadata": metadata,
                "frontmatter": fm_data,
            }
            if include_content:
                entry["content"] = content

            results.append(entry)
            found += 1
        except (ValueError, FileNotFoundError):
            # Generyczny komunikat do klienta (audyt s1099, S78).
            results.append({"path": path, "error": "Not found or invalid"})
            missing += 1
        except Exception:
            logger.exception(f"vault_batch_read unexpected error: {path}")
            results.append({"path": path, "error": "Internal error reading file"})
            missing += 1

    return json.dumps({"files": results, "found": found, "missing": missing})
