"""Write tools for the Obsidian vault MCP server."""

import logging

import frontmatter

from ..git_ops import commit_vault_change
from ..vault import read_file, resolve_vault_path, write_file_atomic
from . import json_utils as json

logger = logging.getLogger(__name__)


def vault_write(path: str, content: str, create_dirs: bool = True, merge_frontmatter: bool = False) -> str:
    """Write a file to the vault, optionally merging frontmatter with existing content."""
    try:
        resolve_vault_path(path)

        if merge_frontmatter:
            try:
                existing_content, _ = read_file(path)
                existing_post = frontmatter.loads(existing_content)
                new_post = frontmatter.loads(content)

                merged_meta = dict(existing_post.metadata)
                merged_meta.update(new_post.metadata)

                new_post.metadata = merged_meta
                content = frontmatter.dumps(new_post)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Frontmatter merge failed for {path}, writing as-is: {e}")

        is_new, size = write_file_atomic(path, content, create_dirs=create_dirs)

        # PDCA-014 auto-commit: utrzymuje tracking git dla zapisów MCP (łatka git_ops)
        commit_vault_change([path], "write")

        return json.dumps({"path": path, "created": is_new, "size": size})
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_write invalid path/content: {path}")
        return json.dumps({"error": "Invalid path or content", "path": path})
    except Exception:
        logger.exception(f"vault_write unexpected error: {path}")
        return json.dumps({"error": "Internal error writing file", "path": path})


def vault_batch_frontmatter_update(updates: list[dict]) -> str:
    """Update frontmatter fields on multiple files without changing body content."""
    results = []
    updated_paths = []

    for update in updates:
        file_path = update.get("path", "")
        fields = update.get("fields", {})

        try:
            content, _ = read_file(file_path)
            post = frontmatter.loads(content)

            for key, value in fields.items():
                post.metadata[key] = value

            new_content = frontmatter.dumps(post)
            write_file_atomic(file_path, new_content, create_dirs=False)

            results.append({"path": file_path, "updated": True})
            updated_paths.append(file_path)
        except FileNotFoundError:
            results.append({"path": file_path, "updated": False, "error": "File not found"})
        except ValueError:
            # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
            logger.exception(f"batch_frontmatter_update invalid: {file_path}")
            results.append({"path": file_path, "updated": False, "error": "Invalid path or content"})
        except Exception:
            logger.exception(f"batch_frontmatter_update unexpected error: {file_path}")
            results.append({"path": file_path, "updated": False, "error": "Internal error updating frontmatter"})

    # PDCA-014 auto-commit zaktualizowanych plików (łatka git_ops)
    if updated_paths:
        commit_vault_change(updated_paths, "batch_frontmatter")

    return json.dumps({"results": results})
