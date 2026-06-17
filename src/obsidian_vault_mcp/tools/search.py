"""Search tools for the Obsidian vault MCP server."""

import logging
import shutil
import subprocess
from pathlib import Path

import frontmatter

from .. import config
from ..vault import resolve_vault_path
from . import json_utils as json

logger = logging.getLogger(__name__)


def _search_ripgrep(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Search using ripgrep for performance."""
    cmd = [
        "rg",
        "--json",
        f"--max-count={max_results}",
        f"--glob={file_pattern}",
        "-i",
        f"--context={context_lines}",
    ]

    for excluded in config.EXCLUDED_DIRS:
        cmd.append(f"--glob=!{excluded}/")

    # S53 (audyt s1099): `--` kończy opcje rg — query/ścieżka są pozycyjne nawet gdy query
    # zaczyna się od `-`. Bez tego query typu `--pre=<cmd>` byłby interpretowany jako flaga
    # ripgrepa (m.in. `--pre` = uruchomienie preprocesora → RCE). Wykluczenia (--glob=!) muszą
    # zostać PRZED `--`, dlatego budujemy flagi najpierw, a pozycyjne dokładamy po separatorze.
    cmd += ["--", query, str(search_path)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    matches = []

    for line in result.stdout.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if data.get("type") == "match":
            match_data = data["data"]
            file_path = match_data["path"]["text"]
            try:
                rel_path = str(Path(file_path).relative_to(config.VAULT_PATH))
            except ValueError:
                continue

            line_number = match_data["line_number"]
            line_text = match_data["lines"]["text"].rstrip("\n")

            matches.append(
                {
                    "path": rel_path,
                    "line_number": line_number,
                    "match_context": line_text,
                }
            )

            if len(matches) >= max_results:
                break

    return matches


def _search_python(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Fallback Python-based search."""
    import fnmatch

    query_lower = query.lower()
    matches = []

    for file_path in search_path.rglob("*"):
        if not file_path.is_file():
            continue

        if any(part in config.EXCLUDED_DIRS for part in file_path.parts):
            continue

        if not fnmatch.fnmatch(file_path.name, file_pattern):
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        lines = content.splitlines()
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = "\n".join(lines[start:end])

                try:
                    rel_path = str(file_path.relative_to(config.VAULT_PATH))
                except ValueError:
                    continue

                matches.append(
                    {
                        "path": rel_path,
                        "line_number": i + 1,
                        "match_context": context,
                    }
                )

                if len(matches) >= max_results:
                    return matches

    return matches


def _get_frontmatter_excerpt(file_path: Path, max_keys: int = 3) -> dict | None:
    """Read frontmatter from a file, returning first N key-value pairs."""
    try:
        content = file_path.read_text(encoding="utf-8")
        post = frontmatter.loads(content)
        if not post.metadata:
            return None
        keys = list(post.metadata.keys())[:max_keys]
        return {k: post.metadata[k] for k in keys}
    except Exception:
        return None


def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search for text across vault files."""
    try:
        if path_prefix:
            search_path = resolve_vault_path(path_prefix)
        else:
            search_path = config.VAULT_PATH

        if not search_path.is_dir():
            return json.dumps({"error": f"Search path is not a directory: {path_prefix}"})

        if shutil.which("rg"):
            matches = _search_ripgrep(query, search_path, file_pattern, max_results, context_lines)
        else:
            matches = _search_python(query, search_path, file_pattern, max_results, context_lines)

        for match in matches:
            file_full_path = config.VAULT_PATH / match["path"]
            match["frontmatter_excerpt"] = _get_frontmatter_excerpt(file_full_path)

        truncated = len(matches) >= max_results

        return json.dumps(
            {
                "results": matches,
                "total_matches": len(matches),
                "truncated": truncated,
            }
        )
    except ValueError:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_search invalid argument (path_prefix={path_prefix!r})")
        return json.dumps({"error": "Invalid search path"})
    except Exception:
        logger.exception(f"vault_search unexpected error (query={query!r})")
        return json.dumps({"error": "Internal error during search"})


def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: str = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
) -> str:
    """Search vault files by frontmatter field values using the in-memory index."""
    from ..server import frontmatter_index

    try:
        results = frontmatter_index.search_by_field(
            field=field,
            value=value,
            match_type=match_type,
            path_prefix=path_prefix,
        )

        formatted = []
        for item in results[:max_results]:
            path = item["path"]
            fm = item["frontmatter"]
            title = fm.get("title", Path(path).stem)
            formatted.append(
                {
                    "path": path,
                    "frontmatter": fm,
                    "title": title,
                }
            )

        truncated = len(results) > max_results

        return json.dumps(
            {
                "results": formatted,
                "total": len(formatted),
                "truncated": truncated,
            }
        )
    except Exception:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception(f"vault_search_frontmatter unexpected error (field={field!r})")
        return json.dumps({"error": "Internal error during search"})
