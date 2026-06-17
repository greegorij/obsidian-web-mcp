"""Obsidian Vault MCP Server.

Exposes read/write access to an Obsidian vault over Streamable HTTP.
Designed to run behind Cloudflare Tunnel for secure remote access.
"""

import json as _json
import logging
import os
import sys
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import MutableHeaders

from .auth import BearerAuthMiddleware
from .config import (
    VAULT_MCP_ALLOWED_HOSTS,
    VAULT_MCP_HOST,
    VAULT_MCP_PORT,
    VAULT_MCP_TOKEN,
    VAULT_PATH,
)
from .frontmatter_index import FrontmatterIndex
from .models import (
    VaultBatchFrontmatterUpdateInput,
    VaultBatchReadInput,
    VaultDeleteInput,
    VaultListInput,
    VaultMoveInput,
    VaultReadInput,
    VaultSearchFrontmatterInput,
    VaultSearchInput,
    VaultWriteInput,
)
from .oauth import oauth_routes
from .tools.manage import vault_delete as _vault_delete
from .tools.manage import vault_list as _vault_list
from .tools.manage import vault_move as _vault_move
from .tools.read import vault_batch_read as _vault_batch_read
from .tools.read import vault_read as _vault_read
from .tools.search import vault_search as _vault_search
from .tools.search import vault_search_frontmatter as _vault_search_frontmatter
from .tools.write import vault_batch_frontmatter_update as _vault_batch_frontmatter_update
from .tools.write import vault_write as _vault_write

logger = logging.getLogger(__name__)

# Global frontmatter index — initialized once at import, not per-request.
# With stateless_http=True, lifespan runs per session. Building the index
# there caused 17s cold starts on every MCP request. Now the index lives
# at module level: built once, watched by watchdog, shared across sessions.
frontmatter_index = FrontmatterIndex()
_index_started = False
# N72 (audyt s1099): check-then-act na fladze globalnej NIE jest „thread-safe via GIL"
# (poprzedni komentarz wprowadzał w błąd) — między sprawdzeniem `if not _index_started`
# a ustawieniem True inny wątek mógłby wejść i podwójnie wystartować indeks. Lock domyka
# to do prawdziwej idempotencji (kontencja tylko na zimnym starcie).
_index_lock = threading.Lock()


def _ensure_index() -> None:
    """Start the index exactly once (idempotentne, strzeżone lockiem)."""
    global _index_started
    with _index_lock:
        if _index_started:
            return
        logger.info(f"Starting vault MCP server. Vault: {VAULT_PATH}")
        frontmatter_index.start()
        logger.info(f"Frontmatter index built: {frontmatter_index.file_count} files indexed")
        _index_started = True


@asynccontextmanager
async def lifespan(server) -> AsyncIterator[dict]:
    """Ensure index is ready; yield it to the session."""
    _ensure_index()
    yield {"frontmatter_index": frontmatter_index}


# Create the MCP server
mcp = FastMCP(
    "obsidian_web_mcp",
    stateless_http=True,
    json_response=True,
    lifespan=lifespan,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        # Allowlista hostów reverse-proxy (loopback + Funnel + Caddy) — patrz config.
        allowed_hosts=VAULT_MCP_ALLOWED_HOSTS,
    ),
)


# --- Register all tools ---


@mcp.tool(
    name="vault_read",
    description="Read a file from the Obsidian vault, returning content, metadata, and parsed YAML frontmatter.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_read(path: str) -> str:
    """Read a file from the vault."""
    inp = VaultReadInput(path=path)
    return _vault_read(inp.path)


@mcp.tool(
    name="vault_batch_read",
    description="Read multiple files from the vault in one call. Handles missing files gracefully.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_read(paths: list[str], include_content: bool = True) -> str:
    """Read multiple files at once."""
    inp = VaultBatchReadInput(paths=paths, include_content=include_content)
    return _vault_batch_read(inp.paths, inp.include_content)


@mcp.tool(
    name="vault_write",
    description="Write a file to the Obsidian vault. Supports frontmatter merging with existing files. Creates parent directories by default.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_write(path: str, content: str, create_dirs: bool = True, merge_frontmatter: bool = False) -> str:
    """Write a file to the vault."""
    inp = VaultWriteInput(path=path, content=content, create_dirs=create_dirs, merge_frontmatter=merge_frontmatter)
    return _vault_write(inp.path, inp.content, inp.create_dirs, inp.merge_frontmatter)


@mcp.tool(
    name="vault_batch_frontmatter_update",
    description="Update YAML frontmatter fields on multiple files without changing body content. Each update merges new fields into existing frontmatter.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_frontmatter_update(updates: list[dict]) -> str:
    """Batch update frontmatter fields."""
    inp = VaultBatchFrontmatterUpdateInput(updates=updates)
    return _vault_batch_frontmatter_update(inp.updates)


@mcp.tool(
    name="vault_search",
    description="Search for text across vault files. Uses ripgrep if available, falls back to Python. Returns matching lines with context and frontmatter excerpts.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search vault file contents."""
    inp = VaultSearchInput(
        query=query,
        path_prefix=path_prefix,
        file_pattern=file_pattern,
        max_results=max_results,
        context_lines=context_lines,
    )
    return _vault_search(inp.query, inp.path_prefix, inp.file_pattern, inp.max_results, inp.context_lines)


@mcp.tool(
    name="vault_search_frontmatter",
    description="Search vault files by YAML frontmatter field values. Queries an in-memory index for fast results. Supports exact match, contains, and field-exists queries.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: str = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
) -> str:
    """Search by frontmatter fields."""
    inp = VaultSearchFrontmatterInput(
        field=field, value=value, match_type=match_type, path_prefix=path_prefix, max_results=max_results
    )
    return _vault_search_frontmatter(inp.field, inp.value, inp.match_type, inp.path_prefix, inp.max_results)


@mcp.tool(
    name="vault_list",
    description="List directory contents in the vault. Supports recursion depth, file/dir filtering, and glob patterns. Excludes .obsidian, .trash, .git directories.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_list(
    path: str = "",
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> str:
    """List vault directory contents."""
    inp = VaultListInput(
        path=path, depth=depth, include_files=include_files, include_dirs=include_dirs, pattern=pattern
    )
    return _vault_list(inp.path, inp.depth, inp.include_files, inp.include_dirs, inp.pattern)


@mcp.tool(
    name="vault_move",
    description="Move a file or directory within the vault. Validates both source and destination paths.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_move(source: str, destination: str, create_dirs: bool = True) -> str:
    """Move a file or directory."""
    inp = VaultMoveInput(source=source, destination=destination, create_dirs=create_dirs)
    return _vault_move(inp.source, inp.destination, inp.create_dirs)


@mcp.tool(
    name="vault_delete",
    description="Delete a file by moving it to .trash/ in the vault root. Requires confirm=true as a safety gate. Does NOT hard delete.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_delete(path: str, confirm: bool = False) -> str:
    """Delete a file (move to .trash/)."""
    inp = VaultDeleteInput(path=path, confirm=confirm)
    return _vault_delete(inp.path, inp.confirm)


# --- RAG search tool (proxied to jarvis-rag on localhost:8765) ---

_RAG_URL = os.environ.get("RAG_INTERNAL_URL", "http://127.0.0.1:8765")
_RAG_TOKEN = os.environ.get("RAG_TOKEN", "")


@mcp.tool(
    name="rag_search",
    description="Search across all indexed documents (Obsidian vault, Google Drive files, meeting transcripts). "
    "Returns the most relevant chunks with source info. "
    "Use for questions like 'where is the SLK contract?', 'what did we decide about pricing?', "
    "'find Borycka contact details'. Query in Polish or English.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def rag_search(query: str, n_results: int = 5, source_type: str | None = None) -> str:
    """Search RAG index via internal HTTP call to jarvis-rag."""
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{_RAG_URL}/mcp",
                headers={
                    "Authorization": f"Bearer {_RAG_TOKEN}",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "rag_search",
                        "arguments": {
                            "query": query,
                            "n_results": n_results,
                            **({"source_type": source_type} if source_type else {}),
                        },
                    },
                    "id": 1,
                },
            )

            if resp.status_code != 200:
                return f"RAG search error: HTTP {resp.status_code}"

            # Parse SSE response (FastMCP returns event stream)
            text = resp.text
            for line in text.split("\n"):
                if line.startswith("data: "):
                    data = _json.loads(line[6:])
                    if "result" in data:
                        content = data["result"].get("content", [])
                        if content:
                            return content[0].get("text", "No results")
                    if "error" in data:
                        return f"RAG error: {data['error'].get('message', 'unknown')}"

            return "RAG search: no response parsed"
    except Exception:
        # Komunikat generyczny do klienta (audyt s1099, S78) — pełny kontekst w logach serwisu.
        logger.exception("rag_search failed")
        return "Internal error during RAG search"


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware — nagłówki bezpieczeństwa na każdej odpowiedzi (audyt s1099,
    N70, GOLDEN-PATTERNS Wzorzec 8). vault_mcp zwraca JSON/MCP, więc bez CSP."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Strict-Transport-Security", "max-age=31536000")
            await send(message)

        await self.app(scope, receive, send_with_headers)


def main() -> None:
    """Entry point. Run with streamable HTTP transport."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not VAULT_PATH.is_dir():
        logger.error(f"Vault path does not exist: {VAULT_PATH}")
        sys.exit(1)

    # Fail-closed (audyt s1099, S79): bez tokenu NIE startujemy. Wcześniej awaryjna
    # gałąź uruchamiała mcp.run() BEZ auth na publicznym Funnelu — krytyczna furtka.
    if not VAULT_MCP_TOKEN:
        raise RuntimeError(
            "VAULT_MCP_TOKEN is not set — refusing to start without bearer auth "
            "(fail-closed, audyt s1099 S79). Niezautentykowany dostęp do vaulta jest zbyt "
            "niebezpieczny. Ustaw VAULT_MCP_TOKEN w EnvironmentFile."
        )

    app = mcp.streamable_http_app()

    # Mount OAuth routes (excluded from bearer auth via the middleware)
    for route in oauth_routes:
        app.routes.insert(0, route)

    app.add_middleware(BearerAuthMiddleware)
    # Nagłówki bezpieczeństwa na każdej odpowiedzi (audyt s1099, N70, Wzorzec 8) —
    # dodane ostatnie = najbardziej zewnętrzne (obejmują też 401/błędy bramki).
    app.add_middleware(SecurityHeadersMiddleware)
    logger.info(f"Starting server on {VAULT_MCP_HOST}:{VAULT_MCP_PORT} with bearer auth + OAuth")

    uvicorn.run(
        app,
        host=VAULT_MCP_HOST,
        port=VAULT_MCP_PORT,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


if __name__ == "__main__":
    main()
