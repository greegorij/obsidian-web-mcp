import os
from pathlib import Path

# Vault configuration
VAULT_PATH = Path(os.environ.get("VAULT_PATH", os.path.expanduser("~/Obsidian/MyVault")))
VAULT_MCP_TOKEN = os.environ.get("VAULT_MCP_TOKEN", "")
VAULT_MCP_PORT = int(os.environ.get("VAULT_MCP_PORT", "8420"))
# Bind loopback domyślnie (audyt s1099, secure-coding §5) — dostęp przez Funnel/Caddy.
VAULT_MCP_HOST = os.environ.get("VAULT_MCP_HOST", "127.0.0.1")
# Zaufany publiczny URL bazowy dla metadanych OAuth (audyt s1099, N69) — zamiast
# nagłówka Host żądania (anti-spoofing). Pusty → fallback do request.base_url (dev).
VAULT_MCP_BASE_URL = os.environ.get("VAULT_MCP_BASE_URL", "").rstrip("/")

# Dozwolone nagłówki Host (ochrona DNS-rebinding biblioteki MCP, audyt s1099). Allowlista:
# loopback + nazwy hostów reverse-proxy które realnie kierują ruch na tę usługę. Caddy
# zachowuje oryginalny Host (vault.grzegorzgolas.com), Funnel przekazuje nazwę tailnet —
# OBA muszą tu być, inaczej żądania dostają HTTP 421. Konfigurowalne env (przecinki);
# dopisanie własnej domeny NIE osłabia ochrony (to wciąż allowlista, nie wildcard).
VAULT_MCP_ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "VAULT_MCP_ALLOWED_HOSTS",
        "127.0.0.1:*,localhost:*,[::1]:*,vps-2557.tail301a28.ts.net,vault.grzegorzgolas.com",
    ).split(",")
    if h.strip()
]

# (usunięto VAULT_OAUTH_CLIENT_ID/SECRET — martwe, audyt s1099 N71: /oauth/register to
#  public client PKCE, client_credentials wyłączone, sekret nigdy nie był używany.)

# Safety limits
MAX_CONTENT_SIZE = 1_000_000  # 1MB max write size
MAX_BATCH_SIZE = 20  # Max files per batch operation
MAX_SEARCH_RESULTS = 50  # Max results per search
DEFAULT_SEARCH_RESULTS = 20
MAX_LIST_DEPTH = 5  # Max directory recursion depth
CONTEXT_LINES = 2  # Default lines of context in search results

# Directories to never expose or modify
EXCLUDED_DIRS = {".obsidian", ".trash", ".git", ".DS_Store"}

# Frontmatter index refresh interval (seconds)
FRONTMATTER_INDEX_DEBOUNCE = 5.0

# Rate limiting publicznych endpointów OAuth (audyt s1099, S77/S81) — per-IP w oknie
# czasu, in-memory. Per-token limit nieosiągalny (jeden statyczny token), więc
# ograniczamy najbardziej narażoną powierzchnię: publiczne wejścia OAuth na Funnelu.
RATE_LIMIT_OAUTH_PER_MIN = int(os.environ.get("VAULT_MCP_OAUTH_RATELIMIT", "20"))
