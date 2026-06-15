"""Adapter OAuth dla vault-mcp — cienka warstwa nad reużywalną bramą `mcp_oauth`.

Cała logika OAuth (authorization_code + PKCE) i brama tożsamości Google żyją w
`mcp_oauth.McpOAuthGate` (wendorowana kopia workos_shared — JEDEN mechanizm dla
wszystkich serwerów MCP, kanon GOLDEN-PATTERNS Wzorzec 9). Ten moduł tylko:

1. Buduje instancję bramy z `config` (token, base-url, klient Google, allowlista e-maili).
2. Dokłada fork-owy rate-limit per-IP na publicznych wejściach OAuth (audyt s1099 S77/S81)
   — komponent celowo go nie ma (różne usługi mają różne progi).
3. Eksponuje `oauth_routes` (montowane w server.py) i `OPEN_PATHS` (wyjątek bearer-auth).

Domknięcie K1 (s1286): poprzednia wersja auto-approve'owała (każdy znający URL Funnela
wyciągał master-token). Teraz `/oauth/authorize` deleguje do logowania Google i wydaje kod
tylko zweryfikowanemu e-mailowi z allowlisty. FAIL-CLOSED bez konfiguracji bramy.
"""

import logging
import os
import time

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import config
from .mcp_oauth import McpOAuthGate

logger = logging.getLogger(__name__)

# Allowlist of permitted OAuth redirect URIs (exact match). Bez tego ktokolwiek mógłby
# poprowadzić /oauth/authorize i dostarczyć kod na host atakującego (KRYT, audyt s693).
# Konfigurowalne env (przecinki); domyślnie callback konektora MCP claude.ai.
REDIRECT_ALLOWLIST = frozenset(
    u.strip()
    for u in os.environ.get(
        "VAULT_OAUTH_REDIRECT_ALLOWLIST",
        "https://claude.ai/api/mcp/auth_callback",
    ).split(",")
    if u.strip()
)


def _build_gate() -> McpOAuthGate:
    """Brama z bieżącego configu. Wydzielone, by testy mogły zbudować wariant z bramą."""
    return McpOAuthGate(
        service_name="vault-mcp",
        master_token=config.VAULT_MCP_TOKEN,
        public_base=config.VAULT_MCP_BASE_URL,
        resource_path="/mcp",
        redirect_allowlist=REDIRECT_ALLOWLIST,
        google_client_id=config.VAULT_MCP_GOOGLE_OAUTH_CLIENT_ID,
        google_client_secret=config.VAULT_MCP_GOOGLE_OAUTH_SECRET,
        google_redirect_uri=config.VAULT_MCP_GOOGLE_OAUTH_REDIRECT_URI,
        allowed_emails=config.VAULT_MCP_ALLOWED_EMAILS,
        dev_insecure=config.VAULT_MCP_OAUTH_DEV_INSECURE,
    )


# Instancja modułowa — trasy referują ją DYNAMICZNIE (przez nazwę globalną), więc test
# może podmienić `oauth._GATE` na wariant z włączoną bramą bez przebudowy tras.
_GATE = _build_gate()

# ── rate-limit per-IP publicznych wejść OAuth (audyt s1099 S77/S81) ────────────
_OAUTH_WINDOW_S = 60
_oauth_hits: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    """Realny adres za Funnel/Caddy z X-Forwarded-For (port bindowany na loopback)."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _oauth_rate_limited(request: Request) -> bool:
    """True gdy IP przekroczył limit żądań OAuth w oknie 60 s (S77/S81)."""
    ip = _client_ip(request)
    cutoff = time.time() - _OAUTH_WINDOW_S
    for key in list(_oauth_hits):
        fresh = [t for t in _oauth_hits[key] if t > cutoff]
        if fresh:
            _oauth_hits[key] = fresh
        else:
            del _oauth_hits[key]
    hits = _oauth_hits.setdefault(ip, [])
    hits.append(time.time())
    return len(hits) > config.RATE_LIMIT_OAUTH_PER_MIN


def _rate_limited(handler):
    """Owija publiczne wejście OAuth limitem per-IP. Discovery (metadata/protected) NIE
    limitowane — claude.ai odpytuje je często przy odkrywaniu."""

    async def wrapped(request: Request):
        if _oauth_rate_limited(request):
            return JSONResponse({"error": "rate_limited"}, status_code=429)
        return await handler(request)

    return wrapped


# Wrappery referują `_GATE` dynamicznie (nie wiążą bound-method przy konstrukcji trasy).
async def _metadata(request: Request):
    return await _GATE.metadata(request)


async def _protected_resource(request: Request):
    return await _GATE.protected_resource(request)


async def _authorize(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.authorize(request)


async def _google_callback(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.google_callback(request)


async def _token(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.token(request)


async def _register(request: Request):
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    return await _GATE.register(request)


oauth_routes = [
    Route("/.well-known/oauth-authorization-server", _metadata, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", _protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource/mcp", _protected_resource, methods=["GET"]),
    Route("/oauth/authorize", _authorize, methods=["GET", "POST"]),
    Route("/oauth/google/callback", _google_callback, methods=["GET"]),
    Route("/oauth/token", _token, methods=["POST"]),
    Route("/oauth/register", _register, methods=["POST"]),
]

# Ścieżki zwolnione z bearer-auth (pre-auth flow OAuth + odkrywania). Wyprowadzone z bramy
# — single source, obejmuje /oauth/google/callback (nowy w s1286).
OPEN_PATHS = _GATE.open_paths
