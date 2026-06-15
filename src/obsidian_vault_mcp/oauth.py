"""OAuth 2.0 authorization code flow with PKCE for Claude app MCP integration.

Claude's MCP connector uses the full OAuth authorization code flow:
1. Discovers metadata at /.well-known/oauth-authorization-server
2. Dynamically registers at /oauth/register
3. Redirects user's browser to /oauth/authorize
4. Server auto-approves (single-user) and redirects back with an auth code
5. Claude exchanges the code at /oauth/token for a bearer token
6. Claude uses the bearer token on all MCP requests

Single-user personal server: the authorization page auto-approves immediately.

Security hardening (audyt s693, KRYT — same class as jarvis_rag KRYT-1; this module
is the original the RAG OAuth was adapted from):
  1. redirect_uri allowlist — codes only go to a registered callback.
  2. PKCE mandatory — no downgrade; authorize requires S256 challenge, token always verifies.
  3. client_credentials grant removed — it minted the master token for any holder of the
     shared client secret.
  4. /oauth/register is a public client (PKCE), no shared secret handed out.
The static Bearer (config.VAULT_MCP_TOKEN) still gates every MCP request (unchanged).
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from . import config

logger = logging.getLogger(__name__)

# Allowlist of permitted OAuth redirect URIs (exact match). Without this, anyone can
# drive /oauth/authorize and have the auth code delivered to an attacker host (KRYT,
# audyt s693). Configurable via env (comma-separated); defaults to the claude.ai MCP
# connector callback.
REDIRECT_ALLOWLIST = frozenset(
    u.strip()
    for u in os.environ.get(
        "VAULT_OAUTH_REDIRECT_ALLOWLIST",
        "https://claude.ai/api/mcp/auth_callback",
    ).split(",")
    if u.strip()
)

# In-memory store for authorization codes (short-lived)
_auth_codes: dict[str, dict] = {}


def _cleanup_codes():
    now = time.time()
    expired = [k for k, v in _auth_codes.items() if v["expires_at"] < now]
    for k in expired:
        del _auth_codes[k]


def _public_base(request: Request) -> str:
    """Zaufany publiczny URL bazowy. Z env VAULT_MCP_BASE_URL (anti-Host-spoofing, N69);
    fallback do request.base_url gdy nieustawiony (środowisko dev)."""
    if config.VAULT_MCP_BASE_URL:
        return config.VAULT_MCP_BASE_URL
    return str(request.base_url).rstrip("/")


# Rate-limit publicznych endpointów OAuth (audyt s1099, S77/S81) — per-IP, in-memory.
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


async def oauth_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth authorization server metadata."""
    base_url = _public_base(request)
    return JSONResponse(
        {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            # Public client + PKCE: no client secret used at the token endpoint.
            "token_endpoint_auth_methods_supported": ["none"],
        }
    )


async def oauth_authorize(request: Request):
    """OAuth 2.0 authorization endpoint (allowlisted redirect + mandatory PKCE)."""
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    response_type = request.query_params.get("response_type", "")
    client_id = request.query_params.get("client_id", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)

    if not redirect_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri required"},
            status_code=400,
        )

    # Allowlist check: refuse to issue a code to an unregistered redirect target.
    if redirect_uri not in REDIRECT_ALLOWLIST:
        logger.warning(f"OAuth authorize rejected: redirect_uri not in allowlist ({redirect_uri[:60]!r})")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri not allowed"},
            status_code=400,
        )

    # PKCE is mandatory (no downgrade): require an S256 challenge up front.
    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge required (PKCE)"},
            status_code=400,
        )
    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge_method must be S256"},
            status_code=400,
        )

    # Generate authorization code
    _cleanup_codes()
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 300,  # 5 minute expiry
    }

    logger.info(f"OAuth authorization code issued, redirecting to {redirect_uri[:50]}...")

    params = {"code": code}
    if state:
        params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
    )


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint -- authorization_code + PKCE only."""
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type", "")

    # Only authorization_code + PKCE is supported. client_credentials was removed
    # (audyt s693): it minted the master VAULT_MCP_TOKEN for anyone holding the shared
    # client secret handed out by /oauth/register.
    if grant_type == "authorization_code":
        return await _handle_authorization_code(form)
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _handle_authorization_code(form) -> JSONResponse:
    """Exchange an authorization code for a bearer token (PKCE mandatory)."""
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    _cleanup_codes()

    if code not in _auth_codes:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired code"},
            status_code=400,
        )

    code_data = _auth_codes.pop(code)

    # Bezwarunkowy exact-match (audyt s1099, bliźniak jarvis_rag N32): poprzedni warunek
    # pomijał porównanie gdy obie strony były puste. Kod zawsze bindowany do redirect_uri
    # z allowlisty przy wydaniu, więc stored nigdy nie jest pusty.
    if redirect_uri != code_data.get("redirect_uri", ""):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # PKCE verification is mandatory. Codes are only issued with a stored challenge
    # (oauth_authorize enforces it). A missing challenge here means a forged/legacy
    # grant -- reject. Never fall through to issuing a token.
    stored_challenge = code_data.get("code_challenge", "")
    if not stored_challenge:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "missing PKCE challenge"},
            status_code=400,
        )
    if not code_verifier:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "code_verifier required"},
            status_code=400,
        )

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    if not hmac.compare_digest(computed_challenge, stored_challenge):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    logger.info("OAuth token issued via authorization_code grant")
    return JSONResponse(
        {
            "access_token": config.VAULT_MCP_TOKEN,
            "token_type": "bearer",
            "expires_in": 86400,
        }
    )


async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration -- public client (PKCE), no shared secret."""
    if _oauth_rate_limited(request):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    try:
        body = await request.json()
    except Exception:
        body = {}

    client_id = f"vault-mcp-{secrets.token_hex(8)}"

    # Public client (PKCE): no shared client secret handed out (audyt s693 + s1099 N71 —
    # the dead VAULT_OAUTH_CLIENT_SECRET env was removed). authorization_code+PKCE needs
    # no client secret, and client_credentials is disabled.
    return JSONResponse(
        {
            "client_id": client_id,
            "client_name": body.get("client_name", "Obsidian Vault MCP Client"),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "redirect_uris": body.get("redirect_uris", []),
            "token_endpoint_auth_method": "none",
        },
        status_code=201,
    )


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """RFC 9728 OAuth 2.0 Protected Resource Metadata."""
    base_url = _public_base(request)
    return JSONResponse(
        {
            "resource": base_url,
            "authorization_servers": [base_url],
        }
    )


oauth_routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/oauth/authorize", oauth_authorize, methods=["GET"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/register", oauth_register, methods=["POST"]),
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource/mcp", oauth_protected_resource, methods=["GET"]),
]
