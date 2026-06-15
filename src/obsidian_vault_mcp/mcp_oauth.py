# ⚠️ WENDOROWANE z workos_shared/mcp_oauth.py (jedno źródło logiki) — NIE edytuj tutaj.
# vault-mcp jest forkiem samodzielnym (obsidian-web-mcp, nie importuje workos_shared),
# więc trzyma wierną kopię. Przy zmianie bramy: edytuj workos_shared, potem zsynchronizuj
# (cp). Kanon: GOLDEN-PATTERNS Wzorzec 9. Wierność (AST) sprawdzana w tests/test_oauth_gate.
"""Reużywalny OAuth 2.0 (authorization code + PKCE) z bramą tożsamości Google dla
connectorów MCP (claude.ai). JEDEN mechanizm logowania dla wszystkich serwerów MCP.

Owner-only: tylko e-maile z `allowed_emails` przechodzą logowanie Google → dostają
master-token usługi. FAIL-CLOSED bez konfiguracji bramy (odmowa, nie auto-approve).

Kanon: GOLDEN-PATTERNS Wzorzec 9. Decision Memory `2026-06-15 — Brama tożsamości Google
dla MCP`. Wzór sprawdzony end-to-end: jarvis_rag (s1286).

Dlaczego nie alternatywy (z incydentu s1286):
- auto-approve = każdy znający URL wyciąga master-token (czyta kod z własnego 302;
  redirect-allowlist+PKCE NIE chronią przed self-driven exfiltracją).
- formularz hasła operatora = claude.ai NIE domyka interaktywnego pośrednika.
- statyczny Bearer w nagłówku = działa w Claude Code, ale web/desktop wymusza OAuth.

Użycie:
    gate = McpOAuthGate(
        service_name="jarvis-rag",
        master_token=RAG_TOKEN,
        public_base="https://vps-2557.tail301a28.ts.net/rag",  # issuer / metadata base
        resource_path="/mcp",
        google_client_id=..., google_client_secret=..., google_redirect_uri=...,
        allowed_emails={"gg@example.com"},
        dev_insecure=False,
    )
    # mount gate.routes do aplikacji Starlette; dodaj gate.open_paths do wyjątku bearer-auth
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 (URL, nie sekret)

_AUTHORIZE_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
)

_CODE_TTL_S = 300
_PENDING_TTL_S = 600
_MAX_PENDING_LOGINS = 256  # twardy cap (anti-DoS) — publiczny /oauth/authorize


async def _read_urlencoded(request: Request) -> dict[str, str]:
    """Parsuj application/x-www-form-urlencoded BEZ python-multipart.

    Endpointy OAuth (token, authorize POST) używają wyłącznie urlencoded (RFC 6749).
    `request.form()` Starlette wymaga python-multipart — niepotrzebna zależność dla
    reużywalnej biblioteki. Parsujemy surowe ciało (last-wins, jak form.get)."""
    body = await request.body()
    return dict(parse_qsl(body.decode("utf-8")))


class McpOAuthGate:
    """OAuth authorization-code + PKCE z bramą tożsamości Google dla jednego serwera MCP.

    Każda instancja trzyma własny config + stan (kody, pending-loginy). Dostarcza trasy
    Starlette (`routes`) i ścieżki zwolnione z bearer-auth (`open_paths`).
    """

    def __init__(
        self,
        *,
        service_name: str,
        master_token: str,
        public_base: str,
        resource_path: str = "/mcp",
        redirect_allowlist: Iterable[str] = ("https://claude.ai/api/mcp/auth_callback",),
        google_client_id: str = "",
        google_client_secret: str = "",
        google_redirect_uri: str = "",
        allowed_emails: Iterable[str] = (),
        dev_insecure: bool = False,
    ):
        self.service_name = service_name
        self._master_token = master_token
        self.public_base = public_base.rstrip("/")
        self.resource_path = resource_path
        self.redirect_allowlist = frozenset(u.strip() for u in redirect_allowlist if u.strip())
        self.google_client_id = google_client_id
        self._google_client_secret = google_client_secret
        self.google_redirect_uri = google_redirect_uri
        self.allowed_emails = frozenset(e.strip().lower() for e in allowed_emails if e.strip())
        self.dev_insecure = dev_insecure
        self.log = logging.getLogger(f"{service_name}.mcp_oauth")

        self._auth_codes: dict[str, dict] = {}
        self._pending_logins: dict[str, dict] = {}

    # ── publiczne wejścia ────────────────────────────────────────────────────

    @property
    def identity_gate_enabled(self) -> bool:
        """Brama aktywna tylko gdy W PEŁNI skonfigurowana (4 elementy)."""
        return bool(
            self.google_client_id and self._google_client_secret and self.google_redirect_uri and self.allowed_emails
        )

    @property
    def open_paths(self) -> set[str]:
        """Ścieżki zwolnione z bearer-auth (pre-auth dla flow OAuth + odkrywania)."""
        return {
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            f"/.well-known/oauth-protected-resource{self.resource_path}",
            "/oauth/authorize",
            "/oauth/google/callback",
            "/oauth/token",
            "/oauth/register",
        }

    @property
    def routes(self) -> list[Route]:
        return [
            Route(
                "/.well-known/oauth-authorization-server",
                self.metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource",
                self.protected_resource,
                methods=["GET"],
            ),
            Route(
                f"/.well-known/oauth-protected-resource{self.resource_path}",
                self.protected_resource,
                methods=["GET"],
            ),
            Route("/oauth/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/oauth/google/callback", self.google_callback, methods=["GET"]),
            Route("/oauth/token", self.token, methods=["POST"]),
            Route("/oauth/register", self.register, methods=["POST"]),
        ]

    # ── helpery ──────────────────────────────────────────────────────────────

    def _base(self, request: Request) -> str:
        """Zaufany publiczny URL bazowy (anti Host-spoofing); fallback do request (dev)."""
        return self.public_base or str(request.base_url).rstrip("/")

    def _cleanup_codes(self) -> None:
        now = time.time()
        for k in [k for k, v in self._auth_codes.items() if v["expires_at"] < now]:
            del self._auth_codes[k]

    def _cleanup_pending(self) -> None:
        now = time.time()
        for k in [k for k, v in self._pending_logins.items() if v["expires_at"] < now]:
            del self._pending_logins[k]
        if len(self._pending_logins) > _MAX_PENDING_LOGINS:
            excess = len(self._pending_logins) - _MAX_PENDING_LOGINS
            for k, _ in sorted(self._pending_logins.items(), key=lambda kv: kv[1]["expires_at"])[:excess]:
                del self._pending_logins[k]

    def _validate_authorize(self, params: dict) -> JSONResponse | None:
        if params.get("response_type") != "code":
            return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
        redirect_uri = params.get("redirect_uri", "")
        if not redirect_uri:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri required",
                },
                status_code=400,
            )
        if redirect_uri not in self.redirect_allowlist:
            self.log.warning("authorize odrzucony: redirect_uri spoza allowlisty")
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri not allowed",
                },
                status_code=400,
            )
        if not params.get("code_challenge"):
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "code_challenge required (PKCE)",
                },
                status_code=400,
            )
        if params.get("code_challenge_method", "S256") != "S256":
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "code_challenge_method must be S256",
                },
                status_code=400,
            )
        return None

    def _issue_code_and_redirect(self, params: dict):
        # Re-check allowlisty tuż przed wydaniem (anti open-redirect regres).
        if params.get("redirect_uri") not in self.redirect_allowlist:
            self.log.warning("issue_code odmówił: redirect_uri spoza allowlisty")
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri not allowed",
                },
                status_code=400,
            )
        self._cleanup_codes()
        code = secrets.token_urlsafe(32)
        self._auth_codes[code] = {
            "client_id": params.get("client_id", ""),
            "redirect_uri": params["redirect_uri"],
            "code_challenge": params["code_challenge"],
            "code_challenge_method": params.get("code_challenge_method", "S256"),
            "expires_at": time.time() + _CODE_TTL_S,
        }
        self.log.info("kod autoryzacji wydany, redirect → %s...", params["redirect_uri"][:50])
        query = {"code": code}
        if params.get("state"):
            query["state"] = params["state"]
        redirect_uri = params["redirect_uri"]
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(url=f"{redirect_uri}{sep}{urlencode(query)}", status_code=302)

    async def _verify_google_identity(self, code: str) -> str | None:
        """Wymień kod Google na zweryfikowany e-mail (None gdy niepowodzenie). Fail-closed."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    _GOOGLE_TOKEN_URL,
                    data={
                        "code": code,
                        "client_id": self.google_client_id,
                        "client_secret": self._google_client_secret,
                        "redirect_uri": self.google_redirect_uri,
                        "grant_type": "authorization_code",
                    },
                )
        except httpx.HTTPError as exc:
            self.log.warning("Google token exchange transport error: %s", type(exc).__name__)
            return None
        if resp.status_code != 200:
            self.log.warning("Google token exchange rejected: HTTP %s", resp.status_code)
            return None
        id_tok = resp.json().get("id_token", "")
        if not id_tok:
            return None
        try:
            claims = google_id_token.verify_oauth2_token(id_tok, google_requests.Request(), self.google_client_id)
        except Exception as exc:  # noqa: BLE001 — weryfikacja podpisu MUSI fail-closed na każdy błąd
            self.log.warning("Google id_token verification failed: %s", type(exc).__name__)
            return None
        if not claims.get("email_verified"):
            return None
        return claims.get("email")

    # ── trasy ────────────────────────────────────────────────────────────────

    async def metadata(self, request: Request) -> JSONResponse:
        """RFC 8414 OAuth authorization server metadata."""
        base = self._base(request)
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
            }
        )

    async def protected_resource(self, request: Request) -> JSONResponse:
        """RFC 9728 — obsługuje wariant goły I z sufiksem zasobu (claude.ai pyta o ten drugi)."""
        base = self._base(request)
        resource = f"{base}{self.resource_path}" if request.url.path.endswith(self.resource_path) else base
        return JSONResponse({"resource": resource, "authorization_servers": [base]})

    async def authorize(self, request: Request):
        """Brama tożsamości: waliduj → przekieruj do Google (lub fail-closed/dev)."""
        if request.method == "POST":
            form = await _read_urlencoded(request)
            params = {f: form.get(f, "") for f in _AUTHORIZE_FIELDS}
        else:
            params = {f: request.query_params.get(f, "") for f in _AUTHORIZE_FIELDS}
        if not params.get("code_challenge_method"):
            params["code_challenge_method"] = "S256"
        err = self._validate_authorize(params)
        if err:
            return err

        if not self.identity_gate_enabled:
            if self.dev_insecure:
                self.log.warning("DEV_INSECURE — auto-approve (TYLKO dev, nigdy produkcja)")
                return self._issue_code_and_redirect(params)
            self.log.error("Brama tożsamości nieskonfigurowana — authorize ODMÓWIONY (fail-closed)")
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "OAuth identity gate not configured",
                },
                status_code=503,
            )

        self._cleanup_pending()
        login_state = secrets.token_urlsafe(32)
        self._pending_logins[login_state] = {
            **params,
            "expires_at": time.time() + _PENDING_TTL_S,
        }
        google_url = (
            _GOOGLE_AUTH_URL
            + "?"
            + urlencode(
                {
                    "client_id": self.google_client_id,
                    "redirect_uri": self.google_redirect_uri,
                    "response_type": "code",
                    "scope": "openid email",
                    "state": login_state,
                    "access_type": "online",
                    "prompt": "select_account",
                }
            )
        )
        return RedirectResponse(google_url, status_code=302)

    async def google_callback(self, request: Request):
        """Powrót z Google: weryfikuj tożsamość, sprawdź allowlistę, wznów OAuth."""
        login_state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        self._cleanup_pending()
        pending = self._pending_logins.pop(login_state, None)
        if not pending or not code:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Nieznany lub wygasły stan logowania.",
                },
                status_code=400,
            )
        email = await self._verify_google_identity(code)
        if not email or email.lower() not in self.allowed_emails:
            self.log.warning("Brama tożsamości: ODMOWA dla %r", email or "nieznany")
            return JSONResponse(
                {
                    "error": "access_denied",
                    "error_description": "To konto Google nie ma dostępu do tego serwera.",
                },
                status_code=403,
            )
        self.log.info("Brama tożsamości: WPUSZCZONO %s", email)
        return self._issue_code_and_redirect({f: pending.get(f, "") for f in _AUTHORIZE_FIELDS})

    async def token(self, request: Request) -> JSONResponse:
        """OAuth token endpoint — authorization_code + PKCE (zwraca master-token usługi)."""
        try:
            form = await _read_urlencoded(request)
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        if form.get("grant_type", "") != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        code_verifier = form.get("code_verifier", "")
        self._cleanup_codes()
        if code not in self._auth_codes:
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired code",
                },
                status_code=400,
            )
        data = self._auth_codes.pop(code)
        if redirect_uri != data.get("redirect_uri", ""):
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "redirect_uri mismatch",
                },
                status_code=400,
            )
        stored_challenge = data.get("code_challenge", "")
        if not stored_challenge:
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "missing PKCE challenge",
                },
                status_code=400,
            )
        if not code_verifier:
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "code_verifier required",
                },
                status_code=400,
            )
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not secrets.compare_digest(computed, stored_challenge):
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "PKCE verification failed",
                },
                status_code=400,
            )
        self.log.info("token wydany via authorization_code grant")
        return JSONResponse(
            {
                "access_token": self._master_token,
                "token_type": "bearer",
                "expires_in": 86400,
            }
        )

    async def register(self, request: Request) -> JSONResponse:
        """Dynamic client registration — public client (PKCE), bez współdzielonego sekretu."""
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        client_id = f"{self.service_name}-{secrets.token_hex(8)}"
        return JSONResponse(
            {
                "client_id": client_id,
                "client_name": body.get("client_name", self.service_name),
                "redirect_uris": body.get("redirect_uris", list(self.redirect_allowlist)),
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            },
            status_code=201,
        )
