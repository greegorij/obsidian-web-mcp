"""Bearer token authentication middleware for the vault MCP server."""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import VAULT_MCP_TOKEN

# Paths that don't require bearer auth (OAuth flow + health)
_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
    "/.well-known/openid-configuration",
}


def _www_authenticate_header(request: Request) -> dict[str, str]:
    """Per MCP spec 2025-03-26: 401 MUST include WWW-Authenticate pointing to PRM."""
    base = os.environ.get("PUBLIC_BASE_URL", str(request.base_url).rstrip("/")).rstrip("/")
    return {
        "WWW-Authenticate": (
            f'Bearer realm="vault-mcp", '
            f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
        )
    }


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens on all requests except OAuth and health endpoints."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        if not VAULT_MCP_TOKEN:
            return JSONResponse(
                {"error": "Server misconfigured: no auth token set"},
                status_code=500,
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing or malformed Authorization header"},
                status_code=401,
                headers=_www_authenticate_header(request),
            )

        token = auth_header[7:]
        if token != VAULT_MCP_TOKEN:
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers=_www_authenticate_header(request),
            )

        return await call_next(request)
