"""Bearer-token authentication for the optional HTTP transport."""

from __future__ import annotations

import hmac

from fastmcp.server.auth import AccessToken, TokenVerifier


class StaticBearerVerifier(TokenVerifier):
    """Accepts exactly one pre-shared bearer token, compared in constant time."""

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token.encode()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an access token when the presented token matches, else None."""
        if not token or not hmac.compare_digest(token.encode(), self._token):
            return None
        # The placeholder keeps the real secret out of the access token and any logs.
        return AccessToken(token="static-bearer", client_id="static-bearer", scopes=[], expires_at=None)  # noqa: S106
