"""Small, explicit authentication boundary for the durable web API.

The application is often deployed behind Tailscale, but tailnet reachability is
not report-level authorization.  Review and deletion audit records must be
attributed to a server-authenticated principal rather than a caller-supplied
``actor`` field.  This module deliberately keeps the first deployment option
small: a static bearer-token map from protected environment configuration.

For an organization SSO/reverse-proxy deployment, use ``trusted_proxy`` only
when the application is reachable *solely* through that proxy and the proxy
strips/replaces the configured identity header.  It is explicit because blindly
trusting a browser-supplied identity header would recreate the original flaw.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

from fastapi import Request


class AuthenticationError(RuntimeError):
    """Raised when a request lacks a valid authenticated principal."""


class AuthorizationError(AuthenticationError):
    """Raised when an authenticated principal lacks a required permission."""


@dataclass(frozen=True)
class Principal:
    actor_id: str
    roles: frozenset[str]
    authentication_method: str

    def can(self, permission: str) -> bool:
        role_permissions = {
            "viewer": {"view"},
            "analyst": {"view", "submit", "operate"},
            "reviewer": {"view", "review", "delete"},
            "admin": {"view", "submit", "operate", "review", "delete", "admin"},
        }
        return any(permission in role_permissions.get(role, set()) for role in self.roles)


def parse_token_map(raw: str | None) -> dict[str, Principal]:
    """Parse ``CSDH_AUTH_TOKENS_JSON`` without ever returning raw tokens.

    Expected format::

        {"long-random-token": {"actor": "analyst@example", "roles": ["admin"]}}

    A string value is accepted as a concise actor-only admin entry for a small
    single-user deployment.  Invalid configuration is rejected at startup;
    silently running an unauthenticated service would be unsafe.
    """
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthenticationError("CSDH_AUTH_TOKENS_JSON is not valid JSON.") from exc
    if not isinstance(parsed, Mapping):
        raise AuthenticationError("CSDH_AUTH_TOKENS_JSON must be a JSON object keyed by bearer token.")
    result: dict[str, Principal] = {}
    for token, value in parsed.items():
        token_value = str(token)
        if len(token_value) < 16:
            raise AuthenticationError("Each API bearer token must be at least 16 characters.")
        if isinstance(value, str):
            actor = value.strip()
            roles = {"admin"}
        elif isinstance(value, Mapping):
            actor = str(value.get("actor") or "").strip()
            raw_roles = value.get("roles", [])
            if isinstance(raw_roles, str):
                raw_roles = [raw_roles]
            roles = {str(role).strip().lower() for role in raw_roles if str(role).strip()} if isinstance(raw_roles, (list, tuple, set)) else set()
        else:
            raise AuthenticationError("Each token entry must be an actor string or an object with actor/roles.")
        if not actor:
            raise AuthenticationError("Each API token entry requires a non-empty actor.")
        if not roles or not roles <= {"viewer", "analyst", "reviewer", "admin"}:
            raise AuthenticationError("Each API token entry requires one or more valid roles.")
        result[token_value] = Principal(actor_id=actor, roles=frozenset(roles), authentication_method="bearer_token")
    return result


@dataclass(frozen=True)
class AuthPolicy:
    """Authentication configuration supplied by :class:`BackendSettings`."""

    mode: str
    token_principals: Mapping[str, Principal]
    trusted_proxy_header: str = "X-CSDH-Authenticated-User"

    @property
    def is_enabled(self) -> bool:
        return self.mode != "disabled"

    @property
    def is_ready(self) -> bool:
        if self.mode == "disabled":
            return True
        if self.mode == "token":
            return bool(self.token_principals)
        return self.mode == "trusted_proxy" and bool(self.trusted_proxy_header)

    def authenticate(self, request: Request) -> Principal | None:
        if self.mode == "disabled":
            return None
        if self.mode == "token":
            header = (request.headers.get("authorization") or "").strip()
            scheme, _, supplied = header.partition(" ")
            if scheme.lower() != "bearer" or not supplied:
                # The SPA exchanges an initial bearer token for this HttpOnly,
                # same-origin session cookie so EventSource can authenticate
                # without placing a long-lived secret in a query string.
                supplied = str(request.cookies.get("csdh_session") or "")
            if not supplied:
                raise AuthenticationError("A bearer token is required.")
            # Compare every configured token with ``compare_digest`` rather
            # than relying on a direct dictionary membership timing signal.
            for configured, principal in self.token_principals.items():
                if hmac.compare_digest(configured, supplied):
                    return principal
            raise AuthenticationError("The supplied bearer token is not recognized.")
        if self.mode == "trusted_proxy":
            actor = (request.headers.get(self.trusted_proxy_header) or "").strip()
            roles = (request.headers.get(f"{self.trusted_proxy_header}-Roles") or "").split(",")
            normalized_roles = {role.strip().lower() for role in roles if role.strip()}
            if not actor or not normalized_roles:
                raise AuthenticationError("The authenticated reverse-proxy identity headers are missing.")
            if not normalized_roles <= {"viewer", "analyst", "reviewer", "admin"}:
                raise AuthenticationError("The authenticated reverse-proxy roles are invalid.")
            return Principal(actor_id=actor, roles=frozenset(normalized_roles), authentication_method="trusted_proxy")
        raise AuthenticationError(f"Unsupported CSDH_AUTH_MODE '{self.mode}'.")

    def require(self, request: Request, permission: str) -> Principal | None:
        if not self.is_ready:
            raise AuthenticationError("Authentication is required but not configured. Set CSDH_AUTH_TOKENS_JSON or configure a trusted reverse proxy.")
        principal = self.authenticate(request)
        if principal is not None and not principal.can(permission):
            raise AuthorizationError(f"Authenticated actor '{principal.actor_id}' lacks '{permission}' permission.")
        return principal
