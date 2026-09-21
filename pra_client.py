"""
Minimal client for the BeyondTrust Privileged Remote Access APIs.

Every URL, parameter and field in this module comes from the spec files in this directory:

    bt-pra-configuration-v1.openapi.yaml   ->  https://<host>/api/config/v1
    bt-pra-command-v2.openapi.yaml         ->  https://<host>/api/command/v2

If something is not in those files, it does not belong here.

Stages 1-2 scope: obtain a token and read users, their group policies, and the names of the
vendor's security provider and group policy. There are no write methods.
"""

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = PROJECT_DIR / ".env"

# The variables named in CLAUDE.md "Environment". Anything else in .env is ignored.
KNOWN_VARS = (
    "PRA_HOST",
    "PRA_CLIENT_ID",
    "PRA_CLIENT_SECRET",
    "VENDOR_SECURITY_PROVIDER_ID",
    "VENDOR_GROUP_POLICY_ID",
    "APPROVER_EMAILS",
    "DEFAULT_EXPIRY_DAYS",
    "DRY_RUN",
)
REQUIRED_VARS = ("PRA_HOST", "PRA_CLIENT_ID", "PRA_CLIENT_SECRET")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    """Raised when .env / the environment is missing or malformed."""


@dataclass
class Config:
    pra_host: str
    pra_client_id: str
    pra_client_secret: str
    vendor_security_provider_id: Optional[int]
    vendor_group_policy_id: Optional[int]
    approver_emails: List[str]
    default_expiry_days: int
    dry_run: bool


def _read_env_file(path: Path) -> Dict[str, str]:
    """Parse KEY=VALUE lines. Blank lines and # comments are skipped; a trailing
    ' # comment' after a value is stripped; single or double quotes around a value are removed."""
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.split(" #", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _optional_int(raw: Optional[str], name: str) -> Optional[int]:
    if raw is None or raw.strip() == "":
        return None
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


def _parse_bool(raw: Optional[str], default: bool) -> bool:
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off")


def load_config(env_file: Path = DEFAULT_ENV_FILE) -> Config:
    """Load settings from .env, with real environment variables taking precedence."""
    values = _read_env_file(env_file)
    for key in KNOWN_VARS:
        if key in os.environ:
            values[key] = os.environ[key]

    missing = [k for k in REQUIRED_VARS if not values.get(k)]
    if missing:
        raise ConfigError(
            f"missing required setting(s): {', '.join(missing)}. "
            f"Copy .env.example to .env and fill them in (looked for {env_file})."
        )

    host = values["PRA_HOST"].strip()
    if "://" in host or "/" in host or " " in host:
        raise ConfigError(
            "PRA_HOST must be a bare hostname such as access.example.com "
            f"(no scheme, no path, no /login) — got {host!r}"
        )

    emails = [e.strip() for e in values.get("APPROVER_EMAILS", "").split(",") if e.strip()]

    return Config(
        pra_host=host,
        pra_client_id=values["PRA_CLIENT_ID"].strip(),
        pra_client_secret=values["PRA_CLIENT_SECRET"],
        vendor_security_provider_id=_optional_int(
            values.get("VENDOR_SECURITY_PROVIDER_ID"), "VENDOR_SECURITY_PROVIDER_ID"
        ),
        vendor_group_policy_id=_optional_int(
            values.get("VENDOR_GROUP_POLICY_ID"), "VENDOR_GROUP_POLICY_ID"
        ),
        approver_emails=emails,
        default_expiry_days=_optional_int(values.get("DEFAULT_EXPIRY_DAYS"), "DEFAULT_EXPIRY_DAYS")
        or 365,
        # Dry-run is the default. Only an explicit false/0/no/off turns it off.
        dry_run=_parse_bool(values.get("DRY_RUN"), default=True),
    )


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------


class PraApiError(Exception):
    """A non-2xx response. Carries the request and the raw body so it can be compared to the spec."""

    def __init__(self, method: str, url: str, status: int, body: str):
        self.method = method
        self.url = url
        self.status = status
        self.body = body
        super().__init__(self._format())

    def _format(self) -> str:
        lines = [f"{self.method} {self.url}", f"HTTP {self.status}", self.body.strip() or "(empty body)"]
        if self.status == 401:
            # Configuration API spec, "Common HTTP Status Codes": 401 is also what you get for
            # unrecognized query string parameters or request body fields, not only bad tokens.
            lines.append(
                "Note: the Configuration API returns 401 for unrecognized query parameters or "
                "body fields as well as for an invalid token. Check spelling against the spec."
            )
        if self.status == 403:
            lines.append(
                "Note: 403 means this API account does not have permission to use this API. "
                "Run smoke_test.py --info to see the account's permissions."
            )
        return "\n".join(lines)


@dataclass
class PageInfo:
    """Pagination and rate-limit headers from a list response."""

    current_page: Optional[int]
    per_page: Optional[int]
    last_page: Optional[int]
    total: Optional[int]
    link: Optional[str]
    rate_limit: Optional[int]
    rate_limit_remaining: Optional[int]

    @classmethod
    def from_headers(cls, headers: Any) -> "PageInfo":
        def num(name: str) -> Optional[int]:
            value = headers.get(name)
            return int(value) if value is not None and str(value).isdigit() else None

        return cls(
            current_page=num("X-BT-Pagination-Current-Page"),
            per_page=num("X-BT-Pagination-Per-Page"),
            last_page=num("X-BT-Pagination-Last-Page"),
            total=num("X-BT-Pagination-Total"),
            link=headers.get("Link"),
            rate_limit=num("X-RateLimit-Limit"),
            rate_limit_remaining=num("X-RateLimit-Remaining"),
        )


class PraClient:
    """OAuth 2 client-credentials client for one PRA appliance. Read-only through stage 2."""

    # Refresh the token this many seconds before the appliance says it expires.
    TOKEN_SKEW_SECONDS = 60

    def __init__(self, host: str, client_id: str, client_secret: str, timeout: float = 30.0):
        self.host = host
        self.token_url = f"https://{host}/oauth2/token"
        self.config_base = f"https://{host}/api/config/v1"
        self.command_base = f"https://{host}/api/command/v2"
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self.token_expires_in: Optional[int] = None
        # (method, url) of the most recent request — for "show me what we actually sent".
        self.last_request: Optional[Tuple[str, str]] = None

    # -- auth -------------------------------------------------------------

    def get_token(self) -> str:
        """Return a cached bearer token, fetching a new one when missing or near expiry.

        Spec: POST https://<host>/oauth2/token with the client id and secret Base64-encoded in an
        HTTP Basic Authorization header and a body of grant_type=client_credentials. The token lives
        one hour; each API account may hold at most 30 live tokens, so we reuse rather than re-mint.
        """
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        # requests' auth= tuple produces exactly "Authorization: Basic base64(client_id:secret)".
        resp = requests.post(
            self.token_url,
            auth=(self._client_id, self._client_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json", "Connection": "close"},
            timeout=self._timeout,
        )
        self.last_request = ("POST", self.token_url)
        if resp.status_code != 200:
            raise PraApiError("POST", self.token_url, resp.status_code, resp.text)

        payload = resp.json()
        self._token = payload["access_token"]
        self.token_expires_in = int(payload.get("expires_in", 3600))
        self._token_expires_at = time.monotonic() + max(
            self.token_expires_in - self.TOKEN_SKEW_SECONDS, 0
        )
        return self._token

    # -- transport --------------------------------------------------------

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        """GET with bearer auth. Raises PraApiError on any non-2xx status.

        Deliberately uses requests.get (a fresh connection per call, closed afterwards) plus an
        explicit Connection: close header. The spec says: "When making consecutive API calls,
        you must close the connection after each API call." Do not switch this to a Session.
        """
        headers = {
            "Authorization": f"Bearer {self.get_token()}",
            "Accept": "application/json",  # required on GET and DELETE per the spec
            "Connection": "close",
        }
        resp = requests.get(url, params=params, headers=headers, timeout=self._timeout)
        self.last_request = ("GET", resp.url)
        if not 200 <= resp.status_code < 300:
            raise PraApiError("GET", resp.url, resp.status_code, resp.text)
        return resp

    # -- Configuration API v1 ---------------------------------------------

    def get_users(
        self,
        security_provider_id: Optional[int] = None,
        per_page: int = 100,
        current_page: int = 1,
    ) -> Tuple[List[Dict[str, Any]], PageInfo]:
        """GET /api/config/v1/user — one page of User resources.

        Filter is security_provider_id (exact match). per_page is 5..100; 100 is the default and
        the maximum. Non-local users are returned in order of first authentication.
        """
        params: Dict[str, Any] = {"per_page": per_page, "current_page": current_page}
        if security_provider_id is not None:
            params["security_provider_id"] = security_provider_id
        resp = self.get(f"{self.config_base}/user", params=params)
        return resp.json(), PageInfo.from_headers(resp.headers)

    def iter_users(self, security_provider_id: int) -> Iterator[Dict[str, Any]]:
        """Every User in one security provider, walking all pages of GET /user.

        The filter is mandatory here on purpose: this is the call the detection loop uses, and the
        brief says every query is scoped to one vendor server-side. Stops when the page index
        reaches X-BT-Pagination-Last-Page, or after the first page if that header is missing.
        """
        page = 1
        while True:
            users, info = self.get_users(security_provider_id=security_provider_id, current_page=page)
            for user in users:
                yield user
            if not users or info.last_page is None or page >= info.last_page:
                return
            page += 1

    def get_user_group_policies(self, user_id: int) -> Tuple[List[Dict[str, Any]], PageInfo]:
        """GET /api/config/v1/user/{id}/group-policies — GroupPolicy resources (id, name, ...) the
        user is currently a member of.

        The spec declares pagination *headers* on this response but no per_page/current_page query
        parameters, so none are sent — the Configuration API answers 401 to unrecognised parameters.
        Callers should check PageInfo.last_page and warn if it is above 1.
        """
        resp = self.get(f"{self.config_base}/user/{int(user_id)}/group-policies")
        return resp.json(), PageInfo.from_headers(resp.headers)

    def get_security_provider(self, provider_id: int) -> Dict[str, Any]:
        """GET /api/config/v1/security-provider/{id} — id, type, name, enabled, user_authentication."""
        return self.get(f"{self.config_base}/security-provider/{int(provider_id)}").json()

    def get_group_policy(self, policy_id: int) -> Dict[str, Any]:
        """GET /api/config/v1/group-policy/{id} — the GroupPolicy resource; we only read id and name."""
        return self.get(f"{self.config_base}/group-policy/{int(policy_id)}").json()

    # -- Command API v2 ---------------------------------------------------

    def info(self) -> Dict[str, Any]:
        """GET /api/command/v2/info — API versions, product type, and this API account's permissions."""
        return self.get(f"{self.command_base}/info").json()
