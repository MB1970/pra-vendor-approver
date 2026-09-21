#!/usr/bin/env python3
"""
Stage 1 smoke test: get a token, make one GET /user call, print what came back.

Read-only. Nothing in this script writes to PRA, regardless of DRY_RUN.

    python3 smoke_test.py            # token + GET /user
    python3 smoke_test.py --info     # also GET /api/command/v2/info first

Exit codes: 0 success, 1 API or network failure, 2 configuration problem.
"""

import argparse
import sys
from typing import Any, Dict, List

import requests

from pra_client import Config, ConfigError, PageInfo, PraApiError, PraClient, load_config

# Fields from the User schema worth seeing on a first run. security_provider_id is included so an
# unscoped run reveals which id to put in VENDOR_SECURITY_PROVIDER_ID; last_authentication is
# included because it answers the customer's open question about last-login visibility.
USER_COLUMNS = (
    "id",
    "security_provider_id",
    "username",
    "email_address",
    "enabled",
    "created_at",
    "last_authentication",
)


def redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}...({len(value)} chars)"


def indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def print_config(cfg: Config) -> None:
    scope = cfg.vendor_security_provider_id
    print(f"Host:                        {cfg.pra_host}")
    print(f"Client ID:                   {redact(cfg.pra_client_id)}")
    print("Client secret:               (loaded, not shown)")
    print(f"VENDOR_SECURITY_PROVIDER_ID: {scope if scope is not None else '(not set)'}")
    print(f"DRY_RUN:                     {cfg.dry_run}   (this script performs no writes either way)")
    if scope is None:
        print()
        print("WARNING: VENDOR_SECURITY_PROVIDER_ID is not set — this run lists ALL users, unscoped.")
        print("         Use the security_provider_id column below to find the vendor's id, then set")
        print("         it in .env. Every later stage refuses to run without it.")
    print()


def print_info(client: PraClient) -> None:
    print("GET", f"{client.command_base}/info")
    try:
        data = client.info()
    except PraApiError as e:
        print("  --info failed; continuing to GET /user:")
        print(indent(str(e)))
        print()
        return
    print(f"  product:               {data.get('product')}")
    print(f"  command_api_version:   {data.get('command_api_version')}")
    print(f"  config_api_version:    {data.get('config_api_version')}")
    print(f"  current_time:          {data.get('current_time')}")
    perms: Dict[str, Any] = data.get("permissions") or {}
    print("  permissions:")
    for key in sorted(perms):
        print(f"    {key:<40} {perms[key]}")
    if perms.get("perm_configuration") is False:
        print()
        print("  !! perm_configuration is false — GET /user will return 403.")
        print("     Tick 'Configuration API -> Allow Access' on the API account and re-run.")
    print()


def print_users(users: List[Dict[str, Any]]) -> None:
    if not users:
        print("0 users returned.")
        print("If VENDOR_SECURITY_PROVIDER_ID is set, either it is wrong or no one from that provider")
        print("has authenticated yet — non-local users only appear in PRA after first login.")
        return

    rows = [[str(u.get(col, "")) for col in USER_COLUMNS] for u in users]
    widths = [max(len(col), *(len(r[i]) for r in rows)) for i, col in enumerate(USER_COLUMNS)]
    line = "  ".join(col.ljust(widths[i]) for i, col in enumerate(USER_COLUMNS))
    print(line)
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)))

    extra = sorted({k for u in users for k in u} - set(USER_COLUMNS))
    print()
    print(f"Other fields present on each user ({len(extra)}): {', '.join(extra)}")


def print_page(url: str, users: List[Dict[str, Any]], page: PageInfo) -> None:
    print("GET", url)
    total = page.total if page.total is not None else "?"
    last = page.last_page if page.last_page is not None else "?"
    print(f"  HTTP 200 — {len(users)} user(s) on this page, {total} total, {last} page(s)")
    if page.rate_limit_remaining is not None:
        print(f"  rate limit: {page.rate_limit_remaining}/{page.rate_limit} requests remaining")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Also call GET /api/command/v2/info to show the product type and this API account's "
        "permissions. Tells a permissions problem apart from a bad token.",
    )
    args = parser.parse_args(argv)

    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    print_config(cfg)
    client = PraClient(cfg.pra_host, cfg.pra_client_id, cfg.pra_client_secret)

    try:
        print("POST", client.token_url)
        client.get_token()
        print(f"  token OK (expires_in={client.token_expires_in}s)")
        print()

        if args.info:
            print_info(client)

        users, page = client.get_users(security_provider_id=cfg.vendor_security_provider_id)
        print_page(client.last_request[1] if client.last_request else "?", users, page)
        print_users(users)
        return 0

    except PraApiError as e:
        print("\nAPI call failed:", file=sys.stderr)
        print(indent(str(e), "  "), file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"\nNetwork error talking to {cfg.pra_host}: {e}", file=sys.stderr)
        print(
            "Check DNS, outbound 443, and that this host's public IP is on the API account's "
            "Network Address Allow List.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
