#!/usr/bin/env python3
"""
Stage 2: detection loop, log-only.

Polls PRA for users belonging to the vendor's security provider, diffs them against the local
store, and logs what it *would* have emailed the approvers. It does not send email and it does
not write to PRA, regardless of DRY_RUN.

    python3 detect.py                       # one poll, then exit
    python3 detect.py --loop                # poll every 5 minutes until Ctrl-C / SIGTERM
    python3 detect.py --loop --interval 60  # poll every 60 seconds
    python3 detect.py --show                # print the store (users, would-be emails, poll runs)

A "new arrival" is a user from the vendor's provider whom this app has never seen and who is
a member of no group policy. Someone who already has a group policy the first time we see them
is recorded as pre-existing and reported, but no approval request is composed for them — they
already have access and a human needs to decide whether to recertify them.

Exit codes: 0 success, 1 API or network failure, 2 configuration problem.
"""

import argparse
import json
import logging
import signal
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import requests

from pra_client import Config, ConfigError, PraApiError, PraClient, load_config
from store import (
    DEFAULT_DB_PATH,
    NOTIFICATION_NEW_USER,
    STATUS_PENDING,
    STATUS_PREEXISTING,
    Store,
)

log = logging.getLogger("detect")

DEFAULT_INTERVAL_SECONDS = 300


class Vendor:
    """Names for the ids in .env, fetched once per process so log lines are readable."""

    def __init__(self, client: PraClient, cfg: Config):
        assert cfg.vendor_security_provider_id is not None
        self.provider_id: int = cfg.vendor_security_provider_id
        self.policy_id: Optional[int] = cfg.vendor_group_policy_id

        provider = client.get_security_provider(self.provider_id)
        self.provider_name: str = provider.get("name") or f"provider {self.provider_id}"
        if not provider.get("user_authentication", True):
            log.warning(
                "security provider %s (%s) has user_authentication=false; no users will ever "
                "appear under it",
                self.provider_id,
                self.provider_name,
            )
        if provider.get("enabled") is False:
            log.warning("security provider %s (%s) is disabled", self.provider_id, self.provider_name)

        self.policy_name: Optional[str] = None
        if self.policy_id is not None:
            self.policy_name = client.get_group_policy(self.policy_id).get("name") or f"policy {self.policy_id}"


# ---------------------------------------------------------------------------
# The message we would send
# ---------------------------------------------------------------------------


def compose_new_user_notification(user: Dict[str, Any], vendor: Vendor, cfg: Config) -> Dict[str, str]:
    """Subject and body of the approver email for one new arrival. Plain text, no HTML."""
    username = user.get("username") or "(no username)"
    subject = f"[PRA vendor access] {vendor.provider_name}: {username} is waiting for approval"

    grant = (
        f'Approval adds the user to group policy "{vendor.policy_name}" for {cfg.default_expiry_days} days.'
        if vendor.policy_name
        else f"Approval adds the user to the vendor group policy for {cfg.default_expiry_days} days "
        "(VENDOR_GROUP_POLICY_ID is not set yet)."
    )
    body = "\n".join(
        [
            f"A user from {vendor.provider_name} has signed in to PRA and has no access yet.",
            "",
            f"  Username:       {username}",
            f"  Display name:   {user.get('public_display_name') or '-'}",
            f"  Email:          {user.get('email_address') or '-'}",
            f"  First sign-in:  {user.get('created_at') or '-'}",
            f"  Last sign-in:   {user.get('last_authentication') or '-'}",
            f"  PRA user id:    {user.get('id')}",
            "",
            "Approve or deny:  <approver console link - stage 3>",
            "",
            grant,
            "Until approved, this user is a member of no group policy and can reach nothing.",
            "You will only ever be shown users from this vendor.",
        ]
    )
    return {"subject": subject, "body": body}


# ---------------------------------------------------------------------------
# One poll
# ---------------------------------------------------------------------------


def policy_summary(policies: Sequence[Dict[str, Any]]) -> str:
    return ", ".join(f"{p.get('name')!s} (#{p.get('id')})" for p in policies) or "none"


def fetch_group_policies(client: PraClient, user_id: int) -> List[Dict[str, Any]]:
    policies, page = client.get_user_group_policies(user_id)
    if page.last_page is not None and page.last_page > 1:
        log.warning(
            "user %s has %s pages of group policies but the spec offers no way to request page 2; "
            "only the first %s are considered",
            user_id,
            page.last_page,
            len(policies),
        )
    return policies


def poll_once(client: PraClient, store: Store, cfg: Config, vendor: Vendor) -> None:
    run_id = store.start_poll()
    known_before = set(store.known_user_ids())
    seen_ids = set()
    new_pending = 0
    new_preexisting = 0

    try:
        for user in client.iter_users(vendor.provider_id):
            uid = int(user["id"])

            # Belt and braces: the server filtered by security_provider_id, but never let a user
            # from anywhere else into the vendor's store or its counts.
            if int(user.get("security_provider_id", -1)) != vendor.provider_id:
                log.error(
                    "PRA returned user %s from provider %s in a query scoped to %s; ignoring",
                    uid,
                    user.get("security_provider_id"),
                    vendor.provider_id,
                )
                continue
            seen_ids.add(uid)

            existing = store.get_user(uid)
            if existing is not None:
                store.touch_user(user)
                if existing["status"] == STATUS_PENDING:
                    # Has someone granted access behind our back (in the PRA console)?
                    policies = fetch_group_policies(client, uid)
                    if policies:
                        note = f"gained group policy outside this app: {policy_summary(policies)}"
                        store.set_status(uid, STATUS_PREEXISTING, note)
                        log.warning("user %s (%s) %s", uid, user.get("username"), note)
                continue

            # First time this app has seen this user.
            policies = fetch_group_policies(client, uid)
            if not policies:
                store.insert_user(user, STATUS_PENDING, policies)
                msg = compose_new_user_notification(user, vendor, cfg)
                nid = store.add_notification(
                    NOTIFICATION_NEW_USER, uid, cfg.approver_emails, msg["subject"], msg["body"]
                )
                new_pending += 1
                recipients = ", ".join(cfg.approver_emails) or "(APPROVER_EMAILS is empty)"
                log.info(
                    "NEW ARRIVAL user %s username=%s email=%s - WOULD EMAIL %s [notification #%s]\n"
                    "    Subject: %s\n%s",
                    uid,
                    user.get("username"),
                    user.get("email_address"),
                    recipients,
                    nid,
                    msg["subject"],
                    "\n".join("    | " + line for line in msg["body"].splitlines()),
                )
            else:
                in_vendor_policy = vendor.policy_id is not None and any(
                    p.get("id") == vendor.policy_id for p in policies
                )
                if in_vendor_policy:
                    note = "already a member of the vendor group policy when first seen; no expiry on record"
                else:
                    note = f"already a member of other group policies when first seen: {policy_summary(policies)}"
                store.insert_user(user, STATUS_PREEXISTING, policies, note)
                new_preexisting += 1
                log.warning(
                    "PRE-EXISTING user %s username=%s email=%s - %s. Needs a human to recertify or revoke.",
                    uid,
                    user.get("username"),
                    user.get("email_address"),
                    note,
                )

        # Users we knew about that PRA no longer returns (deleted, or moved provider).
        for uid in sorted(known_before - seen_ids):
            if store.mark_missing(uid):
                row = store.get_user(uid)
                log.warning(
                    "user %s username=%s (status %s) was not returned by PRA this poll",
                    uid,
                    row["username"] if row else "?",
                    row["status"] if row else "?",
                )

        store.finish_poll(run_id, len(seen_ids), new_pending, new_preexisting)
        log.info(
            "poll done: %s user(s) under %s, %s new pending, %s new pre-existing, %s known total",
            len(seen_ids),
            vendor.provider_name,
            new_pending,
            new_preexisting,
            len(known_before | seen_ids),
        )
    except Exception as e:  # recorded, then re-raised for the caller to decide
        store.finish_poll(run_id, len(seen_ids), new_pending, new_preexisting, error=str(e)[:2000])
        raise


# ---------------------------------------------------------------------------
# --show
# ---------------------------------------------------------------------------


def print_table(rows: List[sqlite3.Row], columns: Sequence[str]) -> None:
    if not rows:
        print("  (none)")
        return
    cells = [[("" if r[c] is None else str(r[c])) for c in columns] for r in rows]
    widths = [max(len(c), *(len(row[i]) for row in cells)) for i, c in enumerate(columns)]
    print("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns)))
    print("  " + "  ".join("-" * w for w in widths))
    for row in cells:
        print("  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def show_store(store: Store) -> None:
    print(f"Store: {store.path}\n")

    print("Vendor users")
    print_table(
        store.list_users(),
        ("pra_user_id", "username", "email_address", "status", "first_seen_at", "last_seen_at",
         "pra_missing_since", "note"),
    )

    print("\nNotifications that would have been sent")
    for n in store.list_notifications():
        print(f"  #{n['id']}  {n['created_at']}  {n['kind']}  user {n['pra_user_id']}  "
              f"-> {n['recipients'] or '(no recipients)'}  [{n['delivery']}]")
        print(f"      {n['subject']}")
    if not store.list_notifications():
        print("  (none)")

    print("\nRecent polls")
    print_table(
        store.list_polls(),
        ("id", "started_at", "finished_at", "users_seen", "new_pending", "new_preexisting", "error"),
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class Stop(Exception):
    pass


def _request_stop(signum, frame):  # noqa: ARG001 — signal handler signature
    raise Stop()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--loop", action="store_true", help="keep polling until interrupted")
    parser.add_argument(
        "--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
        help=f"seconds between polls with --loop (default {DEFAULT_INTERVAL_SECONDS})",
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="SQLite file (default: vendor_approver.db)")
    parser.add_argument("--show", action="store_true", help="print the store and exit; no PRA calls")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    store = Store(args.db)
    if args.show:
        show_store(store)
        return 0

    try:
        cfg = load_config()
    except ConfigError as e:
        log.error("config error: %s", e)
        return 2
    if cfg.vendor_security_provider_id is None:
        log.error(
            "VENDOR_SECURITY_PROVIDER_ID is not set. This loop refuses to run unscoped. "
            "Run smoke_test.py without it once to find the vendor's id, then set it in .env."
        )
        return 2
    if cfg.vendor_group_policy_id is None:
        log.warning(
            "VENDOR_GROUP_POLICY_ID is not set: pre-existing users cannot be told apart from users "
            "in some other policy, and the would-be email cannot name the policy."
        )
    if not cfg.approver_emails:
        log.warning("APPROVER_EMAILS is empty: notifications will be composed with no recipients.")

    log.info(
        "stage 2 detection, log-only. host=%s provider_id=%s policy_id=%s dry_run=%s db=%s "
        "(this stage never writes to PRA and never sends email)",
        cfg.pra_host, cfg.vendor_security_provider_id, cfg.vendor_group_policy_id, cfg.dry_run, store.path,
    )
    client = PraClient(cfg.pra_host, cfg.pra_client_id, cfg.pra_client_secret)

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    try:
        vendor = Vendor(client, cfg)
        log.info(
            "vendor: security provider %s %r, group policy %s %r",
            vendor.provider_id, vendor.provider_name, vendor.policy_id, vendor.policy_name,
        )
        while True:
            try:
                poll_once(client, store, cfg, vendor)
            except (PraApiError, requests.RequestException) as e:
                if not args.loop:
                    raise
                log.error("poll failed, will retry in %ss: %s", args.interval, e)
            if not args.loop:
                return 0
            time.sleep(max(args.interval, 5))
    except Stop:
        log.info("stopping")
        return 0
    except PraApiError as e:
        log.error("API call failed:\n%s", e)
        return 1
    except requests.RequestException as e:
        log.error(
            "network error talking to %s: %s. Check DNS, outbound 443, and the API account's "
            "Network Address Allow List.", cfg.pra_host, e,
        )
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
