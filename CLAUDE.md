# CLAUDE.md — PRA Vendor Approver Console

## What this is

A small internal tool that adds three things PRA does not have for **federated** vendor users:
an approval step, a per-user access expiry, and a scoped view for the person doing the approving.

It exists because of a specific customer situation. Memorial Sloan Kettering is retiring its
SecureLink appliance and moving third-party vendor access to BeyondTrust PRA. A handful of vendors
refuse to hold BeyondTrust-issued credentials — they want to authenticate their own staff through
their own identity provider, as they did with their own SecureLink appliance.

PRA has two paths and you cannot have both:

| | Vendor Groups | Federated (Pathfinder IdP) |
|---|---|---|
| Vendor's own IdP | No — local BT accounts only | **Yes** |
| Rolling N-day expiry per user | Yes | No — one fixed date for the whole policy |
| Notify an approver when someone is waiting | Yes | No |
| Approval gate before access | Yes | No |
| Auto-delete expired users | Yes | No |

These vendors need column two. **This app supplies the column-one behaviour on top of it.**

Joining the two natively is BeyondTrust idea RSPM-196, currently Backlog / "To Be Prioritised".
There is no committed release, so this app is the answer for the foreseeable future.

## Status

Greenfield. Nothing built yet. This file is the brief.

## The flow to build

1. **Detect.** Poll PRA for users belonging to a specific security provider (the vendor's IdP).
   Anyone with no group-policy membership and no local record of their own is a new arrival.
2. **Notify.** Email or Teams the designated MSK approvers for that vendor, with an approve/deny link.
   The approver never opens the PRA console.
3. **Approve.** On approve, add the user to the vendor's group policy and record an expiry date
   (default 365 days from approval) in the app's own store.
4. **Warn and revoke.** Warn at 30, 14 and 5 days. At expiry, remove the group-policy membership.
   Removing membership revokes entitlement without deleting the account — reversible, and the audit
   trail survives.
5. **Recertify.** An approver can extend a user before expiry, which resets the clock from the
   extension date.

## Non-negotiable design rules

- **Expiry data lives in this app's store, not in PRA.** PRA has nowhere to put a per-user expiry
  date on the federated path — that absence is the entire reason this app exists. If you find
  yourself trying to write an expiry back into PRA, you have misunderstood the problem. Re-read
  this section.
- **Every write to PRA requires a human action.** No scheduled job, no model, and no background
  worker writes to PRA without a person having clicked approve, extend, or revoke. The scheduled
  revoker is the one exception, and only because the human already set the date at approval time.
- **Dry-run is the default.** `DRY_RUN=true` unless explicitly overridden. In dry-run, every write
  is logged with the exact request that would have been sent, and nothing is sent. This app will be
  demoed against a customer tenant; it must be impossible to mutate one by accident.
- **Scope every query to one vendor.** The approver for Vendor A must never see users from Vendor B
  or from MSK itself. Filter server-side by security provider, not in the UI.
- **Never invent an endpoint or field.** If the spec files do not contain it, say so and stop.
  Do not guess at BeyondTrust API shapes from general knowledge — the API has product-specific
  naming that will not match your priors.

## The API

The authoritative specs are three files in this directory, downloaded from a live appliance at
**Management → API Configuration → Download the Configuration API's OpenAPI YAML file**:

| File | Version | Base path | Use |
|---|---|---|---|
| `bt-pra-configuration-v1.openapi.yaml` | 1.12 | `/api/config/v1` | Everything this app does. Start here. |
| `bt-pra-command-v2.openapi.yaml` | 2.0.0 | `/api/command/v2` | Force logout, appliance info/health. |
| `bt-pra-reporting-v2.openapi.yaml` | 2.0.0 | `/api/reporting/v2` | Duplicate Jump Clients only. Not relevant. |

All three hardcode the host they were pulled from (`pf34d701.beyondtrustcloud.com`) in their
`servers` block and token URL. Build URLs from `PRA_HOST`, never from the spec's example host.

Read the configuration spec before writing any client code. If it is missing, stop and ask for it.

Base path is `/api/config/v1/`. Auth is OAuth 2.0 client credentials against an API account created
in the same Management → API Configuration screen, with **Configuration API → Allow Access** ticked.

Endpoints expected to matter:

- `GET /user` — paginated. Filters include `security_provider_id`, `username`, `email_address`.
  Non-local users are returned **in order of first authentication**, which is a cheap way to spot
  new arrivals.
- `GET /user/{id}/group-policies` — what a user currently has.
- `GET | POST /group-policy/{id}/member` and `DELETE /group-policy/{id}/member/{member_id}` —
  **this is the membership path to use.**
- `PATCH /user/{id}` — user properties, including disable.
- `DELETE /user/{id}` — non-admin users only.
- Command API v2: `POST /user/{id}/logout` — force-ends live sessions on revoke.

### Known traps

- `PATCH /user/{id}/group-policy-changes` is documented as applying to a **local** user. Our users
  are federated. Use the `/group-policy/{id}/member` endpoints instead, and verify against the spec.
- **Last-login may not be exposed on the user object.** Check
  `bt-pra-configuration-v1.openapi.yaml` before designing anything that depends on it. If it is
  absent, say so rather than working around it silently — it changes the design and it is an open
  question we owe the customer an answer on.
- Group policies that grant administrative permissions cannot be handed out this way, and a
  delegate cannot grant the delegation permission itself. Do not build a UI that implies otherwise.
- API accounts have their own network allow-list, separate from the site-wide one under
  Management → Security.

## Stack

Choose boring and easy to hand to a customer. Python or Node, a single process, SQLite or Postgres
for the app's own store, server-rendered pages rather than a SPA. No build step if avoidable.
Justify any dependency beyond an HTTP client, a web framework, and a DB driver.

## Environment

Never commit secrets. `.env` is gitignored from the first commit.

```
PRA_HOST=            # e.g. access.example.com — no scheme, no /login
PRA_CLIENT_ID=
PRA_CLIENT_SECRET=
VENDOR_SECURITY_PROVIDER_ID=
VENDOR_GROUP_POLICY_ID=
APPROVER_EMAILS=
DEFAULT_EXPIRY_DAYS=365
DRY_RUN=true
```

## Build order

Do not skip ahead. Each stage has to work against the lab before the next one starts.

1. **Auth + one read.** OAuth token, then `GET /user` returning real users. Nothing else.
2. **Detection loop, log-only.** Poll, diff against the local store, log what it *would* have
   emailed. Run it for a day and see what it actually catches before building anything on top.
3. **Approver UI + writes.** Pending queue, approve/deny, membership write behind the dry-run flag.
4. **Expiry scheduler.** Warnings, then revocation.

## Definition of done for the demo

An MSK approver receives an email about a new vendor user, clicks through, sees **only that
vendor's** pending users, approves one, and the user gains access in PRA with an expiry date set.
The unfiltered user list that PRA's own delegation screen would have shown is never visible.
That last point is the one the customer cares about most — make it visible in the first screenshot.
