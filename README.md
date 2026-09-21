# PRA Vendor Approver Console

Approval, per-user expiry and a vendor-scoped approver view for **federated** vendor users in
BeyondTrust Privileged Remote Access. `CLAUDE.md` is the full brief.

**Status: stage 1** — OAuth token plus one `GET /user`. Read-only. Nothing writes to PRA yet.

## Requirements

- Python 3.9 or newer. Ubuntu 22.04 ships 3.10; `venv` is a separate package there.
- An API account on the PRA appliance (**Management → API Configuration**) with
  **Configuration API → Allow Access** ticked. `--info` additionally needs Command API access
  (read-only is enough).
- The public IP of the host running this on the API account's **Network Address Allow List**.
  That list is per API account and separate from the site-wide one under Management → Security.

## Deploy on the Linux host

```bash
sudo apt install -y python3-venv
git clone git@github.com:<owner>/pra-vendor-approver.git
cd pra-vendor-approver
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env && chmod 600 .env
"${EDITOR:-nano}" .env          # PRA_HOST, PRA_CLIENT_ID, PRA_CLIENT_SECRET at minimum
.venv/bin/python smoke_test.py --info
```

## What success looks like

```
POST https://access.example.com/oauth2/token
  token OK (expires_in=3600s)

GET https://access.example.com/api/command/v2/info
  product:               pra
  ...
  permissions:
    perm_configuration                       True
    ...

GET https://access.example.com/api/config/v1/user?per_page=100&current_page=1&security_provider_id=7
  HTTP 200 — 3 user(s) on this page, 3 total, 1 page(s)

id   security_provider_id  username        email_address        enabled  created_at                 last_authentication
---  --------------------  --------------  -------------------  -------  -------------------------  -------------------------
...
```

If `VENDOR_SECURITY_PROVIDER_ID` is blank the run is unscoped and lists every user; the
`security_provider_id` column tells you which id to set. Later stages refuse to run unscoped.

## Files

| File | Purpose |
|---|---|
| `pra_client.py` | `.env` loading and the API client. Every URL and field traces to the spec files. |
| `smoke_test.py` | Stage 1 check. `--info` adds the API-account permission dump. |
| `bt-pra-*.openapi.yaml` | The three specs downloaded from the appliance. Authoritative. |
| `.env.example` | Settings template. Copy to `.env`; never commit `.env`. |
