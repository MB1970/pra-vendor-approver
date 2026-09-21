# PRA Vendor Approver Console

Approval, per-user expiry and a vendor-scoped approver view for **federated** vendor users in
BeyondTrust Privileged Remote Access. `CLAUDE.md` is the full brief.

**Status: stage 2** — detection loop, log-only. Polls the vendor's users, keeps a local SQLite
store, and logs the approval email it *would* send. Read-only against PRA. Nothing is emailed.

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

## Stage 2: run the detection loop for a day

Set `VENDOR_SECURITY_PROVIDER_ID`, `VENDOR_GROUP_POLICY_ID` and `APPROVER_EMAILS` in `.env`,
then:

```bash
.venv/bin/python detect.py                 # one poll
.venv/bin/python detect.py --loop          # every 5 minutes until Ctrl-C
.venv/bin/python detect.py --show          # what the store holds, no PRA calls
```

To leave it running, a user-level systemd unit is the least surprising option on Ubuntu:

```ini
# ~/.config/systemd/user/pra-detect.service
[Unit]
Description=PRA vendor approver – stage 2 detection (log-only)

[Service]
WorkingDirectory=%h/pra-vendor-approver
ExecStart=%h/pra-vendor-approver/.venv/bin/python detect.py --loop --interval 300
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload && systemctl --user enable --now pra-detect
journalctl --user -u pra-detect -f
```

What each poll does:

1. `GET /security-provider/{id}` and `GET /group-policy/{id}` once per process, to name things in the log.
2. `GET /user?security_provider_id=…`, every page. The filter is applied by the appliance, not here.
3. For each user not yet in the store, `GET /user/{id}/group-policies`.
   - **No group policies** → recorded as `pending`; the approver email is composed, written to the
     `notification` table and logged in full with a `WOULD EMAIL` prefix. Not sent.
   - **Already has group policies** → recorded as `preexisting` and logged as a warning. These
     users had access before the app existed and no expiry is on record for them. A human has to
     recertify or revoke them in stage 3; the app never assumes.
4. For users already `pending`, the same call again — if someone granted a policy in the PRA
   console behind the app's back, that is logged and the status changes to `preexisting`.
5. Users the store knows but PRA stopped returning are logged once and marked `pra_missing_since`.

The store is `vendor_approver.db` next to the scripts (gitignored). Delete it to start over.

## Files

| File | Purpose |
|---|---|
| `pra_client.py` | `.env` loading and the API client. Every URL and field traces to the spec files. Read-only. |
| `smoke_test.py` | Stage 1 check. `--info` adds the API-account permission dump. |
| `detect.py` | Stage 2 detection loop. `--loop`, `--interval`, `--show`. |
| `store.py` | The app's own SQLite store: users, would-be notifications, poll runs. Stdlib only. |
| `bt-pra-*.openapi.yaml` | The three specs downloaded from the appliance. Authoritative. |
| `.env.example` | Settings template. Copy to `.env`; never commit `.env`. |
