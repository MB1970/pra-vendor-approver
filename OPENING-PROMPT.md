# Opening prompt for Claude Code

Paste this as your first message after running `claude` in this directory.
Do not paste it until `openapi.yaml` is sitting next to CLAUDE.md.

---

Read CLAUDE.md and openapi.yaml fully before responding. Do not write any code yet.

I want you to answer four questions from the spec, quoting exact paths, parameter names and
field names. Where the spec does not answer something, say "not in the spec" — do not fill the
gap from general knowledge about BeyondTrust or from what seems reasonable.

1. How do I list users belonging to one security provider? Give me the path, the exact filter
   parameter, and the fields that come back on each user.
2. How do I add a user to a group policy and later remove them? Give both paths and what
   identifier the remove call expects — is it the user's id or a separate membership id?
3. Is last-login or last-authentication exposed anywhere on the user object, or on any other
   endpoint in this spec? This one matters; I need a clear yes or no.
4. What exactly does the OAuth token request look like — URL, grant type, how the token is
   presented on subsequent calls?

Then tell me two things:

- Anything in CLAUDE.md that the spec contradicts. I wrote that file from documentation and a
  customer call, not from the spec, so assume parts of it are wrong.
- The smallest possible first commit: an API client that gets a token and makes one successful
  `GET /user` call against my lab, and nothing else. Describe what you would write and which
  files it would touch. Wait for my go-ahead before writing it.

---

## Follow-up prompts, in order

Use these one at a time. Let each one finish and get tested against the lab before moving on.

**2 — detection loop, log only**

> Build stage 2 from CLAUDE.md: the detection loop, log-only. Poll `GET /user` filtered to
> VENDOR_SECURITY_PROVIDER_ID, diff against a local SQLite store, and for each new user log the
> exact email that would have been sent. No emails, no writes to PRA, no UI. I want to run this
> on a cron for a day and read the log before we build anything on top of it.

**3 — approver UI and the write path**

> Build stage 3. A server-rendered pending queue at `/pending`, one row per unapproved user for
> this vendor only, with approve and deny buttons. Approve writes the group-policy membership and
> records the expiry in our store. Respect DRY_RUN: when it is true, log the exact request body and
> URL that would have been sent and show the approver a clear "dry run — nothing was changed"
> banner. Show me the write call before you wire the button to it.

**4 — expiry scheduler**

> Build stage 4. A scheduled job that emails warnings at 30, 14 and 5 days before expiry, and at
> expiry removes the group-policy membership and force-logs-out any live session. Extension resets
> the clock from the extension date, not from the original approval. Same DRY_RUN rules.

## Prompts worth keeping for later

**Before you demo it:**

> Walk the whole codebase and list every place that writes to PRA. For each one, tell me what
> human action triggers it and what happens if DRY_RUN is true. I am about to demo this against a
> customer tenant and I need to be certain nothing fires on its own.

**When something does not work:**

> Do not guess. Re-read the relevant section of openapi.yaml, tell me what the spec says the
> request should look like, and show me the request we actually sent so I can compare them.
