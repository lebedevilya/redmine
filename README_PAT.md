# Personal Access Tokens for the Redmine API

A slice of [Redmine #43881 — *Strengthen API authentication*](https://www.redmine.org/issues/43881),
built on tag `6.1.2`.

The ticket proposes six pillars and its author asks for a phased rollout, so this ships as two
stacked MRs — each independently reviewable and mergeable:

| MR | Branch | Target | Contents |
|----|--------|--------|----------|
| 1 | `pat/core` | `base-6.1.2` | Pillar 1 — personal access tokens (the required core) |
| 2 | `pat/scopes` | `pat/core` | Pillar 2 — per-token permission scopes |

**Pillar 3 (rate limiting) is deliberately untouched** — already implemented upstream in ticket notes
#7–#10 and steered onto Rails 7.2 `rate_limit` by a maintainer. Duplicating it would be wasted work.

---

## Run and verify

```bash
git checkout pat/scopes          # tip of the stack; pat/core for MR 1 alone
printf 'development:\n  adapter: sqlite3\n  database: db/redmine.sqlite3\ntest:\n  adapter: sqlite3\n  database: db/test.sqlite3\n' > config/database.yml
bundle install
bin/rails db:create db:migrate RAILS_ENV=development
bin/rails db:create db:migrate RAILS_ENV=test

bin/rails test test/unit/personal_access_token_test.rb \
               test/functional/personal_access_tokens_controller_test.rb \
               test/functional/admin/personal_access_tokens_controller_test.rb \
               test/integration/api_test/authentication_test.rb
```

Then `bin/rails server`, and in **My account → Personal access tokens → New** create a token (leave
scopes unchecked for full access, or tick some). The value is shown once.

```bash
curl -H "X-Redmine-API-Key: rmpat_…" localhost:3000/users/current.json   # 200
curl -u "rmpat_…:x" localhost:3000/users/current.json                    # 200
curl "localhost:3000/users/current.json?key=rmpat_…"                     # 401 + explanation
curl "localhost:3000/users/current.json?key=<legacy key>"                # 200 — unchanged
```

Revoke it in the UI and the first call returns 401. With a scoped token, an out-of-scope endpoint
returns 403. Admins get **Administration → Personal access tokens** and a max-lifetime setting under
**Settings → API**.

---

## How the PAT core works

`rmpat_` + 64 hex chars (256 bits from `Redmine::Utils.random_hex`). Only the SHA256 digest is stored,
plus the last four characters for display. The plaintext appears in exactly one HTTP response and is
never persisted, logged, or shown again. Each token has a name, **mandatory** expiry, optional scopes,
last-used and revoked timestamps. `Redmine::ApiAuthentication` resolves a credential, trying a token
first and falling back to the legacy API key. Creation and revocation email the owner, following the
`EmailAddress` security-notification convention — carrying the token's *name*, never its value.

**Why unsalted SHA256.** Verification must be one indexed lookup on the digest. A salted or adaptive
hash can't be looked up by value, so every authenticated request would scan the table. That's safe
here and wouldn't be for a password: the input is 256 bits of CSPRNG output, so there's no dictionary
to attack and no work factor worth buying. `secure_compare` is still used, as defence in depth rather
than the primary check.

**Why a separate model, not `Token`.** Every PAT requirement collides with something `Token` enforces:
`before_create` overwrites `value`, `delete_previous_tokens` caps the `api` action at one instance,
expiry is per-action not per-row, and the lookup regex rejects the `rmpat_` prefix. Hashing settles
it — a digest can't live in a column other code `secure_compare`s against plaintext. Reuse would mean
fighting two callbacks and the sweeper on a table also holding `session`, `autologin` and
`twofa_backup_code` rows, where a bug logs everyone out. As a result `Token`, `User#api_key` and
`User.find_by_api_key` are **byte-for-byte unmodified**, so backward compatibility is structural
rather than asserted — with a regression test proving a legacy key still authenticates.

**Why tokens are refused in the query string.** URLs are captured by proxy access logs, browser
history and `Referer`; `config.filter_parameters` reaches none of that. The compatibility cost is zero
because the credential type is new — nothing deployed can be sending a PAT in a URL. Legacy keys keep
working in `?key=`, with a test pinning it. Rather than a bare 401 (which reads as "my token is
broken"), the response names the correct channels, matching on prefix shape only, never touching the
database, and never echoing the token. This does **not** fix credential-in-URL leakage generally —
legacy keys still leak that way, which is pre-existing Redmine behaviour.

## Scopes (MR 2)

**No new authorization code.** Redmine already has scope filtering for OAuth2 — a `User` carries a
scope array and `Role#allowed_to?` intersects role permissions with it. A scoped token sets the same
value, using the same permission-name vocabulary Doorkeeper exposes. Scopes only ever *restrict*;
selecting a permission your roles lack yields an empty intersection, never an escalation.

Three subtleties, each with a test pinning it:

- The field was renamed `oauth_scope` → `api_scope` (aliases retained) in its own pure-rename commit,
  since `authorized_by_oauth?` would otherwise lie about a non-OAuth credential.
- **An empty scope array fails open** — `[].present?` is false, so the intersection is skipped and
  *every* permission is returned, while `authorized_by_api_scope?` is true and strips admin. Only a
  non-empty scope counts as scoped.
- **Scopes must be symbols**, and the coercion lives in the model. `Array#&` against symbols means
  string scopes deny everything; worse, the serializer only reads YAML symbol syntax, so assigning
  strings round-trips to `[]` — which reads as *unscoped* and grants **full** permissions. Form params
  are always strings, so a `scopes=` writer coerces them, mirroring `Role#permissions=`.

## Relation to the built-in OAuth2 provider

Redmine 6.1 ships Doorkeeper, so this is a fair question. OAuth2 serves *third-party applications* —
authorization-code flow, consent screen, registered client. PATs serve *scripts, CI and personal
automation*, where there's no browser to redirect and no human to consent. Complementary, and this
deliberately reuses OAuth's scope machinery rather than duplicating it.

---

## Limits of the approach

**PATs do not close the 2FA bypass the ticket opens with.** Precisely:

- **No gain at issuance** — both credential types are minted through a 2FA-protected session.
- **The real gain is mandatory expiry**, forcing periodic re-issuance, so the holder re-passes 2FA on
  a cycle. A key minted in 2019 never does.
- **Revocation granularity** — one token dies without breaking every other integration.
- **Least privilege arrives only with MR 2.** With MR 1 alone a token inherits every permission its
  owner has.
- **Residual risk:** within its window a token is still a single-factor bearer credential.

Other limits: `X-Redmine-Switch-User` loads a fresh `User` without the scope, so impersonation acts
unscoped (Redmine does the same for OAuth — inherited, not introduced). `last_used_at` is written at
most hourly via `update_column`, trading precision for bounded write amplification. The max-lifetime
policy re-validates on update, so lowering it blocks edits to previously valid tokens.

## Assumptions

- **SQLite for development and test.** Nothing here is database-specific; it should run on
  PostgreSQL or MySQL unchanged.
- **Any logged-in user may create tokens.** Ticket note #3 asks to restrict this per user, but
  Redmine's permission system is project-scoped, so a global "may create tokens" permission needs a
  new concept — deferred rather than improvised.
- **Token format and length are mine, not the ticket's.** `rmpat_` + 256 bits: the prefix makes tokens
  greppable by secret scanners and cheap to reject before a DB hit.
- **365-day default maximum lifetime**, administrator-configurable, `0` meaning unlimited.
- **Legacy API keys stay indefinitely.** The ticket proposes a deprecation timeline; that needs
  maintainer agreement that doesn't exist yet.
- **This is shaped as an upstream patch, not a plugin** — core conventions, core test layout, existing
  helpers reused rather than reimplemented.
- **Scopes reuse the OAuth ivar deliberately.** The alternative was a parallel permission path; that
  would duplicate tested core logic.

## What is left to implement

| Pillar / item | Why not now |
|---|---|
| **Pillar 4 — audit logging** | Designed and costed, then cut in favour of finishing two pillars properly. Notes below. |
| **Pillar 5 — endpoint control** | Needs its own mechanism rather than riding on the scope model; a parallel system isn't worth the value |
| **Pillar 6 — CORS** | Cheapest pillar but weakest fit — a browser-origin policy, not token authentication. Dropped rather than included as padding |
| Per-project token restriction | Join table plus a second enforcement point; the obvious next increment for scopes |
| Per-user gate on token creation (note #3) | Needs a global-permission concept in a project-scoped system |
| Legacy key deprecation | Proposed by the ticket, but needs maintainer guidance |
| Pillar 3 — rate limiting | Out of scope by instruction; already implemented upstream |

**Pillar 4, for whoever picks it up.** A row per API request is unbounded — ~86k rows/day at 1 req/s,
~31M/year, 5–10 GB with indexes. Plan: log only writes and auth failures by default (successful GETs
dominate traffic and carry least signal); 90-day retention pruned in batches from a cron rake task,
following the `redmine:send_reminders` precedent; store `controller#action` not full URLs; never log
bodies, params or token values — only the token id. The sharp problem is that **auth failures are
attacker-controlled**, so logging each one builds a log-flooding DoS into a security feature, and rate
limiting is out of scope by instruction — collapse repeated failures to one row per IP per minute with
an occurrences counter, plus an `(ip, created_at)` index so that lookup doesn't scan. Rejected:
partitioning (Postgres-only DDL fails the portability bar), daily rollups (scope creep), async writes
(no default worker; ActiveJob `:async` drops work on restart, and a lost audit record is worse than an
inline insert). Worth adding if built: a token arriving via `?key=` is already in someone's proxy
logs, so it deserves an audit row in its own right.

---

## Testing

Unit tests for model invariants, functional for authorization, integration for the authentication
path — the last because it's the only place "it works" can be shown end-to-end rather than inferred.
**64 test methods across 7 files.** Full Redmine suite green: `5557 runs, 24936 assertions, 0
failures`, with one pre-existing environmental error unrelated to this diff (Gantt PNG export, missing
ImageMagick font). RuboCop clean; migrations apply cleanly to an empty database.

Five tests exist to catch silent failures and shouldn't be weakened: a legacy key still authenticates;
a legacy key still works via `?key=`; an empty scope array doesn't grant full permissions; a scoped
token is accepted on an **in**-scope endpoint (an out-of-scope-only test passes straight over the
strings-vs-symbols bug); and the admin panel never renders a token value — that last one originally
asserted the absence of a CSS selector the view never emitted, so it would have passed while leaking
secrets. It now asserts both directions, verified by deliberately making the view leak.

## AI workflow

Built with **Claude Code** (Opus): research → written spec → implementation plan → task-by-task
execution, with a fresh reviewer agent after each task and a fix loop for whatever it found. Unedited
transcripts, including the subagent sessions, are supplied separately.

The review loop caught three fail-opens the tests as written would not have: string scopes minting
full-access tokens (found and reproduced one task before the scope form would have made it live); a
security test that could not fail; and an unsatisfiable instruction in my own plan (add a link to the
admin index — that view is menu-driven, so the link would never have reached the sidebar).

Two decisions changed during implementation and are documented above rather than quietly reversed:
refusing tokens in the query string, and cutting pillar 4.
