# Personal Access Tokens for the Redmine API

An implementation slice of Redmine feature request
[#43881 — *Strengthen API authentication*](https://www.redmine.org/issues/43881), built on tag
`6.1.2`.

The ticket proposes six pillars and its author explicitly asks for a phased rollout. This submission
ships the first two, as a stack of two merge requests:

| MR | Branch | Target | Contents |
|----|--------|--------|----------|
| 1 | `pat/core` | `base-6.1.2` | **Pillar 1 — personal access tokens** (the ticket's required core) |
| 2 | `pat/scopes` | `pat/core` | **Pillar 2 — per-token permission scopes** |

Each MR is independently reviewable and independently mergeable: MR 1 alone is a complete, coherent
feature. Splitting this way is a direct answer to the ticket, where the author proposes phasing and is
still waiting on maintainer guidance about it — not merely a convenience for review.

**Pillar 3 (rate limiting) is deliberately untouched.** It is already implemented upstream: Iurii
Dremov posted a working patch against 6.1.2 in notes #7–#10 of the ticket, and Marius BĂLTEANU steered
it onto Rails 7.2's native `rate_limit`. Duplicating that would be wasted work and a merge conflict.

Pillars 4, 5 and 6 are deferred with reasons — see [What is deferred](#what-is-deferred).

---

## How to run and verify

```bash
git clone <this repo> && cd redmine
git checkout pat/scopes            # tip of the stack; use pat/core for MR 1 alone

cat > config/database.yml <<'YAML'
development:
  adapter: sqlite3
  database: db/redmine.sqlite3
test:
  adapter: sqlite3
  database: db/test.sqlite3
YAML

bundle install
bin/rails db:create db:migrate RAILS_ENV=development
bin/rails db:create db:migrate RAILS_ENV=test
```

Run the tests that cover this work:

```bash
bin/rails test test/unit/personal_access_token_test.rb \
               test/functional/personal_access_tokens_controller_test.rb \
               test/functional/admin/personal_access_tokens_controller_test.rb \
               test/integration/api_test/authentication_test.rb
```

Then verify by hand:

```bash
bin/rails server
```

1. Log in, go to **My account → Personal access tokens → New**.
2. Give it a name and an expiry. Leave every scope unchecked for a full-permission token, or tick
   some (there is a *Select read-only permissions* preset).
3. Copy the value. **This is the only time it is ever shown.**

```bash
# Works — header
curl -H "X-Redmine-API-Key: rmpat_…" http://localhost:3000/users/current.json

# Works — HTTP Basic username slot
curl -u "rmpat_…:x" http://localhost:3000/users/current.json

# Refused, with an explanation — query string (see "Refused in the query string")
curl "http://localhost:3000/users/current.json?key=rmpat_…"

# Still works — the legacy API key is unchanged, including in the query string
curl "http://localhost:3000/users/current.json?key=<your legacy API key>"
```

Revoke the token in the UI, re-run the first command, and observe `401`. With a scoped token, an
endpoint outside the scope returns `403`.

Administrators get **Administration → Personal access tokens** (every user's tokens, with revoke) and
a maximum-token-lifetime policy under **Administration → Settings → API**.

---

## How it works

A token is `rmpat_` followed by 64 hex characters — 256 bits from `Redmine::Utils.random_hex(32)`.
Only its SHA256 digest is stored, alongside the last four characters so the UI can show
`rmpat_…a1b2` in a list. The plaintext exists in exactly one HTTP response and is never persisted,
logged, or displayed again.

Each token carries a name, a **mandatory** expiry date, an optional scope list, a last-used timestamp,
and a revocation timestamp. Authentication resolves a presented credential in
`Redmine::ApiAuthentication`, which tries a personal access token first and falls back to the legacy
API key path.

Redmine mails the token's owner when a token is created or revoked, following the same
`deliver_security_notification` convention `EmailAddress` uses for other security-sensitive account
changes. The mail carries the token's **name**, never its value.

### Why unsalted SHA256

This is the decision most likely to be misread as a mistake, so it is deliberate and worth stating
plainly.

Verification has to be a single indexed lookup:

```ruby
PersonalAccessToken.find_by(:token_hash => Digest::SHA256.hexdigest(presented))
```

A salted or adaptive hash (bcrypt, argon2) cannot be looked up by value — you would have to load
candidate rows and compare one at a time, i.e. a table scan on every authenticated API request.

That is safe *here*, and would not be safe for a password, because the input is 256 bits of CSPRNG
output rather than a human-chosen secret. There is no dictionary to attack and no plausible brute
force, so the work factor an adaptive hash exists to provide buys nothing. The ticket specifies SHA256
for the same reason.

The digest comparison still runs through `ActiveSupport::SecurityUtils.secure_compare`. That is
defence in depth rather than the primary check — the row was fetched *by* that digest, so equality
already holds — and it is kept to mirror `Token.find_token` and to stay correct if the lookup is ever
loosened.

### Why a new model instead of extending `Token`

Redmine already has a `Token` model with an `api` action, so reusing it looks like the smaller change.
It is not. Every core requirement of a personal access token collides with a behaviour `Token`
actively enforces:

| Requirement | What `Token` does at 6.1.2 |
|---|---|
| Store a digest we compute | `before_create :generate_new_token` unconditionally overwrites `value` |
| Many named tokens per user | `before_create :delete_previous_tokens` plus `max_instances: 1` for the `api` action |
| Per-token expiry | Expiry is per-*action*, derived from `created_on` and a class-level registry; no per-row column exists |
| A prefixed value | `find_token` guards with `/\A[a-z0-9]+\z/i` — underscores are rejected |

Hashing alone settles it: a digest cannot live in a column that other code `secure_compare`s against
plaintext. Reuse would mean defeating two `before_create` callbacks, abandoning the expiry design,
bypassing the shared lookup, and special-casing `Token.destroy_expired` — on a table that also carries
`session`, `autologin`, `feeds`, `recovery`, `register` and `twofa_backup_code` rows. A bug there logs
everyone out or breaks two-factor recovery, which is the worst possible blast radius for a security
patch.

A separate model also makes **backward compatibility a fact rather than a claim**: `Token`,
`User#api_key` and `User.find_by_api_key` are byte-for-byte unmodified across this entire branch. The
legacy path cannot regress because it was never edited, and a regression test proves a legacy key
still authenticates.

This is also the idiomatic choice rather than merely a tolerable one. `EmailAddress` is the near-exact
structural precedent — a user-owned 1:N, security-sensitive record, extracted to its own table and
managed from *My account* — and this feature mirrors its file layout, its `safe_attributes` usage, and
its security-notification callbacks.

### Refused in the query string

Redmine accepts an API credential three ways: the `X-Redmine-API-Key` header, the HTTP Basic username
slot, and a `key` query parameter. **Personal access tokens are accepted on the first two only.**

A credential in a URL is recorded far outside the application's control — reverse-proxy and
load-balancer access logs capture the full query string, browsers retain it in history, and it can
escape to third parties via the `Referer` header. Rails' `config.filter_parameters` scrubs only Rails'
own log file and reaches none of that, so filtering would be mitigation theatre rather than a fix.
GitHub and GitLab both withdrew query-string token support for these reasons.

The compatibility cost is zero, and that is the crux: the restriction applies solely to a credential
type that **did not exist before this change**, so no deployed client can be sending one in a URL
today. The legacy API key keeps working in all three positions including `?key=`, with a regression
test pinning it. Redmine's Atom feed keys — the one legitimate URL-borne credential — use a separate
token action and a separate code path and are untouched.

A bare 401 would be the wrong failure mode: the user concludes the token is broken, rotates it,
retries, and files a bug. A personal access token is self-identifying by its `rmpat_` prefix, so the
response names the correct channels instead. That check matches on **prefix shape only and never
touches the database** — this path is reachable by unauthenticated callers — and it never echoes the
presented token.

**This does not fix credential-in-URL leakage generally.** Legacy keys still leak that way. That is
pre-existing Redmine behaviour and out of scope here.

The genuinely excluded population is clients that can set *neither* a custom header *nor* HTTP Basic —
browser address bars, URL-only webhook configuration. Anything that can do `curl -u` adopts tokens
unchanged.

---

## Scopes (MR 2)

A token may be restricted to a subset of its owner's permissions. Unscoped tokens behave exactly like
a legacy API key.

**No new authorization code was written.** Redmine already ships a complete, tested scope-filtering
mechanism built for its OAuth2 provider: a `User` carries a scope array, and `Role#allowed_to?`
intersects role permissions with it. A scoped token sets that same value, so scopes are persistence
and UI rather than a parallel permission system. Scopes are stored as Redmine permission names — the
same vocabulary Doorkeeper exposes — so a token scope means precisely what an OAuth scope means.

Three things about this were subtle enough to be worth recording.

**The field was renamed first, in its own commit.** The attribute was called `oauth_scope`, and
`authorized_by_oauth?` would have started returning true for a credential that has nothing to do with
OAuth. It is now `api_scope` / `authorized_by_api_scope?`, with `oauth_scope=` and
`authorized_by_oauth?` retained as aliases. That commit is a pure rename so that any behavioural
regression would be unambiguous; Redmine's pre-existing OAuth scope tests are untouched and still
exercise the aliased path.

**An empty scope array fails open, so it is never assigned.** In `Role#allowed_permissions`,
`[].present?` is false, which makes the intersection get skipped and returns *every* permission — while
`authorized_by_api_scope?` is `!nil?`, which is true for `[]` and therefore strips admin. The net
effect of an empty array would be a token de-admin'd at the admin check and granted full permissions
at the role check. Only a non-empty scope counts as scoped, and there is a test pinning the empty case
so a future refactor that "helpfully" defaults the column to `[]` fails loudly instead of silently
granting everything.

**Scopes must be symbols, and the coercion lives in the model.** `Role#allowed_permissions` intersects
with `Array#&` against symbols, so string scopes would produce an empty intersection and deny the token
everything — silently. Worse, because the serializer only recognises YAML symbol syntax, assigning
strings round-trips to `[]`, which reads as *unscoped* and therefore grants **full** permissions. Since
form parameters are always strings, a `scopes=` writer coerces them in the model, mirroring core's own
`Role#permissions=`. Sanitising in the controller instead would have left the model unsafe for every
other caller.

The scope picker groups permissions by module and derives its read-only preset from each permission's
own `read?` flag rather than a hand-maintained list, so it cannot drift as Redmine adds permissions.

Scopes only ever **restrict**. Selecting a permission the user's roles do not grant yields an empty
intersection for that permission, never an escalation.

---

## How this relates to the OAuth2 provider

Redmine 6.1 already ships a Doorkeeper-based OAuth2 provider, so it is fair to ask why this is not
redundant.

They serve different callers. **OAuth2 is for third-party applications**: authorization-code flow,
a consent screen, a registered client. **Personal access tokens are for scripts, CI jobs and personal
automation**, where there is no browser to redirect, no human to consent, and no application to
register. Asking a cron job to complete an authorization-code flow is not a reasonable answer.

They are complementary, and this implementation deliberately reuses OAuth's scope machinery rather
than duplicating it.

---

## Limits and residual risk

**Personal access tokens do not close the 2FA bypass the ticket opens with.** This is the claim most
worth stating precisely rather than overselling.

- **No gain at issuance.** Both a legacy key and a token are minted through a 2FA-protected web
  session. Issuance is exactly as protected as before.
- **The real gain is mandatory expiry**, which forces periodic re-issuance, so the holder passes 2FA
  again on a fixed cycle. A legacy key minted once in 2019 never re-authenticates.
- **Also real: revocation granularity.** One named token can be revoked without breaking every other
  integration; today, resetting the single API key breaks all of them at once.
- **Least privilege arrives only with MR 2.** With MR 1 alone, a token inherits every permission its
  owner has, exactly like a legacy key.
- **Residual risk:** within its validity window a token is still a single-factor bearer credential.
  Closing the bypass properly needs step-up authentication on token use, or an administrator policy
  that disables legacy keys outright — both out of scope here.

**`X-Redmine-Switch-User` drops the scope.** An administrator impersonating another user gets a freshly
loaded `User` without the scope applied, so a scoped admin token acts unscoped as the target user.
Redmine behaves identically for OAuth, so this is inherited rather than introduced, but it is reachable
by a second credential type now and should be fixed in the shared code path rather than here.

**`last_used_at` is approximate by design.** Writing it on every request would mean a database write
per API call. It is updated at most once per hour per token via `update_column`, trading precision for
bounded write amplification.

**The maximum-lifetime policy re-validates on update**, so lowering it blocks edits to previously valid
tokens. Arguably correct for a tightening policy, but it is a behaviour rather than an accident.

---

## What is deferred

| Item | Why |
|---|---|
| **Pillar 3 — rate limiting** | Out of scope by instruction, and already implemented upstream (ticket notes #7–#10) |
| **Pillar 4 — audit logging** | Designed and costed, not built. See below. |
| **Pillar 5 — endpoint control** | Would need its own mechanism rather than riding on the scope model; a parallel system is not worth it for the value |
| **Pillar 6 — CORS** | The cheapest pillar, but the weakest fit — it is a browser-origin policy, not token authentication. Evaluated and consciously dropped rather than included as padding |
| **Per-project token restriction** | A join table plus a second enforcement point; the obvious next increment for scopes |
| **Per-user gate on token creation** (ticket note #3) | Redmine's permission system is project-scoped, so a global "may create tokens" permission needs a genuinely new concept — larger than it looks |
| **Legacy key deprecation** | The ticket proposes a timeline but this needs maintainer guidance that does not exist yet |

### Pillar 4 was designed before it was dropped

Audit logging was fully specified and then cut in favour of finishing two pillars properly rather than
three partially. The design is recorded here because the reasoning is the useful part:

A row per API request is unbounded growth — roughly 86k rows/day at one request per second, ~31M/year,
5–10 GB with indexes. The plan was four levers: log only writes and authentication failures by default
(successful `GET`s dominate traffic and carry the least security signal); a 90-day retention window
pruned in batches from a cron-driven rake task, following the `redmine:send_reminders` precedent;
`controller#action` rather than full URLs for bounded cardinality; and never logging request bodies,
parameters, or token values — only the token id.

The sharpest problem was that **authentication failures are attacker-controlled**. Logging every failed
attempt turns a security feature into a log-flooding denial of service, and the obvious counter — rate
limiting — is out of scope by instruction. The answer was to collapse repeated failures to one row per
source IP per minute with an occurrences counter, plus an `(ip, created_at)` index so that lookup does
not table-scan on the attacker-controlled path.

Three alternatives were considered and rejected: table partitioning (Postgres-specific DDL fails the
portability bar for a project supporting PostgreSQL, MySQL and SQLite), daily rollup counters (genuinely
good, but scope creep here), and asynchronous writes (Redmine ships no configured background worker, and
ActiveJob's `:async` adapter drops queued work on restart — a lost audit record is worse than an inline
insert).

One idea worth carrying forward if it is ever built: a token arriving via `?key=` is already in
somebody's proxy logs, so it arguably deserves an audit row as a security event in its own right.

---

## Testing

Test level was a judgement call, so here is the reasoning: **unit tests for model invariants,
functional tests for authorization, and integration tests for the authentication path**, on the
grounds that the authentication path is the only place where "it works" can be demonstrated
end-to-end rather than inferred.

This branch adds **64 test methods** across 7 files. Redmine's full suite runs green against it —
`5557 runs, 24936 assertions, 0 failures` — with one pre-existing environmental error unrelated to
this work (`GanttsControllerTest#test_gantt_should_export_to_png`, a missing ImageMagick font; none of
the Gantt files appear in this diff). RuboCop reports no offenses across the 15 changed Ruby files, and
all migrations apply cleanly to an empty database.

Five tests exist specifically to catch silent failures and should not be weakened:

| Test | What it prevents |
|---|---|
| a legacy API key still authenticates | the backward-compatibility guarantee |
| a legacy API key still works via `?key=` | proves only the new credential type was restricted |
| an empty scope array does not grant full permissions | the fail-open in `Role#allowed_permissions` |
| a scoped token is accepted on an **in**-scope endpoint | catches the strings-vs-symbols bug, which an out-of-scope-only test passes straight over |
| the admin panel never renders a token value | an earlier version of this test asserted the absence of a CSS selector the view never emitted, so it would have passed even while leaking secrets |

That last one is worth dwelling on: it was rewritten to assert both that the masked value is present
*and* that the raw plaintext is absent, then verified by deliberately making the view leak and
confirming the test went red.

---

## AI workflow

Built with **Claude Code** (Opus), using a plan-then-execute workflow: research and design first, a
written spec, an implementation plan, then task-by-task execution with a fresh reviewer agent after
each task and a fix loop for anything it found. Unedited transcripts are included as a separate
artifact.

The review loop earned its place three times, each catching a fail-open that the tests as written
would not have:

1. **String scopes minting full-access tokens.** Reviewed, reproduced directly against the database,
   and fixed one task before the scope form would have made it live.
2. **A security test that could not fail.** The admin-panel test asserted the absence of a selector
   the view never emitted.
3. **An unsatisfiable instruction in my own plan.** It said to add a link to the admin index view; that
   view is menu-driven, so the link would have been an unstyled orphan that never reached the sidebar.
   The implementing agent flagged it rather than shipping it.

Two decisions changed materially during implementation and are documented above rather than quietly
reversed: refusing tokens in the query string (originally the plan accepted all three channels), and
dropping pillar 4 to finish two pillars properly.
