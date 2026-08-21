# Envelope

Self-hosted, API-first, multi-tenant email platform, built on the
[Goose framework](https://github.com/awesome-goose/goose).

See [docs/PITCH.md](docs/PITCH.md), [docs/PRD.md](docs/PRD.md),
[docs/TRD.md](docs/TRD.md) for product/technical context,
[docs/ENVELOPE.md](docs/ENVELOPE.md) for the phased implementation plan
this repository follows, and [docs/RUNBOOK.md](docs/RUNBOOK.md) for
on-call operations.

## Development

Requires a Postgres instance (every Postgres-backed component — Directory,
storage, queue — shares one connection, see `internal/db`):

```bash
docker run --rm -d --name envelope-postgres \
  -e POSTGRES_USER=envelope -e POSTGRES_PASSWORD=envelope -e POSTGRES_DB=envelope \
  -p 5432:5432 postgres:16

cp .env.example .env
cp config/config.example.yaml config/config.yaml

# Required (TRD R1/NFR-SEC-3) — encrypts DKIM keys and webhook secrets at
# rest; the process won't boot without it. Put the output in .env as
# ENVELOPE_MASTER_KEY.
openssl rand -base64 32

# Standard ports (25/587/993) need root/CAP_NET_BIND_SERVICE; override to
# unprivileged ports in .env for local dev — see .env.example.
go run ./cmd/envelope
curl localhost:8080/health
```

Every management API request requires a bearer token (FR-5.2) —
`curl localhost:8080/vhosts` alone now 401s. If `ENVELOPE_API_ADMIN_TOKEN`
isn't set, a one-time admin token is generated and printed to the log on
boot; use it to create an account (`POST /accounts`, FR-1.6), which
auto-issues that account's first token in the same response. From there
everything is self-serve with the account's own token — no further admin
involvement: `POST /accounts/:accountId/vhosts` to create a vhost,
`POST /accounts/:accountId/tokens` to mint further tokens, and
`POST /accounts/:accountId/messages` (FR-3.8) to send email directly via
REST as an alternative to SMTP submission (to/cc/bcc, HTML+text,
attachments, custom headers — DKIM-signed and queued the same way a
submitted message is). See `internal/api`'s package for the full surface,
including `PATCH /vhosts/:id/policy` (retention window and the rest of
FR-1.2's policy), `GET /vhosts/:id/export` / `DELETE /vhosts/:id/data`
(NFR-COMP-2's data export/erasure), and
`POST /vhosts/:vhostId/webhooks/:id/attempts/:eventId/redrive` (manually
retry a dead-lettered webhook event, `internal/webhook.Dispatcher.Redrive`
— 503s if this deployment never wired a Dispatcher into the API). A
dedicated per-client-IP API rate limit (NFR-SEC-4, distinct from the token
check above) applies when a reverse proxy in front of the process sets
`X-Forwarded-For` — see `internal/api.RateLimitPolicy`'s doc. Every list
endpoint (`GET /vhosts`, `.../mailboxes`, `.../webhooks`, `.../tokens`,
`.../webhooks/:id/attempts`, `.../audit-log`, `GET /accounts`) is
cursor-paginated (FR-5.4) via `?cursor=&limit=` query params, with
`meta.nextCursor` in the response pointing at the next page.

Every process logs structured JSON to stdout (`ENVELOPE_LOG_LEVEL`,
NFR-OBS-2), with a `correlation_id` attribute shared across one
message's lifecycle even as it crosses role/replica boundaries (inbound
→ filter → storage → webhook, or submission → queue → deliverer →
webhook).

If port 5432 is already taken by another local Postgres (Homebrew's
`postgres` service is a common culprit — `lsof -nP -iTCP:5432 -sTCP:LISTEN`
will show it), map the container to a different host port instead (e.g.
`-p 5433:5432`) and point `ENVELOPE_DB_PORT`/`ENVELOPE_TEST_POSTGRES_DSN`
at it — connecting to the wrong Postgres silently (rather than failing to
connect at all) is easy to miss otherwise.

`--roles` selects which subset of roles a process runs (`api`,
`smtp-inbound`, `smtp-submission`, `imap`, `deliverer` — all five by
default). Webhook dispatch (`internal/webhook.Dispatcher.Run`) isn't its
own `--roles` value — it runs as an extra background instance bundled
into `api` (TRD §4 role 5: "API...+ webhook dispatch"), so scaling `api`
replicas scales webhook delivery capacity with it:

```bash
go run ./cmd/envelope --roles=api
```

`--rotate-master-key=<new-base64-key>` is a separate, one-shot maintenance
mode (not a role): re-encrypts every DKIM key and webhook secret from
`ENVELOPE_MASTER_KEY` to the given key, then exits — every other process
against that database must be stopped first. See `docs/RUNBOOK.md` §4.7
for the full procedure.

TLS for smtp-inbound/smtp-submission/imap defaults to a self-signed
dev certificate (`internal/platform.SelfSignedTLSConfig`). Set
`ENVELOPE_ACME_EMAIL` to switch to real, automatically-issued Let's
Encrypt certificates instead (FR-1.3, `internal/acme` +
`caddyserver/certmagic`) — issued on demand per active vhost domain, not
for arbitrary SNI. Needs a real registrable domain with public DNS and
port 80 reachable from the internet (HTTP-01 challenge); not meaningful
for local dev, which is why self-signed stays the default.

Inbound mail's spam-score signal comes from an rspamd sidecar
(`ENVELOPE_RSPAMD_URL`, see `.env.example`) — not required for local dev:
FR-2.6 fails open when it's unreachable, quarantining rather than
blocking mail (`internal/filter`, `docs/ENVELOPE.md` Phase 4).

Outbound delivery (`--roles=deliverer`, `internal/deliverer`) does real
MX lookups against real DNS and connects to real remote MTAs — no sidecar
or stub involved, so sending to a real domain from local dev really
attempts real internet delivery. `internal/deliverer`'s own test suite
covers the retry/bounce/concurrency logic against a local fake MTA
instead, for fully offline, deterministic testing (`docs/ENVELOPE.md`
Phase 5).

Every process exposes Prometheus metrics at `:9090/metrics`
(`ENVELOPE_METRICS_ADDR`, NFR-OBS-1) regardless of `--roles` — the
`envelope_*` set named in `docs/TRD.md` §6.5.

### Tests

Most packages run with no external dependencies — including
`internal/deliverer`'s and `internal/webhook`'s retry/backoff/dead-letter
logic, which run against a real local `go-smtp`/`net/http` server
standing in for the remote MTA/tenant endpoint, not a mock, but still
fully offline. Postgres-backed tests (`internal/directory`,
`internal/queue`, `internal/webhook`'s Postgres-store variants,
`internal/storage/postgres`, `internal/api`, plus a couple in
`internal/platform/smtp`) skip themselves unless
`ENVELOPE_TEST_POSTGRES_DSN` is set:

```bash
ENVELOPE_TEST_POSTGRES_DSN="host=127.0.0.1 user=envelope password=envelope dbname=envelope port=5432 sslmode=disable" \
  go test ./...
```

Scale tests (`internal/directory`'s `TestScaleTo100kVhosts`, TRD §6.1, and
`internal/storage/postgres`'s `TestScaleMessageBodyVolume`, TRD R3) bulk-
insert 100k+ rows / several GB of message bodies and are gated behind an
additional `ENVELOPE_RUN_SCALE_TESTS=1`, on top of the Postgres DSN above —
opt in explicitly when re-validating at scale, since every normal
`go test ./...` run shouldn't pay for it. `internal/directory`'s
`TestRotateDKIMKeys` and `internal/webhook`'s `TestPostgresRotateSecrets`
exercise `--rotate-master-key`'s underlying logic; the former is gated
behind `ENVELOPE_RUN_DESTRUCTIVE_TESTS=1` (it rewrites rows in place across
the whole shared `dkim_keys` table, unlike every other test in this repo —
see that test's doc), the latter needs no such gate since its own table is
truncated per test.

CI (`.github/workflows/ci.yml`) also runs `govulncheck` and Trivy
(against the actual built `deploy/docker/Dockerfile` image, not just the
source tree) on every push — see `docs/TRD.md` §10 R5 and
`docs/ENVELOPE.md` Phase 6 for what those have already caught here.

## Docker

Also needs Postgres reachable from the container. `host.docker.internal`
resolves to the host machine on Docker Desktop (Mac/Windows); on native
Linux Docker, add `--add-host=host.docker.internal:host-gateway` or point
`ENVELOPE_DB_HOST` at a proper Postgres service instead:

```bash
docker build -f deploy/docker/Dockerfile -t envelope .
docker run --rm -p 8080:8080 \
  -e ENVELOPE_DB_HOST=host.docker.internal -e ENVELOPE_DB_PORT=5432 -e ENVELOPE_DB_PASSWORD=envelope \
  -e ENVELOPE_MASTER_KEY="$(openssl rand -base64 32)" \
  envelope
curl localhost:8080/health
```

## Kubernetes

`deploy/k8s/deployments.yaml` has one Deployment + PodDisruptionBudget
per `--roles` value (`replicas: 2`, NFR-AV-1) and expects a
`envelope-config` ConfigMap plus an `envelope-secrets` Secret (DB
password, `ENVELOPE_MASTER_KEY`, `ENVELOPE_API_ADMIN_TOKEN`) — see that
file's header comment for the exact keys. `deploy/k8s/networkpolicy.yaml`
and `deploy/postgres/roles.sql` are network- and DB-level segmentation
(NFR-SEC-5); both files' own comments are explicit about what they do and
don't achieve yet — read those before treating either as a completed
security boundary. Each Deployment already satisfies the one-role-per-
process precondition `internal/db.DSNForRole` needs to pick a
differentiated Postgres credential per role instead of one shared one
(see `.env.example`'s `ENVELOPE_DB_USER_<ROLE>` vars) — provisioning
`roles.sql` and populating those keys into the Secret is what actually
turns it on, not done by these manifests on their own.

For `smtp-inbound`/`smtp-submission`/`imap` specifically, NFR-SEC-5's
fuller goal — no live Postgres credential in that pod's environment at
all — is available via `internal/internalapi`: set that Deployment's
`ENVELOPE_INTERNAL_TOKEN_<ROLE>` and `ENVELOPE_INTERNAL_API_URL` (pointed
at the `api` role's `containerPort: 8081`, `envelope-to-internal-api` in
`networkpolicy.yaml`) instead of `ENVELOPE_DB_*`; `api` needs every
activated role's token to authorize incoming calls. See
`docs/RUNBOOK.md` §5 for the full activation procedure and how to confirm
it took effect. These manifests have since been applied against a real
(single-node) Kubernetes cluster — see `docs/ENVELOPE.md` Phase 7 for
what that found, including a real Dockerfile bug (`runAsNonRoot` +
`USER nonroot:nonroot` failed every pod outright — fixed) and a real
`NetworkPolicy` gap (`:9090` metrics had no allow rule — fixed) that only
surfaced by actually deploying to a cluster instead of reading the YAML.
Multi-*node* behavior (surviving a node failure, not just a pod) is still
unverified — that needs ≥2 real machines.
