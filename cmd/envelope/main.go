// Command envelope registers Envelope's roles as concurrent Goose
// instances in one goose.Start(...) call (TRD §2.1): the stock `api`
// platform plus the custom smtp-inbound, smtp-submission, and imap
// platforms, and the headless deliverer/webhook-dispatcher background
// loops. --roles selects which subset to run, so a single binary can be
// deployed per-role (TRD §4, §8 M1; index/ENVELOPE.md Phase 2).
//
// Every role shares one Postgres connection (Phase 3, TRD M2): the
// Directory, storage.Store, and queue.Backend are all Postgres-backed, so
// nothing here holds state that doesn't survive a process restart
// (NFR-AV-2).
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/awesome-goose/goose"
	"github.com/awesome-goose/goose/config"
	"github.com/awesome-goose/goose/platforms/api"
	"github.com/awesome-goose/goose/types"
	"github.com/awesome-goose/goose/utils/path"
	"github.com/caddyserver/certmagic"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	gormlib "gorm.io/gorm"

	"github.com/envelope-mx/envelope/internal/acme"
	envapi "github.com/envelope-mx/envelope/internal/api"
	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/app"
	"github.com/envelope-mx/envelope/internal/audit"
	envdb "github.com/envelope-mx/envelope/internal/db"
	"github.com/envelope-mx/envelope/internal/deliverer"
	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/filter"
	"github.com/envelope-mx/envelope/internal/filter/rspamd"
	"github.com/envelope-mx/envelope/internal/internalapi"
	"github.com/envelope-mx/envelope/internal/kms"
	"github.com/envelope-mx/envelope/internal/logging"
	"github.com/envelope-mx/envelope/internal/platform"
	envimap "github.com/envelope-mx/envelope/internal/platform/imap"
	envsmtp "github.com/envelope-mx/envelope/internal/platform/smtp"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/ratelimit"
	"github.com/envelope-mx/envelope/internal/retention"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/migrations"
	storagepostgres "github.com/envelope-mx/envelope/internal/storage/postgres"
	"github.com/envelope-mx/envelope/internal/webhook"
)

const (
	roleAPI            = "api"
	roleSMTPInbound    = "smtp-inbound"
	roleSMTPSubmission = "smtp-submission"
	roleIMAP           = "imap"
	// roleDeliverer implements TRD §4's role 4 ("Outbound queue... runs as
	// a headless Goose instance") — Phase 2/3 built the durable
	// queue.Backend jobs land in, but nothing consumed them until this
	// phase. Unlike webhook dispatch (which TRD §4 role 5 bundles into the
	// api role instead — see buildInstances), the TRD lists the outbound
	// deliverer as its own distinct role, so it gets its own --roles value
	// for independent scaling.
	roleDeliverer = "deliverer"
)

var allRoles = []string{roleAPI, roleSMTPInbound, roleSMTPSubmission, roleIMAP, roleDeliverer}

func main() {
	// NFR-OBS-2: every process's entire log stream — including GORM's own
	// (internal/db.Open wires it through this same default logger) and
	// this file's own boot-sequence messages below — is structured JSON
	// from the first line, not just the request-handling code paths.
	slog.SetDefault(logging.NewJSONLogger(os.Stdout, logging.LevelFromEnv(os.Getenv("ENVELOPE_LOG_LEVEL"))))

	roles := flag.String("roles", strings.Join(allRoles, ","),
		"comma-separated subset of roles to run: "+strings.Join(allRoles, ", "))
	rotateMasterKeyTo := flag.String("rotate-master-key", "",
		"re-encrypt every DKIM key and webhook secret from ENVELOPE_MASTER_KEY to this base64-encoded "+
			"key, then exit without starting any role — see index/RUNBOOK.md §4.7. Every other process "+
			"pointed at this database must be stopped first.")
	flag.Parse()

	// --rotate-master-key is a one-shot maintenance operation, not a role:
	// it never starts goose.Start, so it's handled before --roles is even
	// parsed.
	if *rotateMasterKeyTo != "" {
		if err := rotateMasterKey(*rotateMasterKeyTo); err != nil {
			slog.Error("envelope: master key rotation failed", "error", err)
			os.Exit(1)
		}
		return
	}

	selected, err := parseRoles(*roles)
	if err != nil {
		slog.Error("envelope: startup failed", "error", err)
		os.Exit(1)
	}

	// NFR-SEC-5's fuller goal for smtp-inbound/smtp-submission/imap: when
	// this process runs exactly one of those roles alone and its
	// ENVELOPE_INTERNAL_TOKEN_<ROLE> is configured (internalAPIActivated),
	// it talks to Postgres exclusively through internal/internalapi's
	// HTTP client — it must not also open a direct connection (or run
	// migrations under envelope_migrator's DDL-capable credential) just
	// because every prior process shape did. Opening the connection
	// anyway and simply not calling most of its methods would leave the
	// live credential sitting in this process's memory/environment
	// regardless — exactly the exposure this whole migration exists to
	// remove, not something narrowing which Go values happen to reference
	// it can paper over.
	needsDirectDB := !(internalAPIActivated(selected, roleSMTPInbound) ||
		internalAPIActivated(selected, roleSMTPSubmission) ||
		internalAPIActivated(selected, roleIMAP))

	var conn *gormlib.DB
	if needsDirectDB {
		// NFR-SEC-5: run migrations as envelope_migrator's DDL-capable
		// credential when deploy/postgres/roles.sql's differentiated roles
		// have actually been provisioned (ENVELOPE_DB_USER_MIGRATOR set);
		// otherwise falls back to the shared credential, identical to every
		// prior behavior. A short-lived connection, closed once migrations
		// finish — the app's ongoing connection below never needs
		// envelope_migrator's broader privileges.
		migratorConn, err := envdb.Open(envdb.DSNForRole("migrator"))
		if err != nil {
			slog.Error("envelope: startup failed", "error", err)
			os.Exit(1)
		}
		if err := migrations.All(migratorConn); err != nil {
			slog.Error("envelope: migrate failed", "error", err)
			os.Exit(1)
		}
		if sqlDB, err := migratorConn.DB(); err == nil {
			sqlDB.Close()
		}

		// NFR-SEC-5: pick a role-specific DB credential only when this
		// process runs exactly one role (dbRoleForProcess's doc explains
		// why a multi-role process — the single-VM/Docker Compose shape,
		// TRD G7 — can't coherently hold one differentiated identity per
		// role on one shared connection, and keeps the pre-existing
		// shared-credential behavior there).
		conn, err = envdb.Open(envdb.DSNForRole(dbRoleForProcess(selected)))
		if err != nil {
			slog.Error("envelope: startup failed", "error", err)
			os.Exit(1)
		}
		if sqlDB, err := conn.DB(); err == nil {
			defer sqlDB.Close()
		}
	} else {
		slog.Info("envelope: internal API activated for this role — skipping migrations and the direct "+
			"Postgres connection entirely (NFR-SEC-5)", "role", dbRoleForProcess(selected))
	}

	instances, err := buildInstances(selected, conn)
	if err != nil {
		slog.Error("envelope: startup failed", "error", err)
		os.Exit(1)
	}

	stop, err := goose.Start(instances...)
	if err != nil {
		slog.Error("envelope: startup failed", "error", err)
		os.Exit(1)
	}
	defer stop()
}

func parseRoles(csv string) (map[string]bool, error) {
	selected := make(map[string]bool)
	for _, r := range strings.Split(csv, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !isKnownRole(r) {
			return nil, fmt.Errorf("unknown role %q (valid: %s)", r, strings.Join(allRoles, ", "))
		}
		selected[r] = true
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("--roles selected no roles")
	}
	return selected, nil
}

// dbRoleForProcess returns the single role name to look up a
// deploy/postgres/roles.sql credential for (NFR-SEC-5, see main's doc),
// or "" if selected doesn't name exactly one role. Every internal package
// this process's roles share (internal/directory, internal/queue,
// internal/webhook, internal/storage/postgres, internal/ratelimit) is
// handed one *gorm.DB at construction and holds it for the process's
// lifetime — there is no per-call "which role is asking" hook to swap
// identities mid-connection, so a process running multiple roles at once
// (e.g. the default --roles, every role in one process) has no coherent
// single differentiated identity to request and keeps using the shared
// credential instead. This is exactly the Kubernetes-vs-single-VM split
// deploy/k8s/deployments.yaml already assumes: one Deployment per role,
// each therefore a single-role process where this returns something real.
func dbRoleForProcess(selected map[string]bool) string {
	if len(selected) != 1 {
		return ""
	}
	for role := range selected {
		return role
	}
	return ""
}

// internalAPIActivated reports whether role should use internal/internalapi
// HTTP clients instead of direct Postgres access for NFR-SEC-5 (see
// buildInstances' smtp-inbound block for the full reasoning). True only
// when this process runs role alone (dbRoleForProcess's exact
// precondition — a process bundling role with roleAPI already holds a
// live DB credential for that other role regardless, so routing role's own
// calls through the internal API would add a network hop with no matching
// security benefit) and that role's token is actually configured.
func internalAPIActivated(selected map[string]bool, role string) bool {
	return dbRoleForProcess(selected) == role && internalAPITokenFor(role) != ""
}

// internalAPITokenEnvVar mirrors internal/db.DSNForRole's
// ENVELOPE_DB_USER_<ROLE> naming convention exactly: role uppercased,
// "-" turned into "_" (e.g. "smtp-inbound" -> ENVELOPE_INTERNAL_TOKEN_SMTP_INBOUND).
func internalAPITokenEnvVar(role string) string {
	return "ENVELOPE_INTERNAL_TOKEN_" + strings.ToUpper(strings.ReplaceAll(role, "-", "_"))
}

func internalAPITokenFor(role string) string {
	return os.Getenv(internalAPITokenEnvVar(role))
}

// internalAPITokens builds the map internalapi.NewServer needs (token ->
// role) from whichever ENVELOPE_INTERNAL_TOKEN_<ROLE> vars are actually
// set — a role with none configured simply has no entry, so every request
// claiming that role is rejected (fail-closed; see internalapi.NewServer's
// doc for why this can't auto-generate a value the way the admin token
// does).
func internalAPITokens() map[string]string {
	tokens := make(map[string]string)
	for _, role := range []string{roleSMTPInbound, roleSMTPSubmission, roleIMAP} {
		if t := internalAPITokenFor(role); t != "" {
			tokens[t] = role
		}
	}
	return tokens
}

// internalAPIURL is where an activated SMTP-facing role's internal API
// clients dial — defaults to the internal API server's own default bind
// address on loopback, the common case where every role (including api)
// runs bundled in one process anyway. A real cross-process/cross-pod
// deployment (Kubernetes's one-Deployment-per-role shape) must override
// this to wherever the api role's internal port is actually reachable
// (e.g. a ClusterIP Service) — deploy/k8s/deployments.yaml's header
// comment names this as a provisioning step, the same way it already does
// for ENVELOPE_DB_USER_<ROLE>.
func internalAPIURL() string {
	return addrFromEnv("ENVELOPE_INTERNAL_API_URL", "http://127.0.0.1:8081")
}

// internalAPIAddr is the internal API server's own bind address (only
// relevant when roleAPI is selected — buildInstances only starts the
// server then). Deliberately a separate port from apiPlatform's public
// 8080, not a route bundled onto it: this lets a NetworkPolicy
// (deploy/k8s/networkpolicy.yaml) restrict who reaches it independently of
// the public management API port.
func internalAPIAddr() string {
	return addrFromEnv("ENVELOPE_INTERNAL_API_ADDR", ":8081")
}

func isKnownRole(r string) bool {
	for _, known := range allRoles {
		if r == known {
			return true
		}
	}
	return false
}

// buildInstances wires the selected roles' Instances. The Directory,
// storage.Store, queue.Backend, and webhook.Dispatcher are constructed
// once here and shared by closing over the same pointers in each
// Instance's Platform config — Goose's kernel gives every Instance its own
// child DI container (core/kernel.go's runServers), so this is how roles
// share state instead (see TRD §2.1's "Multi-port exposure" note,
// corrected there against the actual kernel source).
func buildInstances(selected map[string]bool, conn *gormlib.DB) ([]*types.Instance, error) {
	// enc/conn are both nil together (main's needsDirectDB) when this
	// process is internal-API-activated for its sole role: ENVELOPE_MASTER_KEY
	// decrypts DKIM keys and webhook secrets read from Postgres directly,
	// neither of which this process ever does in that case (the internal
	// API hands back already-decrypted material — see
	// internal/internalapi's package doc) — requiring the key anyway would
	// mean this process could still decrypt any ciphertext it somehow
	// obtained (a DB backup, another vulnerability), which is exactly the
	// exposure this whole migration removes elsewhere. dir/webhookStore
	// below are still constructed with a nil enc in that case, but neither
	// is ever assigned into a Config field or otherwise called for a
	// process in this branch — see the smtp-inbound/submission/imap blocks
	// below, which all use the internalapi-client variants instead
	// whenever conn is nil.
	var enc kms.Encryptor
	if conn != nil {
		var err error
		enc, err = masterKeyFromEnv()
		if err != nil {
			return nil, err
		}
	}

	dir := directory.New(conn, enc)
	store := storagepostgres.New(conn)
	q := queue.NewPostgresBackend(conn)

	// FR-6.x: Enqueue (a fast local DB insert, safe to call inline from
	// smtp-inbound's connection handler and from the deliverer's own
	// per-job goroutine) is shared by every role that can fire an event;
	// Run (the actual outbound HTTP POST loop) only executes wherever
	// roleAPI is selected — see the api block below for why that's the
	// right place per TRD §4 role 5's "API... + webhook dispatch" bundling.
	webhookStore := webhook.NewPostgresStore(conn, enc)
	dispatcher := webhook.NewDispatcher(webhookStore, webhook.NewPostgresEventQueue(conn))

	domain := addrFromEnv("ENVELOPE_DOMAIN", "localhost")

	var instances []*types.Instance

	// NFR-OBS-1: every role exposes /metrics, regardless of --roles — a
	// scrape target shouldn't need to know which role subset a given
	// process happens to run. Unconditional, not gated behind roleAPI:
	// the smtp-inbound/smtp-submission/imap/deliverer roles all update
	// metrics (envelope_messages_received_total,
	// envelope_delivery_latency_seconds, etc.) and need this reachable
	// even when the api role isn't selected for this process.
	instances = append(instances, newInstance(metricsPlatform()))

	// Shared across smtp-inbound's FR-2.3 rate limiting,
	// smtp-submission's FR-3.7 quota enforcement, and the api role's
	// NFR-SEC-4 per-IP API rate limit — one Postgres-backed token-bucket
	// store (internal/ratelimit.PostgresLimiter), namespaced by key prefix
	// ("ip:", "sender:", "quota:", "api:") so the uses never collide.
	var limiter *ratelimit.PostgresLimiter
	if selected[roleSMTPInbound] || selected[roleSMTPSubmission] || selected[roleAPI] {
		limiter = ratelimit.NewPostgresLimiter(conn)
	}

	if selected[roleAPI] {
		tokenStore := apiauth.NewPostgresStore(conn)
		auditStore := audit.NewPostgresStore(conn)
		admin := adminTokenFromEnv()
		apiRateLimit := &envapi.RateLimitPolicy{
			Limiter:         limiter,
			Capacity:        floatEnv("ENVELOPE_RATELIMIT_API_CAPACITY", envapi.DefaultAPIRateLimitCapacity),
			RefillPerSecond: floatEnv("ENVELOPE_RATELIMIT_API_REFILL_PER_SECOND", envapi.DefaultAPIRateLimitRefillPerSecond),
		}
		redrive := &envapi.RedrivePolicy{Dispatcher: dispatcher}
		// FR-3.x via REST (internal/api.MessageController): q and dispatcher
		// are already constructed unconditionally above; quotaPolicy reuses
		// the same limiter FR-3.7's SMTP submission quota check already
		// shares with inbound's IP/sender limits and the API's own per-IP
		// limit (see limiter's construction above for the "quota:"/"ip:"/
		// "sender:"/"api:" key-prefix convention).
		quotaPolicy := &envapi.QuotaPolicy{Limiter: limiter}
		instances = append(instances, goose.API(apiPlatform, rootModule, apiInitializers(
			dir, store, webhookStore, tokenStore, auditStore, admin, apiRateLimit, redrive,
			q, dispatcher, quotaPolicy,
		)))
		instances = append(instances, newInstance(&platform.HeadlessPlatform{
			PlatformType: "webhook-dispatcher",
			PlatformName: "webhook-dispatcher",
			Loop:         dispatcher.Run,
		}))

		// NFR-SEC-5's fuller network-segmentation goal (internal/internalapi's
		// package doc has the full reasoning): a small, internal-only
		// protocol on its own port, so an activated smtp-inbound/
		// smtp-submission/imap role (see the ACTIVATED blocks below) never
		// needs a live Postgres credential in its own environment at all.
		// Backed by the exact same dir/store/q/limiter/dispatcher this
		// process already constructed for its own management-API purposes —
		// unconditional whenever roleAPI is selected (the same posture
		// metricsPlatform takes), gated to a no-op-by-default state by
		// internalAPITokens() being empty until an operator actually
		// provisions ENVELOPE_INTERNAL_TOKEN_<ROLE> for at least one role.
		internalSrv := internalapi.NewServer(dir, store, q, limiter, dispatcher, internalAPITokens())
		instances = append(instances, newInstance(
			httpHeadlessPlatform("internal-api", "internal-api", internalAPIAddr(), internalSrv.Handler()),
		))

		// NFR-COMP-1: retention purge, bundled into roleAPI the same way
		// webhook dispatch is (see that instance's comment) — TRD §4
		// doesn't name a dedicated role for it either, and like webhook
		// dispatch it's platform housekeeping rather than mail-path work,
		// so it doesn't warrant its own --roles value the way the
		// independently-scalable deliverer does.
		purger := &retention.Purger{
			Directory:            dir,
			Store:                store,
			DefaultRetentionDays: intEnv("ENVELOPE_RETENTION_DEFAULT_DAYS", retention.DefaultRetentionDays),
			SweepInterval:        time.Duration(intEnv("ENVELOPE_RETENTION_SWEEP_INTERVAL_HOURS", int(retention.DefaultSweepInterval.Hours()))) * time.Hour,
		}
		instances = append(instances, newInstance(&platform.HeadlessPlatform{
			PlatformType: "retention-purger",
			PlatformName: "retention-purger",
			Loop:         purger.Run,
		}))
	}

	needsTLS := selected[roleSMTPInbound] || selected[roleSMTPSubmission] || selected[roleIMAP]
	var tlsCfg *tls.Config
	if needsTLS {
		// FR-1.3: real ACME automation (internal/acme's on-demand decision
		// function + caddyserver/certmagic) when ENVELOPE_ACME_EMAIL is
		// set — self-signed remains the behavior for every deployment
		// that hasn't configured a real domain to issue against
		// (unchanged default, the same activate-only-when-provisioned
		// posture DSNForRole and internal/internalapi both already take).
		if email := os.Getenv("ENVELOPE_ACME_EMAIL"); email != "" {
			// dir is nil-backed exactly when this process is
			// internal-API-activated for its sole SMTP-facing role (conn
			// == nil, see needsDirectDB in main) — unlike every other
			// unconditional use of dir/store/q/limiter/dispatcher above,
			// which simply go unused in that case, DecisionFunc genuinely
			// gets called on every real TLS handshake, so it needs that
			// role's own activated Directory instead.
			var tlsDir directory.Directory = dir
			if conn == nil {
				role := dbRoleForProcess(selected)
				tlsDir = internalapi.NewDirectoryClient(internalAPIURL(), internalAPITokenFor(role))
			}
			tlsCfg = acmeTLSConfig(tlsDir, email)
		} else {
			cfg, err := platform.SelfSignedTLSConfig("localhost")
			if err != nil {
				return nil, fmt.Errorf("generate dev TLS cert: %w", err)
			}
			tlsCfg = cfg
		}
	}

	if selected[roleSMTPInbound] {
		// NFR-SEC-5: when this process runs smtp-inbound alone (the same
		// precondition dbRoleForProcess already requires for DSNForRole)
		// and ENVELOPE_INTERNAL_TOKEN_SMTP_INBOUND is set, Directory/Store/
		// RateLimiter/Webhooks are internal/internalapi HTTP clients
		// instead of the direct Postgres-backed values above — this
		// process then never needs a live DB credential in its own
		// environment at all. Falls back to the direct values otherwise
		// (every default/bundled-role deployment, unchanged), matching
		// DSNForRole's own "activates only when actually provisioned"
		// posture exactly.
		var inboundDir directory.Directory = dir
		var inboundStore storage.Store = store
		var inboundLimiter envsmtp.RateLimiter = limiter
		var inboundWebhooks webhook.Enqueuer = dispatcher
		if internalAPIActivated(selected, roleSMTPInbound) {
			base, token := internalAPIURL(), internalAPITokenFor(roleSMTPInbound)
			inboundDir = internalapi.NewDirectoryClient(base, token)
			inboundStore = internalapi.NewStoreClient(base, token)
			inboundLimiter = internalapi.NewRateLimiterClient(base, token)
			inboundWebhooks = internalapi.NewWebhookClient(base, token)
		}

		p := envsmtp.NewPlatform(envsmtp.Config{
			Mode:      envsmtp.ModeInbound,
			Name:      roleSMTPInbound,
			Addr:      addrFromEnv("ENVELOPE_SMTP_INBOUND_ADDR", ":25"),
			Domain:    domain,
			TLSConfig: tlsCfg,
			Directory: inboundDir,
			Store:     inboundStore,
			// Queue is unused in ModeInbound (Config.Queue's own doc) — no
			// need for an internal-API-backed variant here.
			Queue: q,
			// FR-2.4/2.5's verdict pipeline. net.DefaultResolver satisfies
			// filter.Resolver directly (same method set), so no adapter is
			// needed for real DNS.
			Filter: &filter.Pipeline{
				Resolver: net.DefaultResolver,
				Rspamd:   rspamd.New(rspamdURLFromEnv()),
			},
			// FR-2.5: message.received, fired here for the first time
			// (Phase 4 built the verdict but deliberately left this call
			// site unwired — index/ENVELOPE.md Phase 4/5).
			Webhooks: inboundWebhooks,
			// FR-2.3: shared, cross-replica rate limiting via Postgres (see
			// internal/ratelimit.PostgresLimiter's doc for why not Goose's
			// kv module). Defaults are deliberately generous starting
			// points, not tuned production values.
			RateLimiter:                inboundLimiter,
			RateLimitIPCapacity:        floatEnv("ENVELOPE_RATELIMIT_IP_CAPACITY", 20),
			RateLimitIPRefillPerSecond: floatEnv("ENVELOPE_RATELIMIT_IP_REFILL_PER_SECOND", 1),
			RateLimitSenderCapacity:    floatEnv("ENVELOPE_RATELIMIT_SENDER_CAPACITY", 10),
			RateLimitSenderRefillPerSecond: floatEnv(
				"ENVELOPE_RATELIMIT_SENDER_REFILL_PER_SECOND", 0.5),
		})
		instances = append(instances, newInstance(p))
	}

	if selected[roleSMTPSubmission] {
		// NFR-SEC-5: see smtp-inbound's identical block above for the
		// activation condition and fallback behavior.
		var submissionDir directory.Directory = dir
		var submissionStore storage.Store = store
		var submissionQueue queue.Backend = q
		var submissionQuota envsmtp.RateLimiter = limiter
		var submissionWebhooks webhook.Enqueuer = dispatcher
		if internalAPIActivated(selected, roleSMTPSubmission) {
			base, token := internalAPIURL(), internalAPITokenFor(roleSMTPSubmission)
			submissionDir = internalapi.NewDirectoryClient(base, token)
			submissionStore = internalapi.NewStoreClient(base, token)
			submissionQueue = internalapi.NewQueueClient(base, token)
			submissionQuota = internalapi.NewRateLimiterClient(base, token)
			submissionWebhooks = internalapi.NewWebhookClient(base, token)
		}

		p := envsmtp.NewPlatform(envsmtp.Config{
			Mode:      envsmtp.ModeSubmission,
			Name:      roleSMTPSubmission,
			Addr:      addrFromEnv("ENVELOPE_SMTP_SUBMISSION_ADDR", ":587"),
			Domain:    domain,
			TLSConfig: tlsCfg,
			Directory: submissionDir,
			Store:     submissionStore,
			Queue:     submissionQueue,
			// FR-3.7: a no-op per vhost unless that vhost's DailyQuota is
			// configured above zero (see Config.Quota's doc).
			Quota: submissionQuota,
			// message.queued, fired once per accepted submission (see
			// submissionSession.fireQueued).
			Webhooks: submissionWebhooks,
		})
		instances = append(instances, newInstance(p))
	}

	if selected[roleIMAP] {
		// NFR-SEC-5: see smtp-inbound's identical block above for the
		// activation condition and fallback behavior.
		var imapDir directory.Directory = dir
		var imapStore storage.Store = store
		if internalAPIActivated(selected, roleIMAP) {
			base, token := internalAPIURL(), internalAPITokenFor(roleIMAP)
			imapDir = internalapi.NewDirectoryClient(base, token)
			imapStore = internalapi.NewStoreClient(base, token)
		}

		p := envimap.NewPlatform(envimap.Config{
			Name:      roleIMAP,
			Addr:      addrFromEnv("ENVELOPE_IMAP_ADDR", ":993"),
			TLSConfig: tlsCfg,
			Directory: imapDir,
			Store:     imapStore,
		})
		instances = append(instances, newInstance(p))
	}

	if selected[roleDeliverer] {
		del := deliverer.New(deliverer.Config{
			Queue:                q,
			Store:                store,
			Directory:            dir,
			Webhooks:             dispatcher,
			Resolver:             net.DefaultResolver,
			Domain:               domain,
			Port:                 intEnv("ENVELOPE_DELIVERER_SMTP_PORT", deliverer.DefaultPort),
			PerDomainConcurrency: intEnv("ENVELOPE_DELIVERER_PER_DOMAIN_CONCURRENCY", deliverer.DefaultPerDomainConcurrency),
		})
		instances = append(instances, newInstance(&platform.HeadlessPlatform{
			PlatformType: roleDeliverer,
			PlatformName: roleDeliverer,
			Loop:         del.Run,
		}))
	}

	return instances, nil
}

// newInstance builds a *types.Instance for a custom Goose platform (TRD
// §2.1) — there's no goose.XXX() convenience constructor for platform
// types outside api/web/spa/cli, so this mirrors what those do internally.
// emptyModule is used because these platforms take their dependencies via
// Config (see envsmtp/envimap's Boot doc) or via closure (HeadlessPlatform),
// not container resolution.
func newInstance(p types.Platform) *types.Instance {
	return &types.Instance{
		Name:     p.Name(),
		Type:     p.Type(),
		Platform: p,
		Module:   emptyModule{},
	}
}

type emptyModule struct{}

func (emptyModule) Imports() []types.Module { return nil }
func (emptyModule) Exports() []any          { return nil }
func (emptyModule) Declarations() []any     { return nil }

func addrFromEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// metricsPlatform returns a headless Goose platform (internal/platform's
// same HeadlessApp/HeadlessPlatform pattern the deliverer/webhook-
// dispatcher roles use) serving Prometheus's default registry at /metrics
// — every metrics.* counter/gauge/histogram registers against that
// registry in its package init(), so nothing else has to be wired here
// beyond starting promhttp.Handler somewhere every process reaches.
func metricsPlatform() *platform.HeadlessPlatform {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return httpHeadlessPlatform("metrics", "metrics", addrFromEnv("ENVELOPE_METRICS_ADDR", ":9090"), mux)
}

// httpHeadlessPlatform wraps a plain net/http.Handler as a Goose headless
// instance bound to addr — the shared bind/serve-until-cancelled/graceful-
// shutdown shape metricsPlatform and buildInstances' internal API instance
// (internal/internalapi, NFR-SEC-5) both need, extracted here once both
// existed instead of copy-pasted a second time.
func httpHeadlessPlatform(platformType, name, addr string, handler http.Handler) *platform.HeadlessPlatform {
	srv := &http.Server{Addr: addr, Handler: handler}

	return &platform.HeadlessPlatform{
		PlatformType: types.PlatformType(platformType),
		PlatformName: name,
		Loop: func(ctx context.Context) error {
			errCh := make(chan error, 1)
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return srv.Shutdown(shutdownCtx)
			case err := <-errCh:
				return err
			}
		},
	}
}

// rspamdURLFromEnv defaults to the conventional rspamd sidecar address
// (TRD §9: "rspamd, run as sidecar").
func rspamdURLFromEnv() string {
	return addrFromEnv("ENVELOPE_RSPAMD_URL", "http://localhost:11333")
}

func floatEnv(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func intEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

var (
	apiPlatform = api.NewPlatform(
		api.WithName("envelope-api"),
		// 0.0.0.0, not the api package's "localhost" default: the health
		// check must be reachable from outside the container/pod network
		// namespace, not just from a loopback interface inside it.
		api.WithHost("0.0.0.0"),
		api.WithPort(8080),
	)
	rootModule = &app.AppModule{}
)

// apiInitializers overrides config.AppConfigPath so config lives under
// ./config (per index/ENVELOPE.md's repo layout) instead of Goose's default
// of the whole app root, and registers the shared *directory.Service,
// storage.Store, webhook.Store, apiauth.Store, audit.Store, AdminToken,
// RateLimitPolicy, RedrivePolicy, queue.Backend, webhook.Enqueuer, and
// QuotaPolicy so internal/api's controllers (all inject:"") can resolve
// them — this Instance's container is otherwise empty (see buildInstances'
// doc on why state is shared via closures, not a shared container). q,
// messageWebhooks, and quota are MessageController's own dependencies
// (internal/api.MessageController, FR-3.x via REST) — otherwise unused by
// every other controller in this module.
func apiInitializers(
	dir *directory.Service, store storage.Store, webhookStore webhook.Store,
	tokenStore apiauth.Store, auditStore audit.Store, admin *envapi.AdminToken,
	apiRateLimit *envapi.RateLimitPolicy, redrive *envapi.RedrivePolicy,
	q queue.Backend, messageWebhooks webhook.Enqueuer, quota *envapi.QuotaPolicy,
) []func(container types.Container) error {
	return []func(container types.Container) error{
		func(container types.Container) error {
			return container.Register(
				func() (config.AppConfigPath, error) {
					d, err := path.Config()
					return config.AppConfigPath(d), err
				},
				"",
				true,
			)
		},
		func(container types.Container) error {
			return container.Register(func() *directory.Service { return dir }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() storage.Store { return store }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() webhook.Store { return webhookStore }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() apiauth.Store { return tokenStore }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() audit.Store { return auditStore }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() *envapi.AdminToken { return admin }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() *envapi.RateLimitPolicy { return apiRateLimit }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() *envapi.RedrivePolicy { return redrive }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() queue.Backend { return q }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() webhook.Enqueuer { return messageWebhooks }, "", true)
		},
		func(container types.Container) error {
			return container.Register(func() *envapi.QuotaPolicy { return quota }, "", true)
		},
	}
}

// adminTokenFromEnv returns the FR-5.2 bootstrap admin credential from
// ENVELOPE_API_ADMIN_TOKEN. If unset, a fresh one is generated and logged
// prominently: the API is authenticated-only from the first request, so
// booting with no way to reach it at all (rather than a discoverable,
// one-time-printed credential) would make a fresh deployment unusable
// until an operator went and read the docs.
func adminTokenFromEnv() *envapi.AdminToken {
	if v := os.Getenv("ENVELOPE_API_ADMIN_TOKEN"); v != "" {
		return &envapi.AdminToken{Value: v}
	}

	raw, _, err := apiauth.GenerateToken()
	if err != nil {
		slog.Error("envelope: generate bootstrap admin token failed", "error", err)
		os.Exit(1)
	}
	slog.Warn("envelope: ENVELOPE_API_ADMIN_TOKEN not set — generated a one-time admin token for this "+
		"process's lifetime (set ENVELOPE_API_ADMIN_TOKEN to persist one across restarts)", "token", raw)
	return &envapi.AdminToken{Value: raw}
}

// rotateMasterKey implements --rotate-master-key: index/RUNBOOK.md §4.7's
// previously-missing "re-encrypt everything under a new key" tool. Reads
// the current key from ENVELOPE_MASTER_KEY (same as normal boot) and the
// target key from newKeyB64 (the flag's value), re-encrypts every DKIM
// private key (directory.Service.RotateDKIMKeys) and webhook signing
// secret (webhook.PostgresStore.RotateSecrets) from the former to the
// latter, then returns — it never starts any server role. Callers must
// stop every other process pointed at this database first: a live app
// decrypting under the old key while this tool re-encrypts rows out from
// under it would see spurious decrypt failures for whichever rows this
// tool has already migrated. After it reports success, set
// ENVELOPE_MASTER_KEY to newKeyB64 and restart the app normally.
func rotateMasterKey(newKeyB64 string) error {
	oldEnc, err := masterKeyFromEnv()
	if err != nil {
		return err
	}
	newKey, err := base64.StdEncoding.DecodeString(newKeyB64)
	if err != nil {
		return fmt.Errorf("--rotate-master-key must be base64-encoded: %w", err)
	}
	newEnc, err := kms.NewAESGCMEncryptor(newKey)
	if err != nil {
		return fmt.Errorf("--rotate-master-key: %w", err)
	}

	conn, err := envdb.Open(envdb.DSNForRole("migrator"))
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, err := conn.DB(); err == nil {
			sqlDB.Close()
		}
	}()
	if err := migrations.All(conn); err != nil {
		return fmt.Errorf("migrate before rotation: %w", err)
	}

	ctx := context.Background()

	dkimRotated, err := directory.New(conn, oldEnc).RotateDKIMKeys(ctx, oldEnc, newEnc)
	if err != nil {
		return fmt.Errorf("rotate dkim keys: %w", err)
	}

	secretsRotated, err := webhook.NewPostgresStore(conn, oldEnc).RotateSecrets(ctx, oldEnc, newEnc)
	if err != nil {
		return fmt.Errorf("rotate webhook secrets: %w", err)
	}

	slog.Info("envelope: master key rotation complete",
		"dkim_keys_rotated", dkimRotated, "webhook_secrets_rotated", secretsRotated)
	slog.Warn("envelope: the database is now encrypted under the new key — set ENVELOPE_MASTER_KEY to " +
		"it and restart every process; this rotation process's own environment still has the old key")
	return nil
}

// acmeTLSConfig builds a certmagic-backed *tls.Config that issues real
// Let's Encrypt certificates on demand for any domain internal/acme's
// DecisionFunc allows — dir.VhostActive, so exactly the set of active
// vhosts, never an arbitrary SNI a client happens to ask for (that
// package's own doc explains why the gate exists at all: unmanaged
// on-demand TLS would let anyone burn this deployment's ACME rate-limit
// budget requesting certs for unrelated domains). Certificates and
// account state persist under certmagic's default file storage
// (~/.local/share/certmagic on Linux) — not itself backed up by anything
// in this repo; losing it means re-issuing (annoying, rate-limited) but
// not re-registering the ACME account (email-recoverable), unlike losing
// ENVELOPE_MASTER_KEY.
//
// Issuance needs port 80 (HTTP-01 challenge, certmagic's default —
// TLS-ALPN-01 would need port 443, which nothing in this deployment
// serves either) reachable from the public internet for the domain being
// issued, in addition to CAP_NET_BIND_SERVICE to bind it — the same
// privileged-port requirement 25/587/993 already have (see README.md).
// Not verified end-to-end against a real ACME CA from this environment:
// that needs a real registrable domain with public DNS pointed at a
// reachable host, neither of which exists in a sandboxed dev environment
// — internal/acme.DecisionFunc itself is unit-tested against a real
// directory.Directory, and this function's wiring is exercised by
// TestACMETLSConfigConstructsAValidTLSConfig (compile/construction-level:
// proves this produces a working *tls.Config with the decision function
// correctly wired, not that a live handshake against Let's Encrypt
// succeeds).
func acmeTLSConfig(dir directory.Directory, email string) *tls.Config {
	cfg := certmagic.NewDefault()
	cfg.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: acme.DecisionFunc(dir)}

	ca := certmagic.LetsEncryptProductionCA
	if os.Getenv("ENVELOPE_ACME_STAGING") != "" {
		// Let's Encrypt's staging CA issues certs no browser/client trusts,
		// but exercises the real issuance flow without spending the much
		// stricter production rate limits — for validating a fresh
		// domain/DNS setup before cutting over.
		ca = certmagic.LetsEncryptStagingCA
	}
	cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		Email: email,
		// Setting ENVELOPE_ACME_EMAIL is the operator's explicit opt-in
		// to the CA's subscriber agreement — there is no separate
		// interactive prompt this process could show instead.
		Agreed: true,
		CA:     ca,
	})}
	return cfg.TLSConfig()
}

// masterKeyFromEnv returns the TRD R1/NFR-SEC-3 at-rest encryption key
// (internal/kms) from ENVELOPE_MASTER_KEY, base64-encoded. Unlike
// adminTokenFromEnv, this deliberately does not auto-generate a fallback:
// silently generating a fresh key every boot would make every
// already-encrypted DKIM key and webhook secret permanently undecryptable
// after a restart — a correctness/data-loss bug, not just an
// inconvenience — so a missing key fails the boot outright with
// instructions instead.
func masterKeyFromEnv() (kms.Encryptor, error) {
	v := os.Getenv("ENVELOPE_MASTER_KEY")
	if v == "" {
		return nil, fmt.Errorf("ENVELOPE_MASTER_KEY is required (TRD R1/NFR-SEC-3: encrypts DKIM keys " +
			"and webhook secrets at rest) — generate one with: openssl rand -base64 32")
	}
	key, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("ENVELOPE_MASTER_KEY must be base64-encoded: %w", err)
	}
	enc, err := kms.NewAESGCMEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("ENVELOPE_MASTER_KEY: %w", err)
	}
	return enc, nil
}
