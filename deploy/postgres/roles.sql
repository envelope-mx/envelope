-- Least-privilege Postgres roles per Envelope service role (NFR-SEC-4/
-- SEC-5, docs/ENVELOPE.md Phase 6). Complements deploy/k8s/networkpolicy.yaml:
-- network segmentation limits *who can open a connection at all*; this
-- limits *what a given connection can do once opened*, so a compromised
-- smtp-inbound process (the one most exposed to the public internet)
-- can't touch tables no inbound-mail code path ever needs — it can't
-- run migrations, mint api_tokens, or read another role's private DKIM
-- key material at the SQL layer even though inbound and submission
-- happen to share the vhosts table.
--
-- Wired into cmd/envelope/main.go via internal/db.DSNForRole: migrations
-- run under ENVELOPE_DB_USER_MIGRATOR/PASSWORD_MIGRATOR when set (a
-- short-lived connection, closed once migrations finish), and the app's
-- ongoing connection uses ENVELOPE_DB_USER_<ROLE>/PASSWORD_<ROLE> when a
-- process runs exactly one --roles value — the Kubernetes per-Deployment
-- shape deploy/k8s/deployments.yaml already assumes. A process running
-- multiple roles at once (the single-VM/Docker Compose shape) has no
-- coherent single differentiated identity to request on its one shared
-- *gorm.DB connection (every internal package holding that connection is
-- constructed once and shared across every role in the process, with no
-- per-call "which role is asking" hook to swap identities), so it falls
-- back to the shared ENVELOPE_DB_USER/PASSWORD credential instead — see
-- internal/db.DSNForRole and dbRoleForProcess's doc comments for the full
-- reasoning. Provisioning these roles in your database (by running this
-- script) and setting the corresponding env vars (.env.example) are both
-- still separate, opt-in operator steps this repository doesn't automate.
--
-- Run once against a fresh database, as a superuser, after
-- internal/storage/migrations.All has created every table.

CREATE ROLE envelope_migrator LOGIN PASSWORD 'CHANGE_ME';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO envelope_migrator;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO envelope_migrator;
GRANT CREATE ON SCHEMA public TO envelope_migrator;

-- messages/queue_jobs are granted here for two reasons predating and
-- postdating this comment: DataController.Export/Delete already read and
-- delete message rows directly (storage.Store), and
-- MessageController.Send (the REST send endpoint) now also writes/enqueues
-- through this same role's connection (storage.Store.Write,
-- queue.Backend.Enqueue) exactly the way envelope_smtp_submission already
-- does for SMTP-submitted mail.
CREATE ROLE envelope_api LOGIN PASSWORD 'CHANGE_ME';
GRANT SELECT, INSERT, UPDATE, DELETE ON
    accounts, vhosts, mailboxes, dkim_keys, messages,
    webhook_subscriptions, webhook_delivery_attempts, webhook_deliveries,
    api_tokens, audit_log, queue_jobs
    TO envelope_api;

CREATE ROLE envelope_smtp_inbound LOGIN PASSWORD 'CHANGE_ME';
GRANT SELECT ON vhosts, webhook_subscriptions TO envelope_smtp_inbound;
GRANT SELECT, INSERT, UPDATE ON messages, rate_limit_buckets TO envelope_smtp_inbound;
GRANT INSERT ON webhook_deliveries TO envelope_smtp_inbound;

-- envelope_smtp_submission additionally needs webhook_subscriptions/
-- webhook_deliveries (previously ungranted here — submission fired zero
-- webhook events until message.queued, submission.go's fireQueued): the
-- same two grants envelope_smtp_inbound and envelope_deliverer already
-- have for the identical reason.
CREATE ROLE envelope_smtp_submission LOGIN PASSWORD 'CHANGE_ME';
GRANT SELECT ON vhosts, dkim_keys, mailboxes, webhook_subscriptions TO envelope_smtp_submission;
GRANT SELECT, INSERT, UPDATE ON messages, rate_limit_buckets TO envelope_smtp_submission;
GRANT INSERT ON queue_jobs, webhook_deliveries TO envelope_smtp_submission;

CREATE ROLE envelope_imap LOGIN PASSWORD 'CHANGE_ME';
GRANT SELECT ON mailboxes TO envelope_imap;
GRANT SELECT, UPDATE ON messages TO envelope_imap;

CREATE ROLE envelope_deliverer LOGIN PASSWORD 'CHANGE_ME';
GRANT SELECT ON vhosts, webhook_subscriptions TO envelope_deliverer;
GRANT SELECT, UPDATE, DELETE ON queue_jobs TO envelope_deliverer;
GRANT SELECT, INSERT, UPDATE ON messages TO envelope_deliverer;
GRANT INSERT ON webhook_deliveries TO envelope_deliverer;

-- Every role needs USAGE on the sequences/defaults GORM's soft-delete and
-- UUID primary keys rely on for the tables it can INSERT into; if a
-- future migration adds a real Postgres SEQUENCE (none exist as of this
-- schema — IDs are app-generated UUIDs, see sql.BaseEntity), grant USAGE
-- explicitly per role above rather than blanket-granting it here.
