package deliverer_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/deliverer"
	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/directory/memory"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/maildir"
)

// receivedMail is one message the fakeMTA accepted through DATA.
type receivedMail struct {
	From string
	To   []string
	Body []byte
}

// fakeMTA is a real go-smtp server standing in for a remote MTA, the same
// pattern internal/platform/smtp's own tests use for the inbound/
// submission roles: a genuine SMTP protocol exchange over a loopback TCP
// listener, not a mocked interface. rcptErr/dataErr, when set, are
// returned verbatim to the deliverer's client, letting a test simulate a
// permanent (5xx) or temporary (4xx) remote response; onData, when set,
// blocks until it returns (for the concurrency-cap test).
type fakeMTA struct {
	mu       sync.Mutex
	received []receivedMail

	rcptErr error
	dataErr error
	onData  func()
}

func (b *fakeMTA) NewSession(*gosmtp.Conn) (gosmtp.Session, error) {
	return &fakeMTASession{backend: b}, nil
}

type fakeMTASession struct {
	backend *fakeMTA
	from    string
	to      []string
}

var _ gosmtp.Session = (*fakeMTASession)(nil)

func (s *fakeMTASession) Mail(from string, _ *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *fakeMTASession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if s.backend.rcptErr != nil {
		return s.backend.rcptErr
	}
	s.to = append(s.to, to)
	return nil
}

func (s *fakeMTASession) Data(r io.Reader) error {
	if s.backend.onData != nil {
		s.backend.onData()
	}
	if s.backend.dataErr != nil {
		return s.backend.dataErr
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received = append(s.backend.received, receivedMail{From: s.from, To: append([]string{}, s.to...), Body: body})
	s.backend.mu.Unlock()
	return nil
}

func (s *fakeMTASession) Reset()        {}
func (s *fakeMTASession) Logout() error { return nil }

func (b *fakeMTA) all() []receivedMail {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]receivedMail{}, b.received...)
}

// startFakeMTA boots backend on a loopback, OS-assigned port and returns
// its port.
func startFakeMTA(t *testing.T, backend *fakeMTA) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := gosmtp.NewServer(backend)
	server.Domain = "mx.remote.test"
	server.AllowInsecureAuth = true
	server.ReadTimeout = 5 * time.Second
	server.WriteTimeout = 5 * time.Second

	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })

	return ln.Addr().(*net.TCPAddr).Port
}

// fakeResolver answers LookupMX from a fixed map, standing in for real DNS.
type fakeResolver struct {
	mxs map[string][]*net.MX
}

func (f fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if mxs, ok := f.mxs[name]; ok {
		return mxs, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}

// firedEvent is one call recorded by fakeEnqueuer.
type firedEvent struct {
	Vhost, EventType string
	Payload          []byte
}

type fakeEnqueuer struct {
	mu     sync.Mutex
	events []firedEvent
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, vhost, eventType string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, firedEvent{vhost, eventType, payload})
	return nil
}

func (f *fakeEnqueuer) all() []firedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]firedEvent{}, f.events...)
}

// testHarness bundles the fakes a Deliverer needs, plus a way to stage an
// outbound job's body exactly the way internal/platform/smtp's submission
// mode does (storage.Write under storage.OutboxMailbox).
type testHarness struct {
	dir      *memory.Directory
	store    storage.Store
	q        *queue.MemoryBackend
	webhooks *fakeEnqueuer
}

func newHarness(t *testing.T) *testHarness {
	t.Helper()
	dir := memory.New()
	if _, err := dir.AddVhost("sender.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("sender.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	return &testHarness{
		dir: dir, store: maildir.New(t.TempDir()), q: queue.NewMemoryBackend(), webhooks: &fakeEnqueuer{},
	}
}

// stageJob writes body under the Outbox mailbox and enqueues a due job
// pointing at it, exactly what submissionSession.Data does.
func (h *testHarness) stageJob(t *testing.T, vhost, from, to, body string) queue.Job {
	t.Helper()
	ref, err := h.store.Write(context.Background(), vhost, storage.OutboxMailbox, strings.NewReader(body))
	if err != nil {
		t.Fatalf("stage body: %v", err)
	}
	job := queue.Job{
		ID: uuid.NewString(), Vhost: vhost, From: from, To: to, BodyRef: ref.Key,
		NextAttemptAt: time.Now().Add(-time.Second),
	}
	if err := h.q.Enqueue(context.Background(), job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return job
}

func newTestDeliverer(h *testHarness, resolver deliverer.Resolver, port int) *deliverer.Deliverer {
	return deliverer.New(deliverer.Config{
		Queue: h.q, Store: h.store, Directory: h.dir, Webhooks: h.webhooks, Resolver: resolver,
		Domain: "mx.sender.test", Port: port,
		BackoffBase: time.Millisecond, BackoffMax: 5 * time.Millisecond,
		PollInterval: 2 * time.Millisecond, DialTimeout: 2 * time.Second,
	})
}

func runUntilDrained(t *testing.T, d *deliverer.Deliverer, q *queue.MemoryBackend) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !q.Empty() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !q.Empty() {
		cancel()
		<-done
		t.Fatal("timed out waiting for the outbound queue to drain")
	}
	cancel()
	<-done
}

func TestDeliverSuccessCompletesJobAndFiresDelivered(t *testing.T) {
	h := newHarness(t)
	mta := &fakeMTA{}
	port := startFakeMTA(t, mta)
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {{Host: "127.0.0.1", Pref: 10}},
	}}
	d := newTestDeliverer(h, resolver, port)

	job := h.stageJob(t, "sender.test", "alice@sender.test", "bob@remote.test", "Subject: hi\r\n\r\nhello\r\n")
	runUntilDrained(t, d, h.q)

	got := mta.all()
	if len(got) != 1 || got[0].From != job.From || len(got[0].To) != 1 || got[0].To[0] != job.To {
		t.Fatalf("unexpected mail received by fake MTA: %+v", got)
	}
	if !strings.Contains(string(got[0].Body), "hello") {
		t.Fatalf("body not delivered intact: %s", got[0].Body)
	}

	events := h.webhooks.all()
	if len(events) != 1 || events[0].EventType != "message.delivered" || events[0].Vhost != "sender.test" {
		t.Fatalf("expected exactly one message.delivered event, got %+v", events)
	}
}

func TestDeliverPermanentFailureDeadLettersAndBounces(t *testing.T) {
	h := newHarness(t)
	mta := &fakeMTA{rcptErr: &gosmtp.SMTPError{Code: 550, Message: "no such user"}}
	port := startFakeMTA(t, mta)
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {{Host: "127.0.0.1", Pref: 10}},
	}}
	d := newTestDeliverer(h, resolver, port)

	h.stageJob(t, "sender.test", "alice@sender.test", "bob@remote.test", "Subject: hi\r\n\r\nhello\r\n")
	runUntilDrained(t, d, h.q)

	// FR-3.6: a DSN lands directly in the sender's own INBOX, since
	// alice@sender.test is a mailbox we host ("feasible").
	metas, err := h.store.List(context.Background(), "sender.test", directory.MailboxPath("alice", "INBOX"))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected exactly one DSN delivered to alice's INBOX, got %d", len(metas))
	}
	rc, err := h.store.Read(context.Background(), metas[0].Ref)
	if err != nil {
		t.Fatalf("Read DSN: %v", err)
	}
	dsn, _ := io.ReadAll(rc)
	rc.Close()
	if !strings.Contains(string(dsn), "multipart/report") || !strings.Contains(string(dsn), "550") {
		t.Fatalf("DSN missing expected content: %s", dsn)
	}

	events := h.webhooks.all()
	if len(events) != 1 || events[0].EventType != "message.bounced" {
		t.Fatalf("expected exactly one message.bounced event, got %+v", events)
	}
}

func TestDeliverTemporaryFailureReschedulesAndFiresDeferred(t *testing.T) {
	h := newHarness(t)
	mta := &fakeMTA{dataErr: &gosmtp.SMTPError{Code: 450, Message: "try again later"}}
	port := startFakeMTA(t, mta)
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {{Host: "127.0.0.1", Pref: 10}},
	}}
	d := deliverer.New(deliverer.Config{
		Queue: h.q, Store: h.store, Directory: h.dir, Webhooks: h.webhooks, Resolver: resolver,
		Domain: "mx.sender.test", Port: port,
		BackoffBase: time.Hour, BackoffMax: time.Hour, // don't actually re-fire within this test
		MaxAttempts: 10, PollInterval: 2 * time.Millisecond, DialTimeout: 2 * time.Second,
	})

	job := h.stageJob(t, "sender.test", "alice@sender.test", "bob@remote.test", "Subject: hi\r\n\r\nhello\r\n")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var events []firedEvent
	for time.Now().Before(deadline) {
		events = h.webhooks.all()
		if len(events) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if len(events) != 1 || events[0].EventType != "message.deferred" {
		t.Fatalf("expected exactly one message.deferred event, got %+v", events)
	}
	if h.q.Empty() {
		t.Fatal("expected the job to remain in the queue for retry, not be removed")
	}
	// The huge backoff means it isn't immediately due again.
	if _, ok, err := h.q.Dequeue(context.Background()); err != nil || ok {
		t.Fatalf("job should not be immediately due again (rescheduled far in the future): ok=%v err=%v", ok, err)
	}
	if job.To != "bob@remote.test" {
		t.Fatalf("unexpected job: %+v", job)
	}
}

func TestDeliverExhaustsAttemptsThenBounces(t *testing.T) {
	h := newHarness(t)
	mta := &fakeMTA{dataErr: &gosmtp.SMTPError{Code: 450, Message: "try again later"}}
	port := startFakeMTA(t, mta)
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {{Host: "127.0.0.1", Pref: 10}},
	}}
	d := deliverer.New(deliverer.Config{
		Queue: h.q, Store: h.store, Directory: h.dir, Webhooks: h.webhooks, Resolver: resolver,
		Domain: "mx.sender.test", Port: port,
		BackoffBase: time.Millisecond, BackoffMax: 5 * time.Millisecond,
		MaxAttempts: 3, PollInterval: 2 * time.Millisecond, DialTimeout: 2 * time.Second,
	})

	h.stageJob(t, "sender.test", "alice@sender.test", "bob@remote.test", "Subject: hi\r\n\r\nhello\r\n")
	runUntilDrained(t, d, h.q)

	events := h.webhooks.all()
	deferredCount, bouncedCount := 0, 0
	for _, e := range events {
		switch e.EventType {
		case "message.deferred":
			deferredCount++
		case "message.bounced":
			bouncedCount++
		}
	}
	if deferredCount != 2 || bouncedCount != 1 {
		t.Fatalf("expected 2 deferrals then 1 bounce after exhausting 3 attempts, got %+v", events)
	}

	metas, err := h.store.List(context.Background(), "sender.test", directory.MailboxPath("alice", "INBOX"))
	if err != nil || len(metas) != 1 {
		t.Fatalf("expected a DSN after exhausting attempts: metas=%+v err=%v", metas, err)
	}
}

func TestDeliverFallsBackToNextMXOnConnectionFailure(t *testing.T) {
	h := newHarness(t)
	mta := &fakeMTA{}
	port := startFakeMTA(t, mta)
	// MX1 (lower preference number = tried first) points at 127.0.0.2 on
	// the same port, where nothing listens -> connection refused. MX2 is
	// the real fake MTA on 127.0.0.1. A real deliverer must fall back to
	// MX2 rather than giving up after MX1's connection failure.
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {
			{Host: "127.0.0.2", Pref: 1},
			{Host: "127.0.0.1", Pref: 10},
		},
	}}
	d := newTestDeliverer(h, resolver, port)

	h.stageJob(t, "sender.test", "alice@sender.test", "bob@remote.test", "Subject: hi\r\n\r\nhello\r\n")
	runUntilDrained(t, d, h.q)

	if got := mta.all(); len(got) != 1 {
		t.Fatalf("expected delivery to fall back to the second MX host, got %+v", got)
	}
}

func TestDeliverUnknownDomainBounces(t *testing.T) {
	h := newHarness(t)
	resolver := fakeResolver{mxs: map[string][]*net.MX{}}
	d := newTestDeliverer(h, resolver, 25)

	h.stageJob(t, "sender.test", "alice@sender.test", "bob@no-such-domain.test", "Subject: hi\r\n\r\nhello\r\n")
	runUntilDrained(t, d, h.q)

	events := h.webhooks.all()
	if len(events) != 1 || events[0].EventType != "message.bounced" {
		t.Fatalf("expected an immediate bounce for a domain with no MX records, got %+v", events)
	}
}

func TestPerDomainConcurrencyCapIsRespected(t *testing.T) {
	h := newHarness(t)
	const domainCap = 2
	const jobCount = 6

	var inFlight, maxInFlight int32
	release := make(chan struct{})
	mta := &fakeMTA{onData: func() {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&maxInFlight)
			if n <= old || atomic.CompareAndSwapInt32(&maxInFlight, old, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inFlight, -1)
	}}
	port := startFakeMTA(t, mta)
	resolver := fakeResolver{mxs: map[string][]*net.MX{
		"remote.test": {{Host: "127.0.0.1", Pref: 10}},
	}}
	d := deliverer.New(deliverer.Config{
		Queue: h.q, Store: h.store, Directory: h.dir, Webhooks: h.webhooks, Resolver: resolver,
		Domain: "mx.sender.test", Port: port, PerDomainConcurrency: domainCap,
		PollInterval: 2 * time.Millisecond, DialTimeout: 2 * time.Second,
	})

	for i := 0; i < jobCount; i++ {
		h.stageJob(t, "sender.test", "alice@sender.test", fmt.Sprintf("bob%d@remote.test", i), "Subject: hi\r\n\r\nhello\r\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()

	// Let every job reach (and block in) onData, then confirm the observed
	// peak never exceeded domainCap before releasing them all.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&inFlight) < domainCap && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // give any over-cap goroutine a chance to (wrongly) start
	if got := atomic.LoadInt32(&inFlight); got > domainCap {
		t.Fatalf("in-flight deliveries (%d) exceeded the per-domain cap (%d)", got, domainCap)
	}
	close(release)

	runUntilDrainedFrom(t, h.q, done, cancel)

	if got := atomic.LoadInt32(&maxInFlight); got > domainCap {
		t.Fatalf("observed peak in-flight deliveries (%d) exceeded the per-domain cap (%d)", got, domainCap)
	}
}

func runUntilDrainedFrom(t *testing.T, q *queue.MemoryBackend, done chan struct{}, cancel context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !q.Empty() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if !q.Empty() {
		t.Fatal("timed out waiting for the outbound queue to drain")
	}
}
