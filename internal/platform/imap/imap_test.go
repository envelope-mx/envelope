package imap_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/directory/memory"
	envimap "github.com/isaiahiroko/envelope/internal/platform/imap"

	"github.com/isaiahiroko/envelope/internal/platform"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/storage/maildir"
)

func startIMAP(t *testing.T, cfg envimap.Config) string {
	t.Helper()

	cfg.Addr = "127.0.0.1:0"
	p := envimap.NewPlatform(cfg)
	app, err := p.Boot(nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	appImpl := app.(*platform.App)
	addr := appImpl.Listener.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.Run(nil)
	}()
	t.Cleanup(func() {
		app.Shutdown()
		<-done
	})

	return addr
}

func TestIMAPLoginSelectFetchStore(t *testing.T) {
	dir := memory.New()
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	store := maildir.New(t.TempDir())

	body := "From: sender@elsewhere.test\r\nTo: alice@example.test\r\nSubject: hi\r\n\r\nbody\r\n"
	ref, err := store.Write(context.Background(), "example.test", directory.MailboxPath("alice", "INBOX"), strings.NewReader(body))
	if err != nil {
		t.Fatalf("seed Write: %v", err)
	}

	tlsCfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}
	addr := startIMAP(t, envimap.Config{Name: "test-imap", TLSConfig: tlsCfg, Directory: dir, Store: store})

	c, err := imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer c.Close()

	if err := c.Login("alice@example.test", "s3cret").Wait(); err != nil {
		t.Fatalf("Login: %v", err)
	}

	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if selectData.NumMessages != 1 {
		t.Fatalf("NumMessages = %d, want 1", selectData.NumMessages)
	}

	fetchOpts := &goimap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*goimap.FetchItemBodySection{{}},
	}
	msgs, err := c.Fetch(goimap.SeqSetNum(1), fetchOpts).Collect()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 fetched message, got %d", len(msgs))
	}
	if len(msgs[0].BodySection) != 1 || string(msgs[0].BodySection[0].Bytes) != body {
		t.Fatalf("unexpected body section: %+v", msgs[0].BodySection)
	}
	if len(msgs[0].Flags) != 0 {
		t.Fatalf("expected no flags before STORE, got %v", msgs[0].Flags)
	}

	storeFlags := &goimap.StoreFlags{Op: goimap.StoreFlagsAdd, Flags: []goimap.Flag{goimap.FlagSeen}}
	if _, err := c.Store(goimap.SeqSetNum(1), storeFlags, nil).Collect(); err != nil {
		t.Fatalf("Store: %v", err)
	}

	metas, err := store.List(context.Background(), "example.test", directory.MailboxPath("alice", "INBOX"))
	if err != nil {
		t.Fatalf("List after Store: %v", err)
	}
	if len(metas) != 1 || len(metas[0].Flags) != 1 || metas[0].Flags[0] != storage.FlagSeen {
		t.Fatalf("expected \\Seen persisted via storage.Store, got %+v", metas)
	}
	if metas[0].Ref.Key != ref.Key {
		t.Fatalf("ref mismatch: %+v vs seeded %+v", metas[0].Ref, ref)
	}
}

func TestIMAPLoginRejectsWrongPassword(t *testing.T) {
	dir := memory.New()
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	store := maildir.New(t.TempDir())

	tlsCfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}
	addr := startIMAP(t, envimap.Config{Name: "test-imap", TLSConfig: tlsCfg, Directory: dir, Store: store})

	c, err := imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer c.Close()

	if err := c.Login("alice@example.test", "wrong").Wait(); err == nil {
		t.Fatal("expected Login with wrong password to fail")
	}
}
