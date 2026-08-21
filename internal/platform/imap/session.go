package imap

import (
	"context"
	"io"
	"sort"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/storage"
)

// allFlags is advertised as both the mailbox's defined flags and its
// permanent flags: storage.Store accepts exactly this vocabulary (see
// storage.Flag* constants), so it's also the complete set IMAP clients may
// set via STORE.
var allFlags = []goimap.Flag{
	goimap.FlagSeen, goimap.FlagAnswered, goimap.FlagFlagged, goimap.FlagDeleted, goimap.FlagDraft,
}

// errNotSupported reports an IMAP command Phase 2 doesn't implement.
// FR-7.x only requires login, viewing messages, and flag mutation through
// storage.Store (FR-7.1/7.2/7.3) — folder management, search, and copy
// aren't part of any FR-7.x requirement and are deferred until real usage
// needs them (see docs/ENVELOPE.md Phase 2 scope).
func errNotSupported(command string) error {
	return &goimap.Error{
		Type: goimap.StatusResponseTypeNo,
		Text: command + " not supported",
	}
}

// session implements imapserver.Session. It only ever exposes a single
// mailbox, "INBOX", per authenticated account — multi-folder support
// (Create/Delete/Rename) isn't required by FR-7.x.
type session struct {
	cfg  Config
	conn *imapserver.Conn

	local string // set after Login
	vhost string

	mailbox string                // set after Select
	view    []storage.MessageMeta // index i => sequence number / UID i+1, snapshotted at Select
}

var _ imapserver.SessionIMAP4rev2 = (*session)(nil)

func (s *session) Close() error { return nil }

// Login authenticates against the same Directory credential store as
// submission (FR-7.2): one credential per mailbox, not a separate
// IMAP-specific store.
func (s *session) Login(username, password string) error {
	local, vhost, ok := directory.ParseAddress(username)
	if !ok || !s.cfg.Directory.Authenticate(context.Background(), vhost, local, password) {
		return imapserver.ErrAuthFailed
	}
	s.local = local
	s.vhost = vhost
	return nil
}

func (s *session) Create(string, *goimap.CreateOptions) error { return errNotSupported("CREATE") }
func (s *session) Delete(string) error                        { return errNotSupported("DELETE") }
func (s *session) Rename(string, string, *goimap.RenameOptions) error {
	return errNotSupported("RENAME")
}
func (s *session) Subscribe(string) error   { return errNotSupported("SUBSCRIBE") }
func (s *session) Unsubscribe(string) error { return errNotSupported("UNSUBSCRIBE") }

// List reports the single mailbox Phase 2 exposes: INBOX.
func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, _ *goimap.ListOptions) error {
	for _, pattern := range patterns {
		if imapserver.MatchList("INBOX", '/', ref, pattern) {
			return w.WriteList(&goimap.ListData{Mailbox: "INBOX", Delim: '/'})
		}
	}
	return nil
}

// Select snapshots the mailbox's current messages (FR-7.1). Sequence
// numbers and UIDs are assigned by this snapshot's order (Key sorts
// chronologically — see internal/storage/maildir's unique-name format) and
// are only stable for the lifetime of the selection, matching Phase 2's
// scope: no CONDSTORE/QRESYNC persistence across sessions.
func (s *session) Select(mailbox string, _ *goimap.SelectOptions) (*goimap.SelectData, error) {
	metas, err := s.listMailbox(mailbox)
	if err != nil {
		return nil, err
	}
	s.mailbox = mailbox
	s.view = metas

	return &goimap.SelectData{
		Flags:          allFlags,
		PermanentFlags: allFlags,
		NumMessages:    uint32(len(metas)),
		UIDNext:        goimap.UID(len(metas) + 1),
		UIDValidity:    1,
	}, nil
}

func (s *session) listMailbox(folder string) ([]storage.MessageMeta, error) {
	metas, err := s.cfg.Store.List(context.Background(), s.vhost, directory.MailboxPath(s.local, folder))
	if err != nil {
		return nil, err
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Ref.Key < metas[j].Ref.Key })
	return metas, nil
}

func (s *session) Status(mailbox string, options *goimap.StatusOptions) (*goimap.StatusData, error) {
	metas, err := s.listMailbox(mailbox)
	if err != nil {
		return nil, err
	}

	data := &goimap.StatusData{Mailbox: mailbox, UIDValidity: 1, UIDNext: goimap.UID(len(metas) + 1)}
	if options.NumMessages {
		n := uint32(len(metas))
		data.NumMessages = &n
	}
	return data, nil
}

func (s *session) Append(string, goimap.LiteralReader, *goimap.AppendOptions) (*goimap.AppendData, error) {
	// Messages arrive via SMTP inbound (Phase 2's smtp.Platform) or the
	// submission -> queue -> deliverer path (Phase 5); client-side APPEND
	// isn't required by FR-7.x.
	return nil, errNotSupported("APPEND")
}

// Poll reports no unilateral updates: Phase 2's view is a point-in-time
// snapshot taken at Select, not a live feed.
func (s *session) Poll(_ *imapserver.UpdateWriter, _ bool) error { return nil }

func (s *session) Idle(_ *imapserver.UpdateWriter, _ <-chan struct{}) error {
	return errNotSupported("IDLE")
}

func (s *session) Unselect() error {
	s.mailbox = ""
	s.view = nil
	return nil
}

func (s *session) Expunge(_ *imapserver.ExpungeWriter, _ *goimap.UIDSet) error {
	return errNotSupported("EXPUNGE")
}

func (s *session) Search(_ imapserver.NumKind, _ *goimap.SearchCriteria, _ *goimap.SearchOptions) (*goimap.SearchData, error) {
	return nil, errNotSupported("SEARCH")
}

// Fetch serves BODY[], FLAGS, UID, and RFC822.SIZE from the Select-time
// snapshot.
func (s *session) Fetch(w *imapserver.FetchWriter, numSet goimap.NumSet, options *goimap.FetchOptions) error {
	for i, meta := range s.view {
		seqNum := uint32(i + 1)
		uid := goimap.UID(seqNum)
		if !numSetContains(numSet, seqNum, uid) {
			continue
		}

		mw := w.CreateMessage(seqNum)
		if options.UID {
			mw.WriteUID(uid)
		}
		if options.Flags {
			mw.WriteFlags(toIMAPFlags(meta.Flags))
		}
		if options.RFC822Size {
			mw.WriteRFC822Size(meta.Size)
		}
		for _, sec := range options.BodySection {
			body, err := s.readBody(meta.Ref)
			if err != nil {
				mw.Close()
				return err
			}
			wc := mw.WriteBodySection(sec, int64(len(body)))
			if _, err := wc.Write(body); err != nil {
				wc.Close()
				mw.Close()
				return err
			}
			if err := wc.Close(); err != nil {
				mw.Close()
				return err
			}
		}
		if err := mw.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) readBody(ref storage.MessageRef) ([]byte, error) {
	rc, err := s.cfg.Store.Read(context.Background(), ref)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Store mutates flags through storage.Store.UpdateFlags (FR-7.3), keeping
// storage backends consistent regardless of access path (API vs IMAP).
func (s *session) Store(w *imapserver.FetchWriter, numSet goimap.NumSet, flags *goimap.StoreFlags, _ *goimap.StoreOptions) error {
	for i := range s.view {
		seqNum := uint32(i + 1)
		uid := goimap.UID(seqNum)
		if !numSetContains(numSet, seqNum, uid) {
			continue
		}

		meta := &s.view[i]
		newFlags := applyStoreOp(meta.Flags, flags)

		if err := s.cfg.Store.UpdateFlags(context.Background(), meta.Ref, newFlags); err != nil {
			return err
		}
		meta.Flags = newFlags

		if flags.Silent {
			continue
		}
		mw := w.CreateMessage(seqNum)
		mw.WriteFlags(toIMAPFlags(newFlags))
		if err := mw.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) Copy(goimap.NumSet, string) (*goimap.CopyData, error) {
	return nil, errNotSupported("COPY")
}

// Namespace advertises a single personal namespace with no prefix: Phase 2
// exposes exactly one mailbox (INBOX) per account, so there's no shared or
// other-users namespace to report.
func (s *session) Namespace() (*goimap.NamespaceData, error) {
	return &goimap.NamespaceData{
		Personal: []goimap.NamespaceDescriptor{{Prefix: "", Delim: '/'}},
	}, nil
}

func (s *session) Move(*imapserver.MoveWriter, goimap.NumSet, string) error {
	return errNotSupported("MOVE")
}

func numSetContains(numSet goimap.NumSet, seqNum uint32, uid goimap.UID) bool {
	switch set := numSet.(type) {
	case goimap.SeqSet:
		return set.Contains(seqNum)
	case goimap.UIDSet:
		return set.Contains(uid)
	default:
		return false
	}
}

func toIMAPFlags(flags []string) []goimap.Flag {
	out := make([]goimap.Flag, len(flags))
	for i, f := range flags {
		out[i] = goimap.Flag(f)
	}
	return out
}

func applyStoreOp(current []string, store *goimap.StoreFlags) []string {
	set := make(map[string]struct{}, len(current))
	for _, f := range current {
		set[f] = struct{}{}
	}

	switch store.Op {
	case goimap.StoreFlagsSet:
		set = make(map[string]struct{}, len(store.Flags))
		for _, f := range store.Flags {
			set[string(f)] = struct{}{}
		}
	case goimap.StoreFlagsAdd:
		for _, f := range store.Flags {
			set[string(f)] = struct{}{}
		}
	case goimap.StoreFlagsDel:
		for _, f := range store.Flags {
			delete(set, string(f))
		}
	}

	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
