package maildir

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/envelope-mx/envelope/internal/storage"
)

const (
	dirNew = "new"
	dirCur = "cur"
	dirTmp = "tmp"

	infoSep = ":2," // maildir "info" separator introducing the flags suffix
)

// maildirFlagLetters maps storage's backend-agnostic IMAP flag names to the
// single-letter codes the maildir spec (and every maildir-aware MUA) uses in
// the filename info suffix. Kept private to this file so no caller outside
// it holds a maildir-specific assumption about flag encoding (FR-4.1).
var maildirFlagLetters = map[string]byte{
	storage.FlagDraft:    'D',
	storage.FlagFlagged:  'F',
	storage.FlagAnswered: 'R',
	storage.FlagSeen:     'S',
	storage.FlagDeleted:  'T',
}

var letterToFlag = func() map[byte]string {
	m := make(map[byte]string, len(maildirFlagLetters))
	for flag, letter := range maildirFlagLetters {
		m[letter] = flag
	}
	return m
}()

var seq uint64 // monotonic counter, disambiguates same-nanosecond writes

// Backend implements storage.Store on the standard Maildir layout
// (new/cur/tmp), namespaced {base}/{vhost}/{mailbox}/ (FR-4.2).
type Backend struct {
	base string
}

// New returns a maildir Backend rooted at base.
func New(base string) *Backend {
	return &Backend{base: base}
}

var _ storage.Store = (*Backend)(nil)

func (b *Backend) mailboxDir(vhost, mailbox string) string {
	return filepath.Join(b.base, vhost, mailbox)
}

func (b *Backend) ensureMailboxDirs(vhost, mailbox string) (string, error) {
	dir := b.mailboxDir(vhost, mailbox)
	for _, sub := range [...]string{dirNew, dirCur, dirTmp} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return "", fmt.Errorf("maildir: create %s/%s: %w", dir, sub, err)
		}
	}
	return dir, nil
}

func uniqueName() string {
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	n := atomic.AddUint64(&seq, 1)
	return fmt.Sprintf("%d.%d_%d.%s", time.Now().UnixNano(), os.Getpid(), n, host)
}

// Write persists body as a new message: written to tmp/, then linked into
// new/ per the maildir delivery protocol (a reader must never observe a
// partially-written file under new/ or cur/).
func (b *Backend) Write(ctx context.Context, vhost, mailbox string, body io.Reader) (storage.MessageRef, error) {
	if ctx.Err() != nil {
		return storage.MessageRef{}, ctx.Err()
	}

	dir, err := b.ensureMailboxDirs(vhost, mailbox)
	if err != nil {
		return storage.MessageRef{}, err
	}

	name := uniqueName()
	tmpPath := filepath.Join(dir, dirTmp, name)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return storage.MessageRef{}, fmt.Errorf("maildir: create tmp file: %w", err)
	}
	if _, err := io.Copy(f, body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return storage.MessageRef{}, fmt.Errorf("maildir: write tmp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return storage.MessageRef{}, fmt.Errorf("maildir: sync tmp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return storage.MessageRef{}, fmt.Errorf("maildir: close tmp file: %w", err)
	}

	newPath := filepath.Join(dir, dirNew, name)
	if err := os.Rename(tmpPath, newPath); err != nil {
		os.Remove(tmpPath)
		return storage.MessageRef{}, fmt.Errorf("maildir: deliver to new: %w", err)
	}

	return storage.MessageRef{Vhost: vhost, Mailbox: mailbox, Key: name}, nil
}

// locate finds the on-disk path and flags for ref's key, searching new/
// (undelivered/no flags) then cur/ (delivered, may carry an info suffix).
func (b *Backend) locate(ref storage.MessageRef) (path string, flags []string, inNew bool, err error) {
	dir := b.mailboxDir(ref.Vhost, ref.Mailbox)

	newPath := filepath.Join(dir, dirNew, ref.Key)
	if _, statErr := os.Stat(newPath); statErr == nil {
		return newPath, nil, true, nil
	}

	entries, readErr := os.ReadDir(filepath.Join(dir, dirCur))
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return "", nil, false, fmt.Errorf("maildir: message %q not found: %w", ref.Key, os.ErrNotExist)
		}
		return "", nil, false, fmt.Errorf("maildir: read cur: %w", readErr)
	}
	for _, e := range entries {
		base, info, hasInfo := strings.Cut(e.Name(), infoSep)
		if base != ref.Key {
			continue
		}
		if hasInfo {
			flags = decodeFlags(info)
		}
		return filepath.Join(dir, dirCur, e.Name()), flags, false, nil
	}

	return "", nil, false, fmt.Errorf("maildir: message %q not found: %w", ref.Key, os.ErrNotExist)
}

func (b *Backend) Read(ctx context.Context, ref storage.MessageRef) (io.ReadCloser, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	path, _, _, err := b.locate(ref)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (b *Backend) List(ctx context.Context, vhost, mailbox string) ([]storage.MessageMeta, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	dir := b.mailboxDir(vhost, mailbox)

	var out []storage.MessageMeta
	for sub, isNew := range map[string]bool{dirNew: true, dirCur: false} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("maildir: read %s: %w", sub, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return nil, fmt.Errorf("maildir: stat %s: %w", e.Name(), err)
			}

			var key string
			var flags []string
			if isNew {
				key = e.Name()
			} else {
				base, suffix, hasInfo := strings.Cut(e.Name(), infoSep)
				key = base
				if hasInfo {
					flags = decodeFlags(suffix)
				}
			}

			out = append(out, storage.MessageMeta{
				Ref:       storage.MessageRef{Vhost: vhost, Mailbox: mailbox, Key: key},
				Size:      info.Size(),
				Flags:     flags,
				CreatedAt: info.ModTime(),
			})
		}
	}
	return out, nil
}

// ListVhost enumerates every message under vhost's directory, across every
// mailbox — unlike Postgres's single indexed query, maildir has no
// per-vhost index to query, so this walks the filesystem to find every
// leaf mailbox directory (identified by the presence of a "new"
// subdirectory — every real mailbox dir has one, created by
// ensureMailboxDirs) and reuses List's own per-mailbox logic for each.
// Mailbox identifiers can be nested (directory.MailboxPath joins a
// recipient's local-part and folder with "/", e.g. "alice/INBOX", while
// submission's Outbox is a flat top-level mailbox) — walking rather than a
// fixed-depth listing handles both without hard-coding that convention
// here.
func (b *Backend) ListVhost(ctx context.Context, vhost string) ([]storage.MessageMeta, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	vhostDir := filepath.Join(b.base, vhost)
	if _, err := os.Stat(vhostDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("maildir: stat vhost dir: %w", err)
	}

	var mailboxes []string
	seen := make(map[string]bool)
	err := filepath.WalkDir(vhostDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || d.Name() != dirNew {
			return nil
		}
		mailboxDir := filepath.Dir(path)
		rel, relErr := filepath.Rel(vhostDir, mailboxDir)
		if relErr != nil {
			return relErr
		}
		if !seen[rel] {
			seen[rel] = true
			mailboxes = append(mailboxes, rel)
		}
		return fs.SkipDir // don't descend into new/ itself
	})
	if err != nil {
		return nil, fmt.Errorf("maildir: walk vhost dir: %w", err)
	}

	var out []storage.MessageMeta
	for _, mailbox := range mailboxes {
		msgs, err := b.List(ctx, vhost, mailbox)
		if err != nil {
			return nil, err
		}
		out = append(out, msgs...)
	}
	return out, nil
}

// UpdateFlags moves the message into cur/ (if not already there) with the
// new flag set encoded in the filename's info suffix, per the maildir spec.
func (b *Backend) UpdateFlags(ctx context.Context, ref storage.MessageRef, flags []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	path, _, _, err := b.locate(ref)
	if err != nil {
		return err
	}

	dir := b.mailboxDir(ref.Vhost, ref.Mailbox)
	newName := ref.Key + infoSep + encodeFlags(flags)
	newPath := filepath.Join(dir, dirCur, newName)

	if path == newPath {
		return nil
	}
	if err := os.Rename(path, newPath); err != nil {
		return fmt.Errorf("maildir: update flags: %w", err)
	}
	return nil
}

// SetModTimeForTest backdates ref's on-disk file so tests can exercise
// age-based logic (internal/retention's purge) deterministically, without
// sleeping or exposing this backend's file layout as public API. Test-only
// by convention (the name says so), not enforced by a build tag: nothing
// in this package's production code path ever calls it.
func (b *Backend) SetModTimeForTest(ref storage.MessageRef, when time.Time) error {
	path, _, _, err := b.locate(ref)
	if err != nil {
		return err
	}
	return os.Chtimes(path, when, when)
}

func (b *Backend) Delete(ctx context.Context, ref storage.MessageRef) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	path, _, _, err := b.locate(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("maildir: delete: %w", err)
	}
	return nil
}

// encodeFlags renders flags as a maildir info suffix. Flags with no known
// maildir letter are dropped rather than corrupting the filename — an
// unrecognized IMAP flag is a caller bug the storage layer shouldn't crash
// on.
func encodeFlags(flags []string) string {
	letters := make([]byte, 0, len(flags))
	for _, f := range flags {
		if l, ok := maildirFlagLetters[f]; ok {
			letters = append(letters, l)
		}
	}
	sort.Slice(letters, func(i, j int) bool { return letters[i] < letters[j] })
	return string(letters)
}

// decodeFlags parses the letters following the ":2," info separator (the
// separator itself is already stripped by the strings.Cut call at each
// call site).
func decodeFlags(info string) []string {
	if info == "" {
		return nil
	}
	flags := make([]string, 0, len(info))
	for i := 0; i < len(info); i++ {
		if f, ok := letterToFlag[info[i]]; ok {
			flags = append(flags, f)
		}
	}
	return flags
}
