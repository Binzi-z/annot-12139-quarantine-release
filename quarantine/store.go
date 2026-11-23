package quarantine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Store owns the on-disk layout:
//
//	<dir>/blobs/<sha256>      immutable frozen uploads
//	<dir>/release/<name>      released files, names embed tenant/digest/task
//	<dir>/state.json          committed results and request index
//
// The state file is replaced atomically (write temp, fsync, rename), which is
// atomic on Windows for same-volume renames of a closed file.
type Store struct {
	dir     string
	blobDir string
	relDir  string
	state   string
	lock    *fileLock
}

// NewStore prepares the directory layout.
func NewStore(dir string, useFileLock bool) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("quarantine: empty data dir")
	}
	s := &Store{
		dir:     dir,
		blobDir: filepath.Join(dir, "blobs"),
		relDir:  filepath.Join(dir, "release"),
		state:   filepath.Join(dir, "state.json"),
	}
	for _, d := range []string{s.dir, s.blobDir, s.relDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("quarantine: create %s: %w", d, err)
		}
	}
	if useFileLock {
		lk, err := acquireFileLock(filepath.Join(dir, "state.lock"))
		if err != nil {
			return nil, err
		}
		s.lock = lk
	}
	return s, nil
}

// Dir returns the store root.
func (s *Store) Dir() string { return s.dir }

// BlobDir returns the immutable blob directory.
func (s *Store) BlobDir() string { return s.blobDir }

// ReleaseDir returns the release directory.
func (s *Store) ReleaseDir() string { return s.relDir }

// BlobPath returns the path of the blob for d.
func (s *Store) BlobPath(d Digest) string { return filepath.Join(s.blobDir, string(d)) }

// FrozenBlob reads a frozen blob and checks the digest still matches.
func (s *Store) FrozenBlob(d Digest) ([]byte, string, error) {
	p := s.BlobPath(d)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, p, ErrBlobMissing
		}
		return nil, p, err
	}
	if DigestBytes(b) != d {
		return nil, p, fmt.Errorf("%w: %s", ErrBlobMissing, d)
	}
	return b, p, nil
}

func (s *Store) dropBlob(d Digest) error {
	err := os.Remove(s.BlobPath(d))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Save atomically writes the state.
func (s *Store) Save(st diskState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.state); err != nil {
		return err
	}
	return nil
}

// Load reads the state. ok is false when no state file exists yet.
func (s *Store) Load() (diskState, bool, error) {
	var st diskState
	b, err := os.ReadFile(s.state)
	if err != nil {
		if os.IsNotExist(err) {
			return st, false, nil
		}
		return st, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, false, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	return st, true, nil
}

// Close releases the optional file lock.
func (s *Store) Close() error {
	if s.lock != nil {
		return s.lock.release()
	}
	return nil
}

// WriteFrozenBlob stores b under its digest without ever overwriting existing
// content. It returns the digest.
func (s *Store) WriteFrozenBlob(b []byte) (Digest, error) {
	d := DigestBytes(b)
	p := s.BlobPath(d)
	if existing, err := os.ReadFile(p); err == nil {
		if DigestBytes(existing) == d {
			return d, nil
		}
		// Corrupt blob with the same name: quarantine it and rewrite.
		if err := os.Remove(p); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(s.blobDir, ".upload-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, p); err != nil {
		// Another writer may have won the race; accept a correct existing blob.
		if existing, rerr := os.ReadFile(p); rerr == nil && DigestBytes(existing) == d {
			return d, nil
		}
		return "", err
	}
	return d, nil
}
