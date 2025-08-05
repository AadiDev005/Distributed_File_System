// store.go – fixed “is a directory” bug, supports flat & CAS storage
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const defaultRootFolderName = "ggnetwork"

/*────────────────────────────  path helpers  ───────────────────────────*/

// CAS layout – unchanged
func CASPathTransformFunc(key string) PathKey {
	hash := sha1.Sum([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	const block = 5
	sliceLen := len(hashStr) / block
	paths := make([]string, sliceLen)
	for i := 0; i < sliceLen; i++ {
		from, to := i*block, i*block+block
		paths[i] = hashStr[from:to]
	}
	return PathKey{PathName: filepath.Join(paths...), Filename: hashStr}
}

type PathTransformFunc func(string) PathKey

// A logical file location (PathName may be “”, Filename MUST be set)
type PathKey struct {
	PathName string
	Filename string
}

func (p PathKey) FirstPathName() string {
	if p.PathName == "" {
		return ""
	}
	parts := strings.Split(filepath.ToSlash(p.PathName), "/")
	return parts[0]
}

// Join safely, even when PathName is empty
func (p PathKey) FullPath() string {
	if p.PathName == "" {
		return p.Filename
	}
	return filepath.Join(p.PathName, p.Filename)
}

/*────────────────────────────  store struct  ───────────────────────────*/

type StoreOpts struct {
	Root              string
	PathTransformFunc PathTransformFunc
}

// **Flat** transform: no sub-dirs, one file per key
var DefaultPathTransformFunc = func(key string) PathKey {
	return PathKey{
		PathName: "",  // <- DO NOT create “key/” as a folder
		Filename: key, // actual file on disk
	}
}

type Store struct{ StoreOpts }

func NewStore(opts StoreOpts) *Store {
	if opts.PathTransformFunc == nil {
		opts.PathTransformFunc = DefaultPathTransformFunc
	}
	if opts.Root == "" {
		opts.Root = defaultRootFolderName
	}
	return &Store{StoreOpts: opts}
}

/*────────────────────────────  public API  ─────────────────────────────*/

func (s *Store) Has(id, key string) bool {
	pk := s.PathTransformFunc(key)
	full := filepath.Join(s.Root, id, pk.FullPath())
	_, err := os.Stat(full)
	return !errors.Is(err, os.ErrNotExist)
}

func (s *Store) Clear() error { return os.RemoveAll(s.Root) }

func (s *Store) Delete(id, key string) error {
	pk := s.PathTransformFunc(key)
	target := filepath.Join(s.Root, id, pk.FirstPathName())
	if target == filepath.Join(s.Root, id) { // flat file – delete file only
		file := filepath.Join(target, pk.Filename)
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete %s: %w", file, err)
		}
		log.Printf("deleted [%s] from disk", pk.Filename)
		return nil
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("delete %s: %w", target, err)
	}
	log.Printf("deleted CAS dir [%s]", pk.FirstPathName())
	return nil
}

func (s *Store) Write(id, key string, r io.Reader) (int64, error) {
	return s.writeStream(id, key, r)
}

func (s *Store) WriteDecrypt(encKey []byte, id, key string, r io.Reader) (int64, error) {
	f, err := s.openFileForWriting(id, key)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := copyDecrypt(encKey, r, f)
	return int64(n), err
}

func (s *Store) Read(id, key string) (int64, io.ReadCloser, error) {
	return s.readStream(id, key)
}

/*──────────────────────────  internal helpers  ─────────────────────────*/

func (s *Store) openFileForWriting(id, key string) (*os.File, error) {
	pk := s.PathTransformFunc(key)

	// directory that must exist
	dir := filepath.Join(s.Root, id)
	if pk.PathName != "" {
		dir = filepath.Join(dir, pk.PathName)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	full := filepath.Join(dir, pk.Filename)
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", full, err)
	}
	return f, nil
}

func (s *Store) writeStream(id, key string, r io.Reader) (int64, error) {
	f, err := s.openFileForWriting(id, key)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, r)
}

func (s *Store) readStream(id, key string) (int64, io.ReadCloser, error) {
	pk := s.PathTransformFunc(key)
	full := filepath.Join(s.Root, id, pk.FullPath())

	f, err := os.Open(full)
	if err != nil {
		return 0, nil, fmt.Errorf("open %s: %w", full, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return 0, nil, fmt.Errorf("stat %s: %w", full, err)
	}
	return fi.Size(), f, nil
}
