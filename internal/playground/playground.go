// Package playground backs the browser demo: it lists a bundle's entries and makes
// controlled edits so visitors can watch the verifier reject them. It never touches a
// filesystem, and every read is capped because the bundle is untrusted input.
package playground

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	maxEntries   = 64
	maxTextBytes = 256 << 10
	maxEditTotal = 20 << 20
)

type Entry struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Text      string `json:"text"`
	Binary    bool   `json:"binary,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

func open(raw []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, fmt.Errorf("bukan arsip zip yang valid: %w", err)
	}
	if len(zr.File) > maxEntries {
		return nil, fmt.Errorf("jumlah berkas %d melebihi batas %d", len(zr.File), maxEntries)
	}
	return zr, nil
}

// Entries lists every entry with at most 256 KiB of its text, so even a decompression
// bomb only costs a bounded read.
func Entries(raw []byte) ([]Entry, error) {
	zr, err := open(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(zr.File))
	for _, f := range zr.File {
		e := Entry{Name: f.Name, Size: f.UncompressedSize64}
		if rc, err := f.Open(); err == nil {
			data, _ := io.ReadAll(io.LimitReader(rc, maxTextBytes+1))
			rc.Close()
			if len(data) > maxTextBytes {
				data, e.Truncated = data[:maxTextBytes], true
			}
			if utf8.Valid(data) {
				e.Text = string(data)
			} else {
				e.Binary = true
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// Edit returns a re-zipped copy of the bundle with one entry replaced, removed, or added.
// Untouched entries keep their exact bytes, so manifest.json and its signature stay
// valid and the verifier pinpoints only the edited artifact.
func Edit(raw []byte, op, name string, content []byte) ([]byte, error) {
	zr, err := open(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(n string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	found := false
	var total int64
	for _, f := range zr.File {
		data := content
		if f.Name == name {
			found = true
			if op == "remove" {
				continue
			}
			if op == "add" {
				return nil, fmt.Errorf("berkas %q sudah ada", name)
			}
		}
		if f.Name != name || op != "replace" {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, err = io.ReadAll(io.LimitReader(rc, maxEditTotal-total+1))
			rc.Close()
			if err != nil {
				return nil, err
			}
		}
		if total += int64(len(data)); total > maxEditTotal {
			return nil, fmt.Errorf("bundle terlalu besar untuk diubah di browser")
		}
		if err := write(f.Name, data); err != nil {
			return nil, err
		}
	}
	switch {
	case op == "add":
		if err := write(name, content); err != nil {
			return nil, err
		}
	case op != "replace" && op != "remove":
		return nil, fmt.Errorf("operasi tidak dikenal: %q", op)
	case !found:
		return nil, fmt.Errorf("berkas %q tidak ada di bundle", name)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
