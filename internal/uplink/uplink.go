// Package uplink ships outbox bundles to the vault whenever a link is available.
// Failed uploads stay in the outbox and are retried (store-and-forward for DDIL).
package uplink

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func Flush(outbox, vaultURL, token, nodeID string) (int, error) {
	paths, err := filepath.Glob(filepath.Join(outbox, "*.zip"))
	if err != nil || len(paths) == 0 {
		return 0, err
	}
	sentDir := filepath.Join(outbox, "sent")
	if err := os.MkdirAll(sentDir, 0o700); err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	sent := 0
	for _, p := range paths {
		if err := upload(client, p, vaultURL, token, nodeID); err != nil {
			return sent, err
		}
		if err := os.Rename(p, filepath.Join(sentDir, filepath.Base(p))); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func upload(c *http.Client, path, vaultURL, token, nodeID string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("note", "uplink dari "+nodeID); err != nil {
		return err
	}
	fw, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, vaultURL+"/api/bundles", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("vault %s: %s", resp.Status, msg)
	}
	return nil
}
