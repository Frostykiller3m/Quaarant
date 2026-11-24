package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// apiClient talks to one Firecracker's API socket (only what snapshots need).
type apiClient struct{ c *http.Client }

func newAPI(sock string) *apiClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &apiClient{c: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// put sends a PUT with a JSON body; Firecracker answers 204 on success.
func (a *apiClient) put(ctx context.Context, path string, body any) error {
	return a.do(ctx, http.MethodPut, path, body)
}

// patch sends a PATCH (e.g. /vm to pause or resume).
func (a *apiClient) patch(ctx context.Context, path string, body any) error {
	return a.do(ctx, http.MethodPatch, path, body)
}

func (a *apiClient) do(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("firecracker api %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("firecracker api %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker api %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("firecracker api %s: %s: %s", path, resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
