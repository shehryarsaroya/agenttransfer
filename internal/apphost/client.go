package apphost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxClientResponseBytes = 32 << 20

// Client speaks the authenticated runner protocol over a Unix socket.
type Client struct {
	socket string
	token  string
	max    int64
	http   *http.Client
}

// APIError is returned for a non-2xx runner response.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("apphost runner: HTTP %d: %s", e.StatusCode, e.Message)
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.SocketPath == "" || strings.IndexByte(cfg.SocketPath, 0) >= 0 {
		return nil, errors.New("apphost: runner socket path is required")
	}
	socket, err := filepath.Abs(cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve runner socket: %w", err)
	}
	if len(cfg.AuthToken) < 32 || len(cfg.AuthToken) > 4096 || hasControl(cfg.AuthToken) || strings.TrimSpace(cfg.AuthToken) != cfg.AuthToken {
		return nil, errors.New("apphost: runner auth token must be 32-4096 bytes")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 20 << 20
	}
	if cfg.MaxResponseBytes > maxClientResponseBytes {
		return nil, fmt.Errorf("apphost: MaxResponseBytes may not exceed %d", maxClientResponseBytes)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		socket: socket,
		token:  cfg.AuthToken,
		max:    cfg.MaxResponseBytes,
		http:   &http.Client{Transport: transport, Timeout: cfg.Timeout},
	}, nil
}

func (c *Client) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *Client) Health(ctx context.Context) error {
	var out healthResult
	if err := c.do(ctx, http.MethodGet, apiPrefix+"/health", nil, &out); err != nil {
		return err
	}
	if !out.OK {
		return errors.New("apphost: runner reported unhealthy")
	}
	return nil
}

func (c *Client) Build(ctx context.Context, req BuildRequest) (BuildResult, error) {
	var out BuildResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/build", req, &out)
	return out, err
}

func (c *Client) Deploy(ctx context.Context, req DeployRequest) (DeployResponse, error) {
	var out DeployResponse
	err := c.do(ctx, http.MethodPost, apiPrefix+"/deploy", req, &out)
	return out, err
}

func (c *Client) Status(ctx context.Context, appID string) (AppStatus, error) {
	if err := validateAppID(appID); err != nil {
		return AppStatus{}, err
	}
	var out AppStatus
	err := c.do(ctx, http.MethodGet, apiPrefix+"/apps/"+url.PathEscape(appID)+"/status", nil, &out)
	return out, err
}

func (c *Client) RuntimeStatus(ctx context.Context, runtimeID string) (AppStatus, error) {
	if err := validateRuntimeID(runtimeID); err != nil {
		return AppStatus{}, err
	}
	var out AppStatus
	err := c.do(ctx, http.MethodGet, apiPrefix+"/runtimes/"+url.PathEscape(runtimeID)+"/status", nil, &out)
	return out, err
}

func (c *Client) StatusRuntime(ctx context.Context, runtimeID string) (AppStatus, error) {
	return c.RuntimeStatus(ctx, runtimeID)
}

func (c *Client) Logs(ctx context.Context, appID string, tail int) (LogsResult, error) {
	if err := validateAppID(appID); err != nil {
		return LogsResult{}, err
	}
	path := apiPrefix + "/apps/" + url.PathEscape(appID) + "/logs"
	if tail != 0 {
		if tail < 1 {
			return LogsResult{}, errors.New("tail must be positive")
		}
		path += "?tail=" + strconv.Itoa(tail)
	}
	var out LogsResult
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) RuntimeLogs(ctx context.Context, runtimeID string, tail int) (LogsResult, error) {
	if err := validateRuntimeID(runtimeID); err != nil {
		return LogsResult{}, err
	}
	path := apiPrefix + "/runtimes/" + url.PathEscape(runtimeID) + "/logs"
	if tail != 0 {
		if tail < 1 {
			return LogsResult{}, errors.New("tail must be positive")
		}
		path += "?tail=" + strconv.Itoa(tail)
	}
	var out LogsResult
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) LogsRuntime(ctx context.Context, runtimeID string, tail int) (LogsResult, error) {
	return c.RuntimeLogs(ctx, runtimeID, tail)
}

func (c *Client) Stop(ctx context.Context, appID string) (StopResult, error) {
	if err := validateAppID(appID); err != nil {
		return StopResult{}, err
	}
	var out StopResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/apps/"+url.PathEscape(appID)+"/stop", nil, &out)
	return out, err
}

func (c *Client) StopRuntime(ctx context.Context, runtimeID string) (StopResult, error) {
	if err := validateRuntimeID(runtimeID); err != nil {
		return StopResult{}, err
	}
	var out StopResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/runtimes/"+url.PathEscape(runtimeID)+"/stop", nil, &out)
	return out, err
}

func (c *Client) RemoveRuntime(ctx context.Context, runtimeID string) (RemoveResult, error) {
	if err := validateRuntimeID(runtimeID); err != nil {
		return RemoveResult{}, err
	}
	var out RemoveResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/runtimes/"+url.PathEscape(runtimeID)+"/remove", nil, &out)
	return out, err
}

func (c *Client) RemoveApp(ctx context.Context, appID string) (RemoveAppResult, error) {
	if err := validateAppID(appID); err != nil {
		return RemoveAppResult{}, err
	}
	var out RemoveAppResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/apps/"+url.PathEscape(appID)+"/remove", nil, &out)
	return out, err
}

func (c *Client) ReconcileApp(ctx context.Context, appID, keepRuntimeID string) (ReconcileResult, error) {
	if err := validateAppID(appID); err != nil {
		return ReconcileResult{}, err
	}
	if err := validateRuntimeID(keepRuntimeID); err != nil {
		return ReconcileResult{}, err
	}
	var out ReconcileResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/apps/"+url.PathEscape(appID)+"/reconcile",
		ReconcileRequest{KeepRuntimeID: keepRuntimeID}, &out)
	return out, err
}

func (c *Client) Purge(ctx context.Context, appID string) (PurgeResult, error) {
	if err := validateAppID(appID); err != nil {
		return PurgeResult{}, err
	}
	var out PurgeResult
	err := c.do(ctx, http.MethodPost, apiPrefix+"/apps/"+url.PathEscape(appID)+"/purge", nil, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("apphost: encode request: %w", err)
		}
		if len(data) > maxRequestBytes {
			return fmt.Errorf("apphost: request exceeds %d bytes", maxRequestBytes)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://apphost"+path, body)
	if err != nil {
		return fmt.Errorf("apphost: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("apphost: runner request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil {
		return fmt.Errorf("apphost: read runner response: %w", err)
	}
	if int64(len(data)) > c.max {
		return fmt.Errorf("apphost: runner response exceeds %d bytes", c.max)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope errorEnvelope
		if json.Unmarshal(data, &envelope) != nil || envelope.Error == "" {
			envelope.Error = strings.TrimSpace(string(data))
			if envelope.Error == "" {
				envelope.Error = http.StatusText(resp.StatusCode)
			}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: envelope.Error}
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("apphost: decode runner response: %w", err)
	}
	return nil
}
