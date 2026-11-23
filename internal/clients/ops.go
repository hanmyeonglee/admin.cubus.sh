package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	opsTimeout      = 10 * time.Second
	opsMaxBodyBytes = 8 << 20
)

var ErrNotConfigured = errors.New("client endpoint not configured")

type OpsClient struct {
	baseURL      string
	client       *http.Client
	streamClient *http.Client
	devToken     string
}

func NewOpsClient(baseURL, devToken string) *OpsClient {
	return &OpsClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client: &http.Client{
			Timeout: opsTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		streamClient: &http.Client{
			Timeout: 0, // Long-lived SSE stream
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		devToken: devToken,
	}
}

func (c *OpsClient) Configured() bool {
	return c.baseURL != ""
}

type DiscoveredService struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	AdminIP string `json:"admin_ip"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	Health  string `json:"health,omitempty"`
}

func (c *OpsClient) GetSystemRaw(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/ops/v1/system")
}

func (c *OpsClient) GetContainersRaw(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/ops/v1/containers")
}

func (c *OpsClient) GetServices(ctx context.Context) ([]DiscoveredService, error) {
	raw, err := c.getRaw(ctx, "/ops/v1/services")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Services []DiscoveredService `json:"services"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return resp.Services, nil
}

func (c *OpsClient) SearchLogsRaw(ctx context.Context, q url.Values) (json.RawMessage, int, error) {
	if c.baseURL == "" {
		return nil, http.StatusServiceUnavailable, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ops/v1/logs/search?"+q.Encode(), nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if c.devToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.devToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, opsMaxBodyBytes))
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	if !json.Valid(body) {
		return nil, http.StatusBadGateway, errors.New("ops-agent returned invalid JSON")
	}
	return json.RawMessage(body), resp.StatusCode, nil
}

func (c *OpsClient) OpenLogStream(ctx context.Context, service string, tail string) (*http.Response, error) {
	if c.baseURL == "" {
		return nil, ErrNotConfigured
	}
	q := url.Values{"service": {service}}
	if tail != "" {
		q.Set("tail", tail)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ops/v1/logs/stream?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.devToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.devToken)
	}
	return c.streamClient.Do(req)
}

func (c *OpsClient) getRaw(ctx context.Context, path string) (json.RawMessage, error) {
	if c.baseURL == "" {
		return nil, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.devToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.devToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, opsMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ops-agent %s returned status %d", path, resp.StatusCode)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("ops-agent %s returned invalid JSON", path)
	}
	return json.RawMessage(body), nil
}
