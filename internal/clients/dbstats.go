package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	dbStatsTimeout      = 5 * time.Second
	dbStatsMaxBodyBytes = 1 << 20
)

type DBStatsClient struct {
	statsURL string
	client   *http.Client
}

func NewDBStatsClient(statsURL string) *DBStatsClient {
	return &DBStatsClient{
		statsURL: strings.TrimRight(strings.TrimSpace(statsURL), "/"),
		client: &http.Client{
			Timeout: dbStatsTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *DBStatsClient) Configured() bool {
	return c.statsURL != ""
}

func (c *DBStatsClient) GetRaw(ctx context.Context) (json.RawMessage, error) {
	if c.statsURL == "" {
		return nil, ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.statsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, dbStatsMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("db-broker stats returned status %d", resp.StatusCode)
	}
	return json.RawMessage(body), nil
}
