package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type MemoryStore struct {
	mu       sync.Mutex
	kv       map[string]string
	sessions map[string]AdminSession
	oidcTxs  map[string]oidcMemTx
	audits   []AuditLog
}

type oidcMemTx struct {
	OIDCTransaction
	used bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		kv:       make(map[string]string),
		sessions: make(map[string]AdminSession),
		oidcTxs:  make(map[string]oidcMemTx),
	}
}

func (m *MemoryStore) Ping(context.Context) error { return nil }

func (m *MemoryStore) ReapExpired(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for k, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, k)
		}
	}
	for k, tx := range m.oidcTxs {
		if now.After(tx.ExpiresAt) {
			delete(m.oidcTxs, k)
		}
	}
	return nil
}

func (m *MemoryStore) GetOrCreateKV(_ context.Context, key string, generate func() (string, error)) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.kv[key]; ok {
		return v, nil
	}
	v, err := generate()
	if err != nil {
		return "", err
	}
	m.kv[key] = v
	return v, nil
}

func (m *MemoryStore) CreateSession(_ context.Context, sess AdminSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	m.sessions[hex.EncodeToString(sess.TokenHash)] = sess
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, tokenHash []byte) (AdminSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hex.EncodeToString(tokenHash)]
	if !ok || time.Now().UTC().After(s.ExpiresAt) {
		return AdminSession{}, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hex.EncodeToString(tokenHash))
	return nil
}

func (m *MemoryStore) CreateOIDCTransaction(_ context.Context, tx OIDCTransaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.oidcTxs[hex.EncodeToString(tx.TxHash)] = oidcMemTx{OIDCTransaction: tx}
	return nil
}

func (m *MemoryStore) ConsumeOIDCTransaction(_ context.Context, txHash []byte) (OIDCTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := hex.EncodeToString(txHash)
	tx, ok := m.oidcTxs[k]
	if !ok || tx.used || time.Now().UTC().After(tx.ExpiresAt) {
		return OIDCTransaction{}, ErrNotFound
	}
	tx.used = true
	m.oidcTxs[k] = tx
	return tx.OIDCTransaction, nil
}

func (m *MemoryStore) AppendAuditLog(_ context.Context, entry AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	if len(entry.Details) == 0 {
		entry.Details = json.RawMessage(`{}`)
	}
	m.audits = append(m.audits, entry)
	return nil
}

func (m *MemoryStore) ListAuditLogs(_ context.Context, f AuditFilter) ([]AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc := strings.TrimSpace(f.Service)
	act := strings.TrimSpace(f.Action)

	matched := make([]AuditLog, 0, len(m.audits))
	for _, a := range m.audits {
		if svc != "" && a.TargetService != svc {
			continue
		}
		if act != "" && a.Action != act {
			continue
		}
		matched = append(matched, a)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := max(f.Offset, 0)
	if offset >= len(matched) {
		return []AuditLog{}, nil
	}
	end := min(offset+limit, len(matched))
	return matched[offset:end], nil
}
