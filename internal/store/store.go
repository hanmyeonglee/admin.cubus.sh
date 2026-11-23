package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
)

type AdminSession struct {
	TokenHash []byte
	Email     string
	Name      string
	CSRFToken string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type OIDCTransaction struct {
	TxHash       []byte
	State        string
	Nonce        string
	CodeVerifier string
	NextPath     string
	ExpiresAt    time.Time
}

type AuditLog struct {
	ID            string          `json:"id"`
	ActorEmail    string          `json:"actor_email"`
	AuthMethod    string          `json:"auth_method"`
	Action        string          `json:"action"`
	TargetService string          `json:"target_service"`
	TargetID      string          `json:"target_id,omitempty"`
	Details       json.RawMessage `json:"details"`
	ClientIP      string          `json:"client_ip,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

type AuditFilter struct {
	Service string
	Action  string
	Limit   int
	Offset  int
}

type Store interface {
	Ping(ctx context.Context) error
	ReapExpired(ctx context.Context) error

	GetOrCreateKV(ctx context.Context, key string, generate func() (string, error)) (string, error)

	CreateSession(ctx context.Context, sess AdminSession) error
	GetSession(ctx context.Context, tokenHash []byte) (AdminSession, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error

	CreateOIDCTransaction(ctx context.Context, tx OIDCTransaction) error
	ConsumeOIDCTransaction(ctx context.Context, txHash []byte) (OIDCTransaction, error)

	AppendAuditLog(ctx context.Context, entry AuditLog) error
	ListAuditLogs(ctx context.Context, filter AuditFilter) ([]AuditLog, error)
}

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PGStore) ReapExpired(ctx context.Context) error {
	stmts := []string{
		`DELETE FROM admin_sessions WHERE expires_at < now()`,
		`DELETE FROM oidc_transactions WHERE expires_at < now() - INTERVAL '15 minutes'`,
	}
	for _, stmt := range stmts {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *PGStore) GetOrCreateKV(ctx context.Context, key string, generate func() (string, error)) (string, error) {
	var val string
	err := s.pool.QueryRow(ctx, `SELECT value FROM admin_kv WHERE key = $1`, key).Scan(&val)
	if err == nil {
		return val, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	generated, err := generate()
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO admin_kv (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO NOTHING
	`, key, generated)
	if err != nil {
		return "", err
	}
	err = s.pool.QueryRow(ctx, `SELECT value FROM admin_kv WHERE key = $1`, key).Scan(&val)
	return val, err
}

func (s *PGStore) CreateSession(ctx context.Context, sess AdminSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_sessions (token_hash, email, name, csrf_token, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, sess.TokenHash, sess.Email, sess.Name, sess.CSRFToken, sess.ExpiresAt)
	return err
}

func (s *PGStore) GetSession(ctx context.Context, tokenHash []byte) (AdminSession, error) {
	var sess AdminSession
	err := s.pool.QueryRow(ctx, `
		SELECT token_hash, email, name, csrf_token, expires_at, created_at
		FROM admin_sessions
		WHERE token_hash = $1 AND expires_at > now()
	`, tokenHash).Scan(&sess.TokenHash, &sess.Email, &sess.Name, &sess.CSRFToken, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminSession{}, ErrNotFound
	}
	return sess, err
}

func (s *PGStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *PGStore) CreateOIDCTransaction(ctx context.Context, tx OIDCTransaction) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_transactions (tx_hash, state, nonce, code_verifier, next_path, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, tx.TxHash, tx.State, tx.Nonce, tx.CodeVerifier, tx.NextPath, tx.ExpiresAt)
	return err
}

func (s *PGStore) ConsumeOIDCTransaction(ctx context.Context, txHash []byte) (OIDCTransaction, error) {
	var out OIDCTransaction
	err := s.pool.QueryRow(ctx, `
		UPDATE oidc_transactions
		SET used_at = now()
		WHERE tx_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING tx_hash, state, nonce, code_verifier, next_path, expires_at
	`, txHash).Scan(&out.TxHash, &out.State, &out.Nonce, &out.CodeVerifier, &out.NextPath, &out.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCTransaction{}, ErrNotFound
	}
	return out, err
}

func (s *PGStore) AppendAuditLog(ctx context.Context, entry AuditLog) error {
	details := entry.Details
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (actor_email, auth_method, action, target_service, target_id, details, client_ip)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
	`, entry.ActorEmail, entry.AuthMethod, entry.Action, entry.TargetService, entry.TargetID, string(details), entry.ClientIP)
	return err
}

func (s *PGStore) ListAuditLogs(ctx context.Context, f AuditFilter) ([]AuditLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := max(f.Offset, 0)

	args := make([]any, 0, 4)
	conds := []string{"1=1"}
	if svc := strings.TrimSpace(f.Service); svc != "" {
		args = append(args, svc)
		conds = append(conds, fmt.Sprintf("target_service = $%d", len(args)))
	}
	if act := strings.TrimSpace(f.Action); act != "" {
		args = append(args, act)
		conds = append(conds, fmt.Sprintf("action = $%d", len(args)))
	}
	args = append(args, limit, offset)

	query := fmt.Sprintf(`
		SELECT id::text, actor_email, auth_method, action, target_service, target_id, details::text, client_ip, created_at
		FROM audit_logs
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, strings.Join(conds, " AND "), len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AuditLog, 0)
	for rows.Next() {
		var a AuditLog
		var detailsStr string
		if err := rows.Scan(&a.ID, &a.ActorEmail, &a.AuthMethod, &a.Action, &a.TargetService, &a.TargetID, &detailsStr, &a.ClientIP, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Details = json.RawMessage(detailsStr)
		out = append(out, a)
	}
	return out, rows.Err()
}
