package passkeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

const (
	FlowTypeRegister = "register"
	FlowTypeLogin    = "login"
)

type ClientConfig struct {
	DB            *sql.DB
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	FlowTTL       time.Duration
}

type Client struct {
	db      *sql.DB
	wan     *webauthn.WebAuthn
	flowTTL time.Duration
}

type User struct {
	ID          string
	Email       string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte { return []byte(u.ID) }
func (u *User) WebAuthnName() string {
	return u.Email
}
func (u *User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("passkeys client requires db")
	}
	if cfg.RPID == "" {
		return nil, errors.New("passkeys rpid is required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("passkeys rp origins are required")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Sesame"
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = 10 * time.Minute
	}

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}

	return &Client{db: cfg.DB, wan: wan, flowTTL: cfg.FlowTTL}, nil
}

func (c *Client) GetUserByID(ctx context.Context, userID string) (*User, error) {
	row := c.db.QueryRowContext(ctx, "SELECT id, email FROM users WHERE id = ?", userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	creds, err := c.ListUserPasskeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	u.Credentials = creds
	return &u, nil
}

func (c *Client) GetUserByCredentialID(ctx context.Context, credentialID []byte) (*User, error) {
	row := c.db.QueryRowContext(ctx,
		`SELECT u.id
FROM user_passkeys p
JOIN users u ON u.id = p.user_id
WHERE p.credential_id = ?`,
		credentialID,
	)

	var userID string
	if err := row.Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return c.GetUserByID(ctx, userID)
}

func (c *Client) ListUserPasskeys(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT credential_json FROM user_passkeys WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]webauthn.Credential, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

func (c *Client) SaveUserPasskey(ctx context.Context, userID string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	id, err := gonanoid.New()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = c.db.ExecContext(ctx,
		"INSERT INTO user_passkeys (id, user_id, credential_id, credential_json, created_at) VALUES (?, ?, ?, ?, ?)",
		id, userID, cred.ID, raw, now,
	)
	return err
}

func (c *Client) UpdateUserPasskey(ctx context.Context, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = c.db.ExecContext(ctx,
		"UPDATE user_passkeys SET credential_json = ? WHERE credential_id = ?",
		raw, cred.ID,
	)
	return err
}

func (c *Client) BeginRegister(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if user == nil {
		return nil, "", errors.New("user not found")
	}

	creation, sessionData, err := c.wan.BeginMediatedRegistration(
		user,
		protocol.MediationDefault,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", err
	}

	flowID, err := c.createFlow(ctx, FlowTypeRegister, &userID, sessionData)
	if err != nil {
		return nil, "", err
	}

	return creation, flowID, nil
}

func (c *Client) FinishRegister(ctx context.Context, userID, flowID string, r *protocol.ParsedCredentialCreationData) error {
	flow, err := c.consumeFlow(ctx, flowID, FlowTypeRegister)
	if err != nil {
		return err
	}
	if flow == nil || flow.UserID == nil || *flow.UserID != userID {
		return errors.New("invalid webauthn flow")
	}

	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	cred, err := c.wan.CreateCredential(user, flow.SessionData, r)
	if err != nil {
		return err
	}

	return c.SaveUserPasskey(ctx, userID, cred)
}

func (c *Client) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, sessionData, err := c.wan.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		return nil, "", err
	}

	flowID, err := c.createFlow(ctx, FlowTypeLogin, nil, sessionData)
	if err != nil {
		return nil, "", err
	}

	return assertion, flowID, nil
}

func (c *Client) FinishLogin(ctx context.Context, flowID string, parsed *protocol.ParsedCredentialAssertionData) (string, error) {
	flow, err := c.consumeFlow(ctx, flowID, FlowTypeLogin)
	if err != nil {
		return "", err
	}
	if flow == nil {
		return "", errors.New("invalid webauthn flow")
	}

	var resolvedUserID string
	loadUser := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(rawID) > 0 {
			user, err := c.GetUserByCredentialID(ctx, rawID)
			if err != nil {
				return nil, err
			}
			if user != nil {
				resolvedUserID = user.ID
				return user, nil
			}
		}

		if len(userHandle) > 0 {
			resolvedUserID = string(userHandle)
			return c.GetUserByID(ctx, resolvedUserID)
		}

		return nil, errors.New("credential not found")
	}

	cred, err := c.wan.ValidateDiscoverableLogin(loadUser, flow.SessionData, parsed)
	if err != nil {
		return "", err
	}
	if resolvedUserID == "" {
		return "", errors.New("missing user id")
	}

	if err := c.UpdateUserPasskey(ctx, cred); err != nil {
		return "", err
	}

	return resolvedUserID, nil
}

type flow struct {
	ID          string
	UserID      *string
	FlowType    string
	SessionData webauthn.SessionData
	ExpiresAt   time.Time
}

func (c *Client) createFlow(ctx context.Context, flowType string, userID *string, session *webauthn.SessionData) (string, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(c.flowTTL)

	_, err = c.db.ExecContext(ctx,
		"INSERT INTO webauthn_flows (id, user_id, flow_type, session_data_json, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, userID, flowType, raw, expiresAt.Unix(), now.Unix(),
	)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (c *Client) consumeFlow(ctx context.Context, flowID, flowType string) (*flow, error) {
	row := c.db.QueryRowContext(ctx,
		"SELECT user_id, session_data_json, expires_at FROM webauthn_flows WHERE id = ? AND flow_type = ?",
		flowID, flowType,
	)

	var userID sql.NullString
	var raw []byte
	var expiresAtUnix int64
	err := row.Scan(&userID, &raw, &expiresAtUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	_, _ = c.db.ExecContext(ctx, "DELETE FROM webauthn_flows WHERE id = ?", flowID)

	f := &flow{ID: flowID, FlowType: flowType, ExpiresAt: time.Unix(expiresAtUnix, 0).UTC()}
	if userID.Valid {
		f.UserID = &userID.String
	}
	if err := json.Unmarshal(raw, &f.SessionData); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(f.ExpiresAt) {
		return nil, nil
	}

	return f, nil
}
