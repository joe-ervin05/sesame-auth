package sessions

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

type ClientConfig struct {
	DB                           *sql.DB
	SessionInactivityTimeout     time.Duration
	SessionActivityCheckInterval time.Duration
	CookieName                   string
	CookieDomain                 string
	CookiePath                   string
	CookieSameSite               http.SameSite
	CookieSecure                 *bool
	CookieHTTPOnly               *bool
}

type Client struct {
	db                           *sql.DB
	sessionInactivityTimeout     time.Duration
	sessionActivityCheckInterval time.Duration
	cookieOptions                cookieOptions
}

const defaultSessionInactivityTimeout = 10 * 24 * time.Hour
const defaultSessionActivityCheckInterval = time.Hour

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("sessions client requires db")
	}

	inactivityTimeout := cfg.SessionInactivityTimeout
	if inactivityTimeout <= 0 {
		inactivityTimeout = defaultSessionInactivityTimeout
	}

	activityCheckInterval := cfg.SessionActivityCheckInterval
	if activityCheckInterval <= 0 {
		activityCheckInterval = defaultSessionActivityCheckInterval
	}

	if activityCheckInterval >= inactivityTimeout {
		return nil, errors.New("session activity check interval must be less than inactivity timeout")
	}

	cookieOpts := defaultCookieOptions()
	if cfg.CookieName != "" {
		cookieOpts.Name = cfg.CookieName
	}
	cookieOpts.Domain = cfg.CookieDomain
	if cfg.CookiePath != "" {
		cookieOpts.Path = cfg.CookiePath
	}
	if cfg.CookieSameSite != 0 {
		cookieOpts.SameSite = cfg.CookieSameSite
	}
	if cfg.CookieSecure != nil {
		cookieOpts.Secure = *cfg.CookieSecure
	}
	if cfg.CookieHTTPOnly != nil {
		cookieOpts.HttpOnly = *cfg.CookieHTTPOnly
	}

	return &Client{
		db:                           cfg.DB,
		sessionInactivityTimeout:     inactivityTimeout,
		sessionActivityCheckInterval: activityCheckInterval,
		cookieOptions:                cookieOpts,
	}, nil
}

func (c *Client) CreateSession(ctx context.Context, userID string) (string, error) {
	return createSession(ctx, c.db, userID, SessionAuthLevelFull)
}

func (c *Client) CreateSessionWithAuthLevel(ctx context.Context, userID string, authLevel int) (string, error) {
	return createSession(ctx, c.db, userID, authLevel)
}

func (c *Client) ValidateSession(ctx context.Context, token string) (*Session, *User, error) {
	session, user, _, err := validateSession(ctx, c.db, token, c.sessionInactivityTimeout, c.sessionActivityCheckInterval)
	return session, user, err
}

func (c *Client) DeleteSession(ctx context.Context, sessionID string) error {
	return deleteSession(ctx, c.db, sessionID)
}

func (c *Client) UpgradeSessionToFull(ctx context.Context, sessionID string) error {
	return upgradeSessionToFull(ctx, c.db, sessionID)
}

func (c *Client) DeleteUserSessions(ctx context.Context, userID string) error {
	return deleteUserSessions(ctx, c.db, userID)
}

func (c *Client) Logout(ctx context.Context) (string, error) {
	return logout(ctx, c.db)
}

func (c *Client) LogoutHTTP(w http.ResponseWriter, r *http.Request) error {
	return logoutHTTP(w, r, c.db, c.cookieOptions)
}

func (c *Client) SetSessionCookie(w http.ResponseWriter, token string) {
	setSessionCookie(w, token, int(c.sessionInactivityTimeout.Seconds()), c.cookieOptions)
}

func (c *Client) ClearSessionCookie(w http.ResponseWriter) {
	clearSessionCookie(w, c.cookieOptions)
}

func (c *Client) SessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := getSessionToken(r, c.cookieOptions.Name)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}

			session, user, shouldRefresh, err := validateSession(r.Context(), c.db, token, c.sessionInactivityTimeout, c.sessionActivityCheckInterval)
			if err != nil {
				c.ClearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			if shouldRefresh {
				c.SetSessionCookie(w, token)
			}

			ctx := context.WithValue(r.Context(), sessionContextKey, session)
			ctx = context.WithValue(ctx, userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (c *Client) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetSession(r.Context()) == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Client) RequireFullSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSession(r.Context())
		if s == nil || s.AuthLevel != SessionAuthLevelFull {
			http.Redirect(w, r, "/2fa/challenge", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
