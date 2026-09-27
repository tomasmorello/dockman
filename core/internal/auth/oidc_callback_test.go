package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testClientID = "dockman"

// fakeOIDCProvider is a minimal OIDC provider: discovery, JWKS, token and
// userinfo endpoints, with RS256 id tokens signed by a throwaway key.
type fakeOIDCProvider struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	subject  string
	idClaims map[string]any
	userInfo map[string]any
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &fakeOIDCProvider{t: t, key: key, subject: "sub-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.srv.URL,
			"authorization_endpoint":                p.srv.URL + "/authorize",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/jwks",
			"userinfo_endpoint":                     p.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(p.key.N.Bytes()),
			"e": b64(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		claims := map[string]any{
			"iss": p.srv.URL, "aud": testClientID, "sub": p.subject,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range p.idClaims {
			claims[k] = v
		}
		writeJSON(w, map[string]any{
			"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600,
			"id_token": p.sign(claims),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" || p.userInfo == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, p.userInfo)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeOIDCProvider) sign(claims map[string]any) string {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	require.NoError(p.t, err)
	payload, err := json.Marshal(claims)
	require.NoError(p.t, err)
	signingInput := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	require.NoError(p.t, err)
	return signingInput + "." + b64(sig)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

type memUserStore struct {
	mu    sync.Mutex
	users map[string]*User
}

func (m *memUserStore) NewUser(username, encryptedPassword string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.users == nil {
		m.users = map[string]*User{}
	}
	u := &User{Username: username, EncryptedPassword: encryptedPassword}
	u.ID = uint(len(m.users) + 1)
	m.users[username] = u
	return u, nil
}

func (m *memUserStore) GetUser(username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user %q not found", username)
}

func (m *memUserStore) UpdateUser(*User) error { return nil }

type memSessionStore struct{}

func (memSessionStore) NewSession(*Session) error                 { return nil }
func (memSessionStore) DeleteSession(uint) error                  { return nil }
func (memSessionStore) GetSession(uint) (Session, error)          { return Session{}, nil }
func (memSessionStore) GetSessionByToken(string) (Session, error) { return Session{}, nil }

func newOIDCTestService(t *testing.T, p *fakeOIDCProvider, conf Config) (*Service, *memUserStore) {
	conf.OIDCEnable = true
	conf.OIDCIssuerURL = p.srv.URL
	conf.OIDCClientID = testClientID
	conf.OIDCClientSecret = "secret"
	conf.OIDCRedirectURL = "http://localhost:8866/api/auth/login/oidc/callback"
	users := &memUserStore{}
	return NewService("admin", "local-pass", &conf, users, memSessionStore{}), users
}

func TestOIDCCallback_EmailFromUserInfo(t *testing.T) {
	p := newFakeOIDCProvider(t)
	// Authelia >= 4.39 default: no email in the id token, only via userinfo
	p.userInfo = map[string]any{"sub": "sub-1", "email": "alice@x.io"}
	srv, users := newOIDCTestService(t, p, Config{})

	session, _, err := srv.OIDCCallback(context.Background(), "code")
	require.NoError(t, err)
	require.Equal(t, "alice@x.io", session.User.Username)
	_, err = users.GetUser("alice@x.io")
	require.NoError(t, err)
}

func TestOIDCCallback_RejectsMissingEmail(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.userInfo = map[string]any{"sub": "sub-1"}
	srv, users := newOIDCTestService(t, p, Config{})

	_, _, err := srv.OIDCCallback(context.Background(), "code")
	require.ErrorIs(t, err, ErrOIDCForbidden)
	_, err = users.GetUser("")
	require.Error(t, err, "no user with an empty name may be created")
}

func TestOIDCCallback_RejectsUserInfoSubjectMismatch(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.userInfo = map[string]any{"sub": "other", "email": "victim@x.io"}
	srv, _ := newOIDCTestService(t, p, Config{})

	_, _, err := srv.OIDCCallback(context.Background(), "code")
	require.ErrorContains(t, err, "does not match")
}

func TestOIDCCallback_AllowedGroups(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.idClaims = map[string]any{"email": "alice@x.io"}
	srv, _ := newOIDCTestService(t, p, Config{OIDCAllowedGroups: "dockman-admins"})
	require.Contains(t, srv.oauth2Config.Scopes, "groups", "groups scope must be requested when filtering")

	p.userInfo = map[string]any{"sub": "sub-1", "groups": []string{"users"}}
	_, _, err := srv.OIDCCallback(context.Background(), "code")
	require.ErrorIs(t, err, ErrOIDCForbidden)

	p.userInfo = map[string]any{"sub": "sub-1", "groups": []string{"users", "dockman-admins"}}
	session, _, err := srv.OIDCCallback(context.Background(), "code")
	require.NoError(t, err)
	require.Equal(t, "alice@x.io", session.User.Username)
}

func TestOIDCCallbackHandler_ForbiddenIs403(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.idClaims = map[string]any{"email": "alice@x.io", "groups": []string{"users"}}
	srv, _ := newOIDCTestService(t, p, Config{OIDCAllowedGroups: "dockman-admins"})

	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=s1&code=c", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: "s1"})
	rec := httptest.NewRecorder()
	NewHandlerHttp(srv).ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.True(t, strings.Contains(rec.Body.String(), "not a member"), rec.Body.String())
	require.Empty(t, rec.Result().Cookies(), "no session cookie on a rejected login")
}

func TestLogin_LocalLoginDisabledWithOIDC(t *testing.T) {
	p := newFakeOIDCProvider(t)
	srv, _ := newOIDCTestService(t, p, Config{LocalLogin: false})

	_, _, err := srv.Login("admin", "local-pass")
	require.ErrorIs(t, err, ErrLocalLoginDisabled)
}

func TestLogin_LocalLoginStaysOnWithoutOIDC(t *testing.T) {
	users := &memUserStore{}
	// LocalLogin=false without OIDC would lock everyone out; it is ignored
	srv := NewService("admin", "local-pass", &Config{LocalLogin: false}, users, memSessionStore{})

	session, _, err := srv.Login("admin", "local-pass")
	require.NoError(t, err)
	require.Equal(t, "admin", session.User.Username)
}
