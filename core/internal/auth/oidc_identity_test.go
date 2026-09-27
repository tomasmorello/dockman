package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityFromClaims_GroupShapes(t *testing.T) {
	arr := identityFromClaims(map[string]any{"email": " a@x.io ", "groups": []any{"admins", 7, "ops"}}, "groups")
	require.Equal(t, "a@x.io", arr.Email)
	require.True(t, arr.GroupsPresent)
	require.Equal(t, []string{"admins", "ops"}, arr.Groups)

	single := identityFromClaims(map[string]any{"roles": "admins"}, "roles")
	require.True(t, single.GroupsPresent)
	require.Equal(t, []string{"admins"}, single.Groups)

	missing := identityFromClaims(map[string]any{"email": "a@x.io"}, "groups")
	require.False(t, missing.GroupsPresent)
}

func TestResolveOIDCIdentity_UsesIDTokenWhenComplete(t *testing.T) {
	fetch := func() (string, map[string]any, error) {
		t.Fatal("userinfo must not be called when the id token has everything")
		return "", nil, nil
	}
	ident, err := resolveOIDCIdentity(map[string]any{"email": "a@x.io"}, "sub-1", "groups", false, fetch)
	require.NoError(t, err)
	require.Equal(t, "a@x.io", ident.Email)
}

func TestResolveOIDCIdentity_FallsBackToUserInfo(t *testing.T) {
	calls := 0
	fetch := func() (string, map[string]any, error) {
		calls++
		return "sub-1", map[string]any{"email": "a@x.io", "groups": []any{"admins"}}, nil
	}

	// email missing from the id token (Authelia >= 4.39 default)
	ident, err := resolveOIDCIdentity(map[string]any{"name": "Alice"}, "sub-1", "groups", false, fetch)
	require.NoError(t, err)
	require.Equal(t, "a@x.io", ident.Email)
	require.Equal(t, "Alice", ident.Name, "id token values win over userinfo")

	// email present but groups needed and missing
	ident, err = resolveOIDCIdentity(map[string]any{"email": "a@x.io"}, "sub-1", "groups", true, fetch)
	require.NoError(t, err)
	require.Equal(t, []string{"admins"}, ident.Groups)
	require.Equal(t, 2, calls)
}

func TestResolveOIDCIdentity_RejectsSubjectMismatch(t *testing.T) {
	fetch := func() (string, map[string]any, error) {
		return "someone-else", map[string]any{"email": "victim@x.io"}, nil
	}
	_, err := resolveOIDCIdentity(map[string]any{}, "sub-1", "groups", false, fetch)
	require.ErrorContains(t, err, "does not match")
}

func TestResolveOIDCIdentity_PropagatesUserInfoError(t *testing.T) {
	fetch := func() (string, map[string]any, error) { return "", nil, errors.New("boom") }
	_, err := resolveOIDCIdentity(map[string]any{}, "sub-1", "groups", false, fetch)
	require.ErrorContains(t, err, "boom")
}

func TestAuthorizeOIDCIdentity(t *testing.T) {
	tests := []struct {
		name    string
		ident   oidcIdentity
		allowed []string
		wantErr bool
	}{
		{"empty email is rejected", oidcIdentity{}, nil, true},
		{"any user without group filter", oidcIdentity{Email: "a@x.io"}, nil, false},
		{"member of an allowed group", oidcIdentity{Email: "a@x.io", Groups: []string{"dev", "admins"}, GroupsPresent: true}, []string{"admins"}, false},
		{"not a member", oidcIdentity{Email: "a@x.io", Groups: []string{"dev"}, GroupsPresent: true}, []string{"admins"}, true},
		{"groups claim missing", oidcIdentity{Email: "a@x.io"}, []string{"admins"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeOIDCIdentity(tt.ident, tt.allowed)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrOIDCForbidden)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_OIDCHelpers(t *testing.T) {
	c := &Config{OIDCAllowedGroups: " admins, ,ops "}
	require.Equal(t, []string{"admins", "ops"}, c.GetOIDCAllowedGroups())
	require.Equal(t, "groups", c.GetOIDCGroupsClaim())

	c.OIDCGroupsClaim = "roles"
	require.Equal(t, "roles", c.GetOIDCGroupsClaim())

	// local login can only be turned off when OIDC is on
	require.True(t, (&Config{LocalLogin: false, OIDCEnable: false}).LocalLoginEnabled())
	require.False(t, (&Config{LocalLogin: false, OIDCEnable: true}).LocalLoginEnabled())
	require.True(t, (&Config{LocalLogin: true, OIDCEnable: true}).LocalLoginEnabled())
}
