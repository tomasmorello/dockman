package auth

import (
	"strings"
	"time"

	"github.com/RA341/dockman/pkg/fileutil"
)

type Config struct {
	Enable       bool   `config:"flag=auth,env=AUTH_ENABLE,default=false,usage=Enable authentication"`
	Username     string `config:"flag=au,env=AUTH_USERNAME,default=admin,usage=authentication username"`
	Password     string `config:"flag=ap,env=AUTH_PASSWORD,default=admin99988,usage=authentication password,hide=true"`
	CookieExpiry string `config:"flag=ae,env=AUTH_EXPIRY,default=24h,usage=Set cookie expiry-300ms/1.5h/2h45m [ns|us|ms|s|m|h]"`
	MaxSessions  int    `config:"flag=mxs,env=AUTH_MAX_SESSIONS,default=5,usage=Set max active sessions per user"`

	OIDCEnable       bool `config:"flag=eoc,env=AUTH_OIDC_ENABLE,default=false,usage=enable OIDC support"`
	OIDCAutoRedirect bool `config:"flag=ear,env=AUTH_OIDC_AUTO_REDIRECT,default=true,usage=automatically redirect to OIDC login"`

	OIDCIssuerURL    string `config:"flag=oiu,env=AUTH_OIDC_ISSUER,default=,usage=url for your OIDC issuer"`
	OIDCClientID     string `config:"flag=oicd,env=AUTH_OIDC_CLIENT_ID,default=,usage=client id for OIDC,hide=true"`
	OIDCClientSecret string `config:"flag=oics,env=AUTH_OIDC_CLIENT_SECRET,default=,usage=client secret for OIDC,hide=true"`
	OIDCRedirectURL  string `config:"flag=oiurl,env=AUTH_OIDC_REDIRECT_URL,default=,usage=redirect url for OIDC"`
	OIDCHttp         bool   `config:"flag=oicook,env=AUTH_OIDC_SECURE,default=true,usage=disable https only for OIDC"`

	OIDCAllowedGroups string `config:"flag=oigrp,env=AUTH_OIDC_ALLOWED_GROUPS,default=,usage=CSV of groups allowed to log in with OIDC (empty allows any user of the provider)"`
	OIDCGroupsClaim   string `config:"flag=oigc,env=AUTH_OIDC_GROUPS_CLAIM,default=groups,usage=claim holding the user's groups"`
	LocalLogin        bool   `config:"flag=allogin,env=AUTH_LOCAL_LOGIN,default=true,usage=allow username/password login; can only be disabled when OIDC is enabled"`
}

// GetOIDCAllowedGroups returns the configured allowed groups, trimmed and
// without empty entries.
func (d *Config) GetOIDCAllowedGroups() []string {
	var groups []string
	for _, group := range strings.Split(d.OIDCAllowedGroups, ",") {
		if group = strings.TrimSpace(group); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

// GetOIDCGroupsClaim returns the claim name holding the groups, "groups" by default.
func (d *Config) GetOIDCGroupsClaim() string {
	if claim := strings.TrimSpace(d.OIDCGroupsClaim); claim != "" {
		return claim
	}
	return "groups"
}

// LocalLoginEnabled reports whether username/password login is accepted.
// Disabling it without OIDC would lock everyone out, so it only takes effect
// when OIDC is enabled.
func (d *Config) LocalLoginEnabled() bool {
	return d.LocalLogin || !d.OIDCEnable
}

const defaultCookieExpiry = time.Hour * 24

func (d *Config) GetCookieExpiry() time.Duration {
	return fileutil.GetDurOrDefault(d.CookieExpiry, defaultCookieExpiry)
}
