package auth

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrOIDCForbidden marks an OIDC login that authenticated correctly at the
// provider but is not allowed into Dockman (missing email, not in an allowed
// group...). Handlers map it to 403 instead of a server error.
var ErrOIDCForbidden = errors.New("oidc login not allowed")

// ErrLocalLoginDisabled is returned for username/password logins when
// DOCKMAN_AUTH_LOCAL_LOGIN=false and OIDC is enabled.
var ErrLocalLoginDisabled = errors.New("username/password login is disabled, sign in with OIDC")

// oidcIdentity is the subset of OIDC claims Dockman needs to map a login to a
// user and authorize it.
type oidcIdentity struct {
	Email  string
	Name   string
	Groups []string
	// GroupsPresent distinguishes "claim missing" from "claim is empty", so a
	// missing groups claim in the ID token triggers the userinfo fallback.
	GroupsPresent bool
}

// userInfoFetcher returns the userinfo endpoint's subject and claims.
type userInfoFetcher func() (subject string, claims map[string]any, err error)

func identityFromClaims(claims map[string]any, groupsClaim string) oidcIdentity {
	ident := oidcIdentity{
		Email: strings.TrimSpace(stringClaim(claims["email"])),
		Name:  strings.TrimSpace(stringClaim(claims["name"])),
	}
	if raw, ok := claims[groupsClaim]; ok && raw != nil {
		ident.Groups, ident.GroupsPresent = groupsClaimValues(raw)
	}
	return ident
}

// fillFrom completes missing fields with the ones found in other.
func (i oidcIdentity) fillFrom(other oidcIdentity) oidcIdentity {
	if i.Email == "" {
		i.Email = other.Email
	}
	if i.Name == "" {
		i.Name = other.Name
	}
	if !i.GroupsPresent && other.GroupsPresent {
		i.Groups, i.GroupsPresent = other.Groups, true
	}
	return i
}

// resolveOIDCIdentity builds the identity from the ID token claims and, when
// the email (or the groups, if group filtering is on) is missing, falls back
// to the userinfo endpoint. Providers such as Authelia >= 4.39 only put the
// standard claims in the ID token by default and serve email/groups through
// userinfo. The userinfo subject must match the ID token's (OIDC Core 5.3.2).
func resolveOIDCIdentity(
	idClaims map[string]any,
	idSubject string,
	groupsClaim string,
	needGroups bool,
	fetchUserInfo userInfoFetcher,
) (oidcIdentity, error) {
	ident := identityFromClaims(idClaims, groupsClaim)
	if ident.Email != "" && (!needGroups || ident.GroupsPresent) {
		return ident, nil
	}
	if fetchUserInfo == nil {
		return ident, nil
	}

	subject, claims, err := fetchUserInfo()
	if err != nil {
		return oidcIdentity{}, fmt.Errorf("unable to fetch userinfo: %w", err)
	}
	if subject != idSubject {
		return oidcIdentity{}, fmt.Errorf("userinfo subject %q does not match id token subject %q", subject, idSubject)
	}
	return ident.fillFrom(identityFromClaims(claims, groupsClaim)), nil
}

// authorizeOIDCIdentity rejects identities Dockman cannot safely map to a user
// and, when allowedGroups is set, users outside those groups.
func authorizeOIDCIdentity(ident oidcIdentity, allowedGroups []string) error {
	if ident.Email == "" {
		return fmt.Errorf("%w: the provider did not return an email claim "+
			"(request the 'email' scope and release the claim in the ID token or userinfo)", ErrOIDCForbidden)
	}
	if len(allowedGroups) == 0 {
		return nil
	}
	if !ident.GroupsPresent {
		return fmt.Errorf("%w: group filtering is enabled but the provider did not return a groups claim "+
			"(request the 'groups' scope and release the claim)", ErrOIDCForbidden)
	}
	for _, group := range ident.Groups {
		if slices.Contains(allowedGroups, group) {
			return nil
		}
	}
	return fmt.Errorf("%w: user %s is not a member of any allowed group", ErrOIDCForbidden, ident.Email)
}

func stringClaim(raw any) string {
	value, _ := raw.(string)
	return value
}

// groupsClaimValues accepts the common shapes of a groups claim: a JSON array
// of strings, or a single string.
func groupsClaimValues(raw any) ([]string, bool) {
	switch value := raw.(type) {
	case string:
		return []string{value}, true
	case []string:
		return value, true
	case []any:
		groups := make([]string, 0, len(value))
		for _, item := range value {
			if group, ok := item.(string); ok {
				groups = append(groups, group)
			}
		}
		return groups, true
	default:
		return nil, false
	}
}
