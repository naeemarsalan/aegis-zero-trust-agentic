package tui

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// entityRefFromBearer extracts the launcher entity ref
// (user:default/<preferred_username>) from a Keycloak bearer JWT. Returns "" when
// the token is absent/malformed or carries no preferred_username.
//
// The sandbox-launcher rejects a launch (HTTP 403 "Caller identity mismatch")
// unless body.user equals the caller token's OWN entity ref derived this exact
// way (services/sandbox-launcher/.../auth.py extract_entity_ref + api.py strict
// lowercase equality). cfg.Owner is a label, not the identity, so it must NOT be
// used for userRef. Mirrors internal/cli.entityRefFromBearer.
func entityRefFromBearer(bearer string) string {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.PreferredUsername == "" {
		return ""
	}
	return "user:default/" + claims.PreferredUsername
}
