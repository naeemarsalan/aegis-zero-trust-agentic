// Package jwks fetches and caches the Keycloak realm signing keys (JWKS) and
// cryptographically VERIFIES incoming Authorization Bearer JWTs.
//
// This is the independent-verification leg of ext-proc's defense in depth:
// ext-proc does NOT trust that the gateway already validated the token. It
// re-verifies the RS256 signature against the Keycloak JWKS, the issuer, the
// audience, and the exp/nbf time bounds before any claim is trusted as the
// caller identity that drives token exchange.
//
// Keys are cached in-memory with a TTL (~10m). On encountering an unknown
// `kid` the cache is force-refreshed once (key rotation), and only if the kid
// is still absent does verification fail closed.
package jwks

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Default clock leeway for exp/nbf validation.
const defaultLeeway = 60 * time.Second

// VerifiedToken is the result of a successful verification: the raw token
// string (the subject_token used for downstream exchange) plus the trusted
// claims extracted from the *verified* payload.
type VerifiedToken struct {
	Raw               string
	Sub               string
	PreferredUsername string
	Groups            []string
	Issuer            string
}

// Verifier verifies Keycloak-issued RS256 JWTs against a cached JWKS.
type Verifier struct {
	jwksURL          string
	issuer           string
	expectedAudience string
	ttl              time.Duration
	leeway           time.Duration

	httpClient *http.Client

	mu        sync.RWMutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// Config parameterizes a Verifier.
type Config struct {
	JWKSURL          string
	Issuer           string
	ExpectedAudience string
	// TTL is the cache lifetime for fetched keys (default 10m).
	TTL time.Duration
	// Leeway is the clock-skew tolerance for exp/nbf (default 60s).
	Leeway time.Duration
	// HTTPClient is optional; a 5s-timeout client is used if nil.
	HTTPClient *http.Client
}

// New constructs a Verifier. It does NOT fetch keys eagerly; the first
// verification (or an explicit Refresh) populates the cache.
func New(cfg Config) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("jwks: JWKSURL is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("jwks: Issuer is required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("jwks: ExpectedAudience is required")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = defaultLeeway
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{
		jwksURL:          cfg.JWKSURL,
		issuer:           cfg.Issuer,
		expectedAudience: cfg.ExpectedAudience,
		ttl:              ttl,
		leeway:           leeway,
		httpClient:       hc,
	}, nil
}

// ErrVerification is returned (wrapped) whenever a token cannot be trusted.
var ErrVerification = errors.New("jwt verification failed")

// trustedClaims is the subset of claims we read AFTER signature+iss+aud+exp
// have all passed. We never read these from an unverified payload.
type trustedClaims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Issuer            string   `json:"iss"`
	Groups            []string `json:"groups"`
}

// Verify cryptographically verifies a raw JWT (no "Bearer " prefix) and
// returns the trusted claims. It enforces: RS256 signature against the
// Keycloak JWKS, iss == configured issuer, expected audience present,
// exp/nbf within leeway. Any failure returns an error (fail closed).
func (v *Verifier) Verify(ctx context.Context, raw string) (*VerifiedToken, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty token", ErrVerification)
	}

	// Parse, restricting accepted algorithms to RS256 only. This rejects
	// alg=none and any algorithm-confusion attempt at parse time.
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrVerification, err)
	}

	// Determine the signing kid from the JWS header.
	kid := ""
	if len(tok.Headers) > 0 {
		kid = tok.Headers[0].KeyID
	}

	key, err := v.keyForKID(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}

	// Verify the signature by extracting claims with the resolved key. If the
	// signature does not validate, Claims returns an error.
	var std jwt.Claims
	var custom trustedClaims
	if err := tok.Claims(key, &std, &custom); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrVerification, err)
	}

	// Validate issuer, audience, and time bounds against the VERIFIED claims.
	expected := jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.expectedAudience},
		Time:        time.Now(),
	}
	if err := std.ValidateWithLeeway(expected, v.leeway); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrVerification, err)
	}

	if custom.Sub == "" {
		// A verified token with no subject cannot drive delegation.
		return nil, fmt.Errorf("%w: verified token has empty sub", ErrVerification)
	}

	return &VerifiedToken{
		Raw:               raw,
		Sub:               custom.Sub,
		PreferredUsername: custom.PreferredUsername,
		Groups:            custom.Groups,
		Issuer:            custom.Issuer,
	}, nil
}

// keyForKID returns the RSA public key matching kid, refreshing the JWKS once
// on a cache miss (key rotation). Fails closed if the kid is unresolvable.
func (v *Verifier) keyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Try the cache (refresh if stale).
	keys, err := v.ensureKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	if k := lookupRSA(keys, kid); k != nil {
		return k, nil
	}

	// Unknown kid -> force a refresh once (handles rotation).
	keys, err = v.ensureKeys(ctx, true)
	if err != nil {
		return nil, err
	}
	if k := lookupRSA(keys, kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("no RS256 signing key for kid %q", kid)
}

// lookupRSA finds an RSA public key for kid. If kid is empty and exactly one
// key is present, that key is used.
func lookupRSA(set *jose.JSONWebKeySet, kid string) *rsa.PublicKey {
	if set == nil {
		return nil
	}
	if kid != "" {
		for _, jwk := range set.Key(kid) {
			if pk, ok := jwk.Key.(*rsa.PublicKey); ok {
				return pk
			}
		}
		return nil
	}
	// No kid in header: only safe if the set has a single RSA key.
	var found *rsa.PublicKey
	count := 0
	for _, jwk := range set.Keys {
		if pk, ok := jwk.Key.(*rsa.PublicKey); ok {
			found = pk
			count++
		}
	}
	if count == 1 {
		return found
	}
	return nil
}

// ensureKeys returns the cached key set, fetching from the JWKS endpoint when
// the cache is empty, stale (TTL exceeded), or force is true.
func (v *Verifier) ensureKeys(ctx context.Context, force bool) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	cached := v.keys
	fresh := cached != nil && time.Since(v.fetchedAt) < v.ttl
	v.mu.RUnlock()
	if !force && fresh {
		return cached, nil
	}

	set, err := v.fetch(ctx)
	if err != nil {
		// On a forced refresh that fails, fall back to whatever is cached so a
		// transient JWKS outage does not break verification of already-known
		// kids; the caller still fails closed if the kid is genuinely absent.
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	v.mu.Lock()
	v.keys = set
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return set, nil
}

// fetch retrieves and parses the JWKS document.
func (v *Verifier) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %d from %s", resp.StatusCode, v.jwksURL)
	}

	var set jose.JSONWebKeySet
	if err := jsonUnmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks: key set is empty")
	}
	return &set, nil
}
