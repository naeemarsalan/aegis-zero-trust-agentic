// Package extproc implements the Envoy ExternalProcessor gRPC service.
// Each bidirectional stream drives the following state machine:
//
//	RequestHeaders -> RequestBody -> ResponseHeaders
//
// The service performs credential delegation supporting TWO paths:
//
// (A) LEGACY PATH (Keycloak user JWT):
//
//	The caller presents a Keycloak-issued JWT. ext-proc independently verifies
//	it, runs RFC 8693 token exchange (subject_token=caller JWT), fetches the
//	Vault tool secret or static token, and injects the downstream bearer.
//
// (B) SANDBOX AGENT PATH (SPIRE JWT-SVID, Option D):
//
//	The caller presents a SPIRE OIDC JWT-SVID. ext-proc:
//	  1. Verifies the SVID (SPIRE OIDC JWKS, iss=spire-oidc, aud=mcp-gateway,
//	     trust domain=spiffe://anaeem.na-launch.com/).
//	  2. Reads the sandbox consent grant from Vault at
//	     secret/data/sandbox-grants/<svid.sandbox_uid>.
//	  3. Validates: TTL not expired, sandbox_uid+nonce bind SVID to grant,
//	     scope permits the requested tool.
//	  4. Runs RFC 8693 Phase-1 impersonation with requested_subject=grant.user
//	     (NO subject_token — the user JWT was discarded at the launcher).
//	  5. Selects the per-user static pfSense token from Vault by grant.user,
//	     injects it as Authorization: Bearer.
//
// The service is fail-closed: any error in any leg causes an ImmediateResponse
// 403 and denies the request. There is no default-allow path on error.
//
// Fail-closed on body-less / headers-only requests: a downstream credential is
// minted ONLY in the RequestBody leg. If a stream reaches ResponseHeaders
// without a successful exchange (body-less request, empty body, a
// processing-mode downgrade, or a streamed upstream), the request is DENIED —
// the service never emits an allow/inject with an empty downstream token.
package extproc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	statuspb "google.golang.org/grpc/status"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/audit"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/claims"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/config"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/grant"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/inject"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/mcp"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/rbac"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/spire"
)

// Exchanger is the interface for Keycloak RFC 8693 token exchange using the
// caller's own JWT as subject_token (legacy / Keycloak user path).
type Exchanger interface {
	Exchange(ctx context.Context, callerToken, audience string) (string, error)
}

// OnBehalfExchanger is the interface for RFC 8693 Phase-1 impersonation:
// the service authenticates as itself and sets requested_subject=user.
// No user subject_token is involved. Used exclusively on the SPIRE SVID path.
type OnBehalfExchanger interface {
	ExchangeOnBehalf(ctx context.Context, user, audience string) (string, error)
}

// VaultClient is the interface for the Vault secret retrieval leg.
type VaultClient interface {
	FetchToolSecret(ctx context.Context, tool string) (map[string]interface{}, error)
	FetchGrant(ctx context.Context, grantPathPrefix, sandboxUID string) (map[string]interface{}, error)
}

// JITVerifier verifies a jit-approver session JWT and returns its tool_scope.
type JITVerifier interface {
	Verify(ctx context.Context, raw string) (*jwks.VerifiedToken, error)
}

// SpireVerifier verifies SPIRE JWT-SVIDs and extracts sandbox claims.
type SpireVerifier interface {
	VerifySVID(ctx context.Context, raw string) (*spire.SVIDClaims, error)
}

// Server implements extprocv3.ExternalProcessorServer.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	cfg          *config.Config
	kc           Exchanger
	kcOnBehalf   OnBehalfExchanger
	vault        VaultClient
	verifier     claims.Verifier
	jit          JITVerifier
	spireVerifier SpireVerifier
	policy       rbac.Policy
}

// NewServer creates a new ext_proc server. verifier independently verifies the
// caller's JWT (defense in depth — the gateway is not trusted). jit may be nil
// (JIT gate disabled — dangerous tools then require admin only).
// spireV may be nil when SPIRE_JWKS_URL is not configured (sandbox path disabled).
func NewServer(cfg *config.Config, kc Exchanger, vault VaultClient, verifier claims.Verifier, jit JITVerifier) *Server {
	return &Server{
		cfg: cfg, kc: kc, vault: vault, verifier: verifier, jit: jit,
		policy: rbac.Policy{
			ReadOnlyPrefixes:  cfg.ReadOnlyToolPrefixes,
			DangerousPrefixes: cfg.DangerousToolPrefixes,
			RestrictedGroup:   cfg.RestrictedGroup,
			AdminGroup:        cfg.AdminGroup,
			UserGroup:         cfg.UserGroup,
		},
	}
}

// NewServerWithSpire creates a Server with the SPIRE SVID verifier enabled.
// The kc parameter must also implement OnBehalfExchanger for the on-behalf path.
func NewServerWithSpire(
	cfg *config.Config,
	kc Exchanger,
	vault VaultClient,
	verifier claims.Verifier,
	jit JITVerifier,
	sv SpireVerifier,
) *Server {
	s := NewServer(cfg, kc, vault, verifier, jit)
	s.spireVerifier = sv
	if obc, ok := kc.(OnBehalfExchanger); ok {
		s.kcOnBehalf = obc
	}
	return s
}

// Process handles a single bidirectional gRPC stream from Envoy.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	// per-stream state
	var (
		identity       *claims.Identity
		svidClaims     *spire.SVIDClaims // non-nil on SPIRE SVID path
		authHeader     string
		rawToken       string
		reqPath        string
		jitJWT         string
		sessionID      string
		traceID        string
		spanID         string
		mcpReq         *mcp.Request
		downToken      string
		delegationDone bool          // true only after BOTH exchange legs minted a real downstream credential
		spireAudit     spireAuditCtx // populated on the SPIRE path; carries grant + exchange outcome to the final allow audit
	)
	_ = time.Now() // ensure time import used

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			slog.Error("ext_proc: recv error", "err", err)
			return statuspb.Errorf(codes.Unavailable, "recv: %v", err)
		}
		switch msg := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			hdrs := msg.RequestHeaders.GetHeaders()
			authHeader = headerValue(hdrs, "authorization")
			reqPath = headerValue(hdrs, ":path")
			jitJWT = strings.TrimSpace(headerValue(hdrs, "x-jit-session-jwt"))
			sessionID = headerValue(hdrs, "x-jit-session")
			if sessionID == "" {
				sessionID = uuid.New().String()
			}
			traceID = headerValue(hdrs, "x-b3-traceid")
			spanID = headerValue(hdrs, "x-b3-spanid")

			// Extract the raw bearer token (strip "Bearer " prefix).
			rawToken = bearerFromHeader(authHeader)

			// Determine which path: SPIRE SVID or legacy Keycloak user JWT.
			if rawToken != "" && s.spireVerifier != nil && spire.IsSPIRESVID(rawToken, s.cfg.SpireIssuer) {
				// SPIRE SVID path: verify the SVID cryptographically.
				sv, svErr := s.spireVerifier.VerifySVID(ctx, rawToken)
				if svErr != nil {
					slog.Error("ext_proc: SPIRE SVID verification failed", "err", svErr.Error())
					emitter := audit.NewEmitter(sessionID, traceID, spanID)
					emitter.Emit(ctx, "deny", "spire_svid_invalid", false, false)
					return stream.Send(immediateResponse(http.StatusUnauthorized, "invalid SPIRE SVID"))
				}
				svidClaims = sv
			} else {
				// Legacy path: independently verify the caller token against Keycloak JWKS
				// (signature/iss/aud/exp) and cross-check any gateway metadata.
				// No verifiable token -> 401 deny.
				id, idErr := claims.FromContext(ctx, authHeader, s.verifier)
				if idErr != nil {
					slog.Error("ext_proc: identity verification failed", "err", idErr.Error())
					emitter := audit.NewEmitter(sessionID, traceID, spanID)
					emitter.Emit(ctx, "deny", "no_identity", false, false)
					return stream.Send(immediateResponse(http.StatusUnauthorized, "no identity"))
				}
				identity = id
			}

			// Acknowledge request headers — continue to body.
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{},
					},
				},
			}); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			body := msg.RequestBody.GetBody()

			// Fail closed on an empty/absent body: we cannot identify the MCP
			// tool, run the exchange, or mint a downstream credential, so we
			// must not allow the call through.
			if len(body) == 0 {
				emitter := audit.NewEmitter(sessionID, traceID, spanID)
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				} else if svidClaims != nil {
					emitter.SetAgent(svidClaims.SpiffeID, svidClaims.SpiffeID)
				}
				emitter.Emit(ctx, "deny", "empty_body", false, false)
				return stream.Send(immediateResponse(http.StatusForbidden, "empty body"))
			}

			// Enforce body size limit.
			if int64(len(body)) > s.cfg.MaxBodyBytes {
				emitter := audit.NewEmitter(sessionID, traceID, spanID)
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				}
				emitter.Emit(ctx, "deny", "body_too_large", false, false)
				return stream.Send(immediateResponse(413, "body too large"))
			}

			mcpR, parseErr := mcp.Parse(body)
			if parseErr != nil && !errors.Is(parseErr, mcp.ErrNotMCPToolCall) {
				emitter := audit.NewEmitter(sessionID, traceID, spanID)
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				}
				emitter.Emit(ctx, "deny", "mcp_parse_error", false, false)
				return stream.Send(immediateResponse(http.StatusBadRequest, "invalid MCP body"))
			}
			mcpReq = mcpR

			tool := ""
			argsHash := ""
			if mcpReq != nil {
				tool = mcpReq.Tool
				argsHash = mcpReq.ArgsHash
			}

			// Route to the appropriate delegation path.
			if svidClaims != nil {
				// ----------------------------------------------------------------
				// SANDBOX AGENT PATH (Option D: SPIRE SVID + Vault grant)
				// ----------------------------------------------------------------
				tok, dErr := s.handleSandboxAgentPath(ctx, sessionID, traceID, spanID,
					stream, svidClaims, tool, argsHash, reqPath, jitJWT, &spireAudit)
				if dErr != nil {
					return dErr // stream.Send(immediateResponse) already sent inside
				}
				downToken = tok
				delegationDone = true

				mutation := inject.BuildRequestMutation(downToken)
				if err := stream.Send(&extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: mutation,
						},
					},
				}); err != nil {
					return err
				}

			} else {
				// ----------------------------------------------------------------
				// LEGACY PATH (Keycloak user JWT)
				// ----------------------------------------------------------------
				emitter := audit.NewEmitter(sessionID, traceID, spanID)
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				}
				emitter.SetMCP("", tool, argsHash)

				// Tool-level RBAC.
				{
					var groups []string
					if identity != nil {
						groups = identity.Groups
					}
					jitValid := false
					var jitScope []string
					if tool != "" && jitJWT != "" && s.jit != nil {
						if vt, jerr := s.jit.Verify(ctx, jitJWT); jerr == nil {
							jitValid = true
							jitScope = vt.ToolScope
						}
					}
					if reason, allow := s.policy.Decide(groups, tool, jitValid, jitScope); !allow {
						emitter.Emit(ctx, "deny", reason, false, false)
						return stream.Send(immediateResponse(http.StatusForbidden, reason))
					}
				}

				// Run Keycloak exchange and Vault secret fetch concurrently.
				var exchangedToken string
				var vaultErr error
				eg, egCtx := errgroup.WithContext(ctx)

				eg.Go(func() error {
					if identity == nil || identity.Raw == "" {
						return fmt.Errorf("no caller token available for exchange")
					}
					tok, err := s.kc.Exchange(egCtx, identity.Raw, s.cfg.DownstreamAudience)
					if err != nil {
						slog.Error("ext_proc: keycloak exchange failed", "err", err)
						emitter.SetKeycloakExchange(string(s.cfg.ExchangeMode), s.cfg.DownstreamAudience, exchangeErrorCode(err))
						return fmt.Errorf("keycloak exchange: %w", err)
					}
					exchangedToken = tok
					emitter.SetKeycloakExchange(string(s.cfg.ExchangeMode), s.cfg.DownstreamAudience, "success")
					return nil
				})

				eg.Go(func() error {
					vaultTool := tool
					if vaultTool == "" {
						vaultTool = "_default"
					}
					secretPath := s.cfg.ToolSecretPathPrefix + vaultTool
					_, err := s.vault.FetchToolSecret(egCtx, vaultTool)
					// Fall back to the _default secret when a tool has no dedicated
					// KV entry (e.g. pfsense_* tools, echo-mcp tools): the Vault SVID
					// auth still ran, we just have no per-tool backend credential.
					if err != nil && vaultTool != "_default" {
						if _, derr := s.vault.FetchToolSecret(egCtx, "_default"); derr == nil {
							secretPath = s.cfg.ToolSecretPathPrefix + "_default"
							err = nil
						}
					}
					if err != nil {
						slog.Error("ext_proc: vault fetch failed", "err", err)
						vc := vaultErrorCode(err)
						emitter.SetVault(vc, secretPath, vc)
						vaultErr = err
						return fmt.Errorf("vault: %w", err)
					}
					emitter.SetVault("success", secretPath, "success")
					return nil
				})

				if err := eg.Wait(); err != nil {
					// Fail closed: any error -> 403 deny.
					reason := "exchange_failed"
					if vaultErr != nil {
						reason = "vault_failed"
					}
					emitter.Emit(ctx, "deny", reason, false, false)
					return stream.Send(immediateResponse(http.StatusForbidden, reason))
				}

				// Both legs succeeded but the exchange MUST have produced a real
				// downstream credential — never inject/allow an empty token.
				if exchangedToken == "" {
					emitter.Emit(ctx, "deny", "empty_downstream_token", false, false)
					return stream.Send(immediateResponse(http.StatusForbidden, "no downstream credential"))
				}

				downToken = exchangedToken

				// Static-bearer downstreams (e.g. pfsense-mcp on /mcp) validate a
				// fixed per-user token list, not JWTs. For those paths, inject the
				// caller's pre-provisioned static token (Vault KV keyed by username)
				// instead of the exchanged JWT. The exchange above still ran for
				// audit; it is the injected bearer that differs.
				if s.cfg.IsStaticAuthPath(reqPath) {
					m, ferr := s.vault.FetchToolSecret(ctx, s.cfg.StaticTokenSecret)
					if ferr != nil {
						emitter.Emit(ctx, "deny", "static_token_fetch_failed", false, false)
						return stream.Send(immediateResponse(http.StatusForbidden, "no per-user token"))
					}
					userKey := ""
					if identity != nil {
						userKey = identity.PreferredUsername
					}
					ut, _ := m[userKey].(string)
					if ut == "" {
						emitter.Emit(ctx, "deny", "no_user_token", false, false)
						return stream.Send(immediateResponse(http.StatusForbidden, "no per-user token"))
					}
					downToken = ut
				}

				delegationDone = true

				// Inject the downstream token.
				mutation := inject.BuildRequestMutation(downToken)
				if err := stream.Send(&extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: mutation,
						},
					},
				}); err != nil {
					return err
				}
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			// FAIL CLOSED: reaching the response leg without a completed
			// delegation (body-less request, empty body, processing-mode
			// downgrade, or a streamed upstream) means no downstream credential
			// was ever minted. We must NOT allow such a response — emit a deny
			// and terminate the request with a 403 rather than an allow with an
			// empty downstream token.
			if !delegationDone || downToken == "" {
				emitter := audit.NewEmitter(sessionID, traceID, spanID)
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				}
				tool := ""
				argsHash := ""
				if mcpReq != nil {
					tool = mcpReq.Tool
					argsHash = mcpReq.ArgsHash
				}
				emitter.SetMCP("", tool, argsHash)
				emitter.Emit(ctx, "deny", "no_delegation", false, false)
				return stream.Send(immediateResponse(http.StatusForbidden, "no delegation"))
			}

			// Strip credential headers from the upstream response.
			strip := inject.StripResponse()
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: strip,
					},
				},
			}); err != nil {
				return err
			}

			// Emit final allow audit (delegation succeeded — downToken is non-empty).
			emitter := audit.NewEmitter(sessionID, traceID, spanID)
			tool := ""
			argsHash := ""
			if mcpReq != nil {
				tool = mcpReq.Tool
				argsHash = mcpReq.ArgsHash
			}
			emitter.SetMCP("", tool, argsHash)
			if svidClaims != nil {
				// SPIRE / sandbox-agent path: there is no inbound Keycloak identity —
				// the caller resolves to the grant user. Reflect the REAL grant and
				// on-behalf exchange outcome captured during delegation (which may be
				// a non-fatal exchange failure on the static-auth path) rather than a
				// hardcoded success, so the allow audit never overstates the exchange.
				emitter.SetAgent(svidClaims.SpiffeID, svidClaims.SpiffeID)
				emitter.SetCallerUser("", spireAudit.callerUser, nil)
				emitter.SetGrant(spireAudit.grantSandboxUID, spireAudit.grantScope, string(grant.ResultValid), spireAudit.grantNoncePresent)
				emitter.SetVault("success", spireAudit.grantPath, "success")
				emitter.SetKeycloakExchange("on_behalf", s.cfg.DownstreamAudience, spireAudit.exchangeResult)
				emitter.SetJIT(spireAudit.jitElevated, spireAudit.jitSessionID)
			} else {
				if identity != nil {
					emitter.SetCallerUser(identity.Sub, identity.PreferredUsername, identity.Groups)
				}
				emitter.SetKeycloakExchange(string(s.cfg.ExchangeMode), s.cfg.DownstreamAudience, "success")
			}
			emitter.Emit(ctx, "allow", "", true, true)

		case *extprocv3.ProcessingRequest_ResponseBody:
			// Pass response body through without modification.
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{},
					},
				},
			}); err != nil {
				return err
			}

		default:
			// Unknown message type — pass through.
		}
	}
}

// spireAuditCtx carries the SPIRE/sandbox-agent audit fields from
// handleSandboxAgentPath (RequestBody leg) to the final allow emission
// (ResponseHeaders leg). Without this, the final allow audit would have to
// hardcode the exchange result — which becomes incorrect once an on-behalf
// exchange failure is non-fatal on the static-auth path. These fields let the
// allow audit faithfully record the resolved grant user and the real exchange
// outcome.
type spireAuditCtx struct {
	callerUser        string // grant.user — the delegated end-user identity
	grantSandboxUID   string
	grantScope        string
	grantPath         string // full Vault KV path the grant was read from
	grantNoncePresent bool
	exchangeResult    string // "success" or a safe error code (e.g. "exchange_5xx")
	jitElevated       bool   // true when a sandbox-bound JIT session JWT elevated the tool
	jitSessionID      string // jit-approver session id (vt.Sub) that authorised the elevation
}

// handleSandboxAgentPath implements the SPIRE SVID + Vault grant delegation
// flow (Option D). It reads+validates the consent grant, runs RFC 8693 Phase-1
// impersonation, and selects the per-user static pfSense token.
//
// The sandbox UUID binding comes exclusively from the cryptographic SPIFFE URI
// path (sub = spiffe://<trustdomain>/ns/<ns>/sandbox/<uuid>), which is
// guaranteed non-empty by VerifySVID. The grant's nonce field is vestigial on
// this path — real SPIRE JWT-SVIDs cannot carry custom claims, so there is no
// nonce to match from the SVID. The nonce is retained in the grant document for
// audit purposes only (SetGrant records whether g.Nonce is non-empty).
//
// Returns (downstreamToken, nil) on success.
// On any failure it sends an ImmediateResponse on stream and returns ("", err)
// where err is a non-nil sentinel that tells the caller to return immediately.
func (s *Server) handleSandboxAgentPath(
	ctx context.Context,
	sessionID, traceID, spanID string,
	stream extprocv3.ExternalProcessor_ProcessServer,
	svidClaims *spire.SVIDClaims,
	tool, argsHash string,
	reqPath string,
	jitJWT string,
	aud *spireAuditCtx,
) (string, error) {
	if aud == nil { // defensive: callers always pass a non-nil carry struct
		aud = &spireAuditCtx{}
	}
	emitter := audit.NewEmitter(sessionID, traceID, spanID)
	emitter.SetAgent(svidClaims.SpiffeID, svidClaims.SpiffeID)
	emitter.SetMCP("", tool, argsHash)

	// SandboxUID is guaranteed non-empty by VerifySVID (which parses it from the
	// SPIFFE URI path and fails closed if absent). The false literal for the nonce
	// argument reflects that the SVID carries no nonce — the grant nonce field is
	// recorded later via g.Nonce once the grant is loaded.
	deny := func(httpStatus int, reason, grantResult string) (string, error) {
		emitter.SetGrant(svidClaims.SandboxUID, "", grantResult, false)
		emitter.Emit(ctx, "deny", reason, false, false)
		sendErr := stream.Send(immediateResponse(httpStatus, reason))
		if sendErr != nil {
			return "", sendErr
		}
		return "", fmt.Errorf("denied: %s", reason) // sentinel — caller returns this
	}

	// Validate that the on-behalf exchanger is available (required for this path).
	if s.kcOnBehalf == nil {
		slog.Error("ext_proc: OnBehalfExchanger not configured for SPIRE path")
		return deny(http.StatusForbidden, "on_behalf_exchanger_not_configured", string(grant.ResultAbsent))
	}

	// (b) Vault-read grant by sandbox_uid derived from the SVID sub path.
	// The SandboxUID here is the same UUID that was used as the Vault KV key
	// when the grant was written: secret/data/sandbox-grants/<SandboxUID>.
	grantPath := s.cfg.SandboxGrantPathPrefix
	rawData, vErr := s.vault.FetchGrant(ctx, grantPath, svidClaims.SandboxUID)
	if vErr != nil {
		slog.Error("ext_proc: vault grant fetch error", "sandbox_uid", svidClaims.SandboxUID, "err", vErr)
		vc := vaultErrorCode(vErr)
		emitter.SetVault(vc, grantPath+svidClaims.SandboxUID, vc)
		return deny(http.StatusForbidden, "grant_vault_error", string(grant.ResultAbsent))
	}
	emitter.SetVault("success", grantPath+svidClaims.SandboxUID, "success")
	aud.grantPath = grantPath + svidClaims.SandboxUID

	// nil rawData means 404 (grant not found in Vault).
	if rawData == nil {
		return deny(http.StatusForbidden, "grant_absent", string(grant.ResultAbsent))
	}

	g, gErr := grant.FromVaultData(rawData)
	if gErr != nil {
		var ve *grant.ValidationError
		result := string(grant.ResultMalformed)
		if errors.As(gErr, &ve) {
			result = string(ve.Result)
		}
		slog.Error("ext_proc: grant parse/validate error", "err", gErr)
		return deny(http.StatusForbidden, "grant_malformed", result)
	}

	// (c) Binding check: the grant's sandbox_uid field must match the UUID
	// extracted from the SVID sub path. This cross-validates that the Vault
	// document at the path was written for this specific sandbox identity.
	// Note: CheckNonce is NOT called here. Real SPIRE JWT-SVIDs cannot carry a
	// nonce custom claim, so there is nothing to match from the SVID side.
	// The grant.Nonce field may still be non-empty (written by sandbox-launcher
	// for audit/vestigial purposes) but is not used as a security gate here.
	// The cryptographic binding is the unique sandbox UUID in the SPIFFE URI.
	if g.SandboxUID != svidClaims.SandboxUID {
		slog.Error("ext_proc: grant sandbox_uid mismatch", "svid_uid", svidClaims.SandboxUID, "grant_uid", g.SandboxUID)
		return deny(http.StatusForbidden, "grant_uid_mismatch", string(grant.ResultNonceMismatch))
	}

	// (d) TTL cap check (Finding 3): reject grants whose validity window exceeds
	// the platform maximum, regardless of the created/expiry values.
	if capErr := g.CheckTTLCap(); capErr != nil {
		slog.Error("ext_proc: grant TTL exceeds platform cap", "sandbox_uid", g.SandboxUID, "ttl", g.TTL)
		return deny(http.StatusForbidden, "grant_ttl_exceeds_cap", string(grant.ResultMalformed))
	}

	// (d) TTL expiry check.
	if tErr := g.CheckTTL(time.Now()); tErr != nil {
		slog.Error("ext_proc: grant expired", "sandbox_uid", g.SandboxUID)
		return deny(http.StatusForbidden, "grant_expired", string(grant.ResultExpired))
	}

	// JIT elevation (optional): a sandbox-bound jit-approver session JWT that
	// covers THIS tool is itself the authorization to run it, lifting the
	// read-only baseline for that one tool.
	//
	// SECURITY: the session JWT is independently verified (signature/iss/aud/exp
	// via s.jit) AND must be cryptographically bound to THIS sandbox — its
	// sandbox_uid claim must equal the SVID's sandbox_uid — AND must list the
	// requested tool in tool_scope. Any miss (bad signature, no/!= sandbox_uid,
	// tool not in scope) is ignored and we fall back to the read-only baseline
	// (fail-closed). A JIT grant minted for one sandbox can never elevate another,
	// and elevation is only ever a per-tool exception — it never widens the grant.
	jitElevatesTool := false
	if jitJWT != "" && s.jit != nil {
		vt, jErr := s.jit.Verify(ctx, jitJWT)
		switch {
		case jErr != nil:
			slog.Warn("ext_proc: JIT session JWT verification failed — ignoring for elevation", "err", jErr.Error())
		case vt.SandboxUID == "" || vt.SandboxUID != svidClaims.SandboxUID:
			slog.Warn("ext_proc: JIT session JWT not bound to this sandbox — ignoring for elevation",
				"jit_has_sandbox_uid", vt.SandboxUID != "")
		case !containsTool(vt.ToolScope, tool):
			slog.Warn("ext_proc: JIT session JWT does not cover this tool — ignoring for elevation", "tool", tool)
		default:
			jitElevatesTool = true
			aud.jitElevated = true
			aud.jitSessionID = vt.Sub
			slog.Info("ext_proc: sandbox-bound JIT session elevated tool", "tool", tool, "jit_session", vt.Sub)
		}
	}

	if !jitElevatesTool {
		// No JIT elevation → enforce the read-only baseline.
		// (e) Scope: grant.scope must permit the tool.
		if sErr := g.CheckScope(tool, s.cfg.ReadOnlyToolPrefixes); sErr != nil {
			slog.Error("ext_proc: grant scope denied", "tool", tool, "scope", g.Scope)
			return deny(http.StatusForbidden, "grant_scope_denied", string(grant.ResultScopeDenied))
		}
		// Standard RBAC policy — defense-in-depth. grantScopeGroups hard-pins the
		// sandbox path to mcp-users (read-only); without a JIT session the agent
		// has no group that can run a dangerous tool.
		groups := grantScopeGroups(g.Scope, s.cfg)
		if reason, allow := s.policy.Decide(groups, tool, false, nil); !allow {
			return deny(http.StatusForbidden, reason, string(grant.ResultScopeDenied))
		}
	}
	// else: the tool is explicitly authorised by a verified, sandbox-bound JIT
	// session covering it — allowed, bypassing the read-only baseline for THIS
	// tool only. The downstream credential selection + privileged-target check
	// below still apply.

	// Grant is valid. Record grant audit fields (on this emitter for any later
	// deny, and on aud for the final allow emission in the ResponseHeaders leg).
	emitter.SetGrant(g.SandboxUID, g.Scope, string(grant.ResultValid), g.Nonce != "")
	emitter.SetCallerUser("", g.User, nil) // caller_username = grant.user for audit
	aud.callerUser = g.User
	aud.grantSandboxUID = g.SandboxUID
	aud.grantScope = g.Scope
	aud.grantNoncePresent = g.Nonce != ""

	// (f) RFC 8693 Phase-1 impersonation: requested_subject=grant.user.
	//
	// Credential-injection split (see Config.StaticAuthPaths):
	//   - Static-auth path (/mcp → pfsense-mcp): the injected downstream
	//     credential is the per-user PRE-PROVISIONED static token selected
	//     below from Vault by grant.user. The exchanged Keycloak JWT is NOT the
	//     credential here — it is minted for the audit trail and for JWT-aware
	//     downstreams only. An exchange failure on this path is therefore
	//     NON-FATAL: it is recorded honestly in the audit, but delegation still
	//     completes via the static token. (Without this, a transient/buggy
	//     Keycloak token-exchange takes down a path whose real credential never
	//     depended on the exchange.)
	//   - JWT-downstream path (e.g. /echo): the exchanged token IS the injected
	//     credential, so an exchange failure remains FATAL (fail-closed).
	staticPath := s.cfg.IsStaticAuthPath(reqPath)
	exchangedToken, exErr := s.kcOnBehalf.ExchangeOnBehalf(ctx, g.User, s.cfg.DownstreamAudience)
	if exErr != nil {
		exResult := exchangeErrorCode(exErr)
		emitter.SetKeycloakExchange("on_behalf", s.cfg.DownstreamAudience, exResult)
		aud.exchangeResult = exResult
		if !staticPath {
			// JWT-downstream path: the exchanged token is the credential.
			slog.Error("ext_proc: on-behalf exchange failed (fatal, jwt-downstream path)", "user", "[redacted]", "err", exErr)
			return deny(http.StatusForbidden, "on_behalf_exchange_failed", string(grant.ResultValid))
		}
		// Static-auth path: exchange is audit-only; proceed to static-token
		// injection. Discard the (empty) exchanged token.
		slog.Warn("ext_proc: on-behalf exchange failed but non-fatal on static-auth path — injecting per-user static token",
			"user", "[redacted]", "err", exErr)
		exchangedToken = ""
	} else {
		emitter.SetKeycloakExchange("on_behalf", s.cfg.DownstreamAudience, "success")
		aud.exchangeResult = "success"

		// Finding 4: defense-in-depth group check on the exchanged token.
		// If Keycloak placed a groups claim in the issued token and it contains
		// a privileged group (e.g. mcp-admins), deny. This is a belt-and-suspenders
		// check; Keycloak's own impersonation policy is the primary gate.
		// Only meaningful when an exchanged token exists. On the static-auth path
		// a privileged grant.user is independently neutralised by the read-only
		// hard-pin (grantScopeGroups) enforced above, so skipping this check when
		// the audit-only exchange failed does not widen access.
		if tokenGroups := peekJWTGroups(exchangedToken); isPrivilegedGroup(tokenGroups) {
			slog.Error("ext_proc: on-behalf exchange returned privileged group — denying sandbox agent path",
				"groups_count", len(tokenGroups))
			return deny(http.StatusForbidden, "impersonation_target_is_privileged", string(grant.ResultScopeDenied))
		}
	}

	// The exchanged Keycloak token is recorded for audit only. For the static
	// pfSense path (/mcp), we inject the per-user pfSense bearer from Vault
	// keyed by grant.user — NOT the Keycloak JWT.
	downToken := exchangedToken

	if staticPath {
		// (g) Select per-user pfSense static token from Vault by grant.user.
		m, ferr := s.vault.FetchToolSecret(ctx, s.cfg.StaticTokenSecret)
		if ferr != nil {
			slog.Error("ext_proc: static token fetch failed for sandbox agent")
			return deny(http.StatusForbidden, "static_token_fetch_failed", string(grant.ResultValid))
		}
		ut, _ := m[g.User].(string)
		if ut == "" {
			slog.Error("ext_proc: no static token for user in grant", "user", "[redacted]")
			return deny(http.StatusForbidden, "no_user_token", string(grant.ResultValid))
		}
		downToken = ut
	}

	// Fail-closed invariant: never return an empty downstream credential. On the
	// static-auth path downToken is the per-user static token (non-empty, checked
	// above). On the JWT-downstream path downToken is the exchanged token, which
	// is non-empty here because a failed exchange already returned a deny.
	if downToken == "" {
		slog.Error("ext_proc: empty downstream token on sandbox agent path", "static_path", staticPath)
		return deny(http.StatusForbidden, "empty_downstream_token", string(grant.ResultValid))
	}

	return downToken, nil
}

// grantScopeGroups synthesises a group membership list from the grant scope
// for use with the rbac.Policy. This lets the RBAC policy re-validate the tool
// using the same prefix tables without exposing a new code path.
//
// SECURITY (Finding 5): for the sandbox-agent slice we HARD-PIN to read-only.
// Admin/read-write scopes are only used by the legacy path which verifies a JIT
// session JWT separately. On the sandbox-agent path we never synthesise admin or
// read-write group membership from the grant scope — the grant scope is advisory
// metadata; RBAC is the enforced gate.
func grantScopeGroups(scope string, cfg *config.Config) []string {
	// Hard-pin: sandbox-agent path is always treated as read-only (mcp-users
	// equivalent), regardless of the grant scope value. Admin/read-write capability
	// requires a verified JIT session JWT (enforced in the legacy path; not
	// available on the SPIRE/sandbox-agent path in this slice).
	_ = scope
	return []string{cfg.UserGroup}
}

// containsTool reports whether tool is present in the JIT session's tool_scope.
func containsTool(scope []string, tool string) bool {
	for _, t := range scope {
		if t == tool {
			return true
		}
	}
	return false
}

// privilegedGroups is the set of group names that must never be the target of
// on-behalf impersonation on the sandbox-agent path. Keycloak policy is the
// first gate; this is a defense-in-depth check in code (Finding 4).
var privilegedGroups = []string{"mcp-admins"}

// isPrivilegedGroup returns true if any element of groups matches a privileged
// group name. Case-sensitive to match Keycloak group names exactly.
func isPrivilegedGroup(groups []string) bool {
	for _, g := range groups {
		for _, p := range privilegedGroups {
			if g == p {
				return true
			}
		}
	}
	return false
}

// exchangeErrorCode maps an exchange error to a safe, fixed reason code for
// inclusion in audit result fields. The raw error message (which may contain
// internal addresses, server responses, or partial token values) is NEVER
// placed in the audit result — it is logged only via slog.Error.
func exchangeErrorCode(err error) string {
	if err == nil {
		return "success"
	}
	// ExchangeError carries an HTTP status code from Keycloak.
	// Import is avoided by a type-assertion via the error string convention.
	// We use the keycloak.ExchangeError interface through errors.As — the import
	// of keycloak package here would create a circular dependency since keycloak
	// already imports config. Instead we pattern-match on the error string
	// classifications that are safe to expose (status class, not raw body).
	type statusCoder interface{ StatusCode() int }
	var ee interface {
		Error() string
		GetStatusCode() int
	}
	_ = ee
	// Check if the error wraps an ExchangeError by inspecting its content.
	// We cannot import the keycloak package here (circular), so we examine the
	// error string for the class marker we control ("keycloak exchange: HTTP").
	msg := err.Error()
	switch {
	case strings.Contains(msg, "HTTP 5") || strings.Contains(msg, "HTTP 50"):
		return "exchange_5xx"
	case strings.Contains(msg, "HTTP 4") || strings.Contains(msg, "HTTP 40") ||
		strings.Contains(msg, "HTTP 41") || strings.Contains(msg, "HTTP 42") ||
		strings.Contains(msg, "HTTP 43") || strings.Contains(msg, "HTTP 44") ||
		strings.Contains(msg, "unauthorized"):
		return "exchange_4xx"
	case strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "timeout"):
		return "exchange_network"
	default:
		return "exchange_error"
	}
}

// peekJWTGroups extracts the "groups" claim from an unverified JWT payload.
// This is used ONLY as a defense-in-depth check on the sandbox-agent path AFTER
// the token has already been minted by Keycloak via an authenticated on-behalf
// exchange (the authenticity is already assured). We never trust the result
// for positive access grants — only to detect and DENY impersonation of
// privileged subjects.
//
// Returns nil (not an error) if the token cannot be parsed or has no groups
// claim, so the caller must treat "no groups parsed" as safe (we only deny on
// explicit privileged group membership).
func peekJWTGroups(raw string) []string {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims.Groups
}

// vaultErrorCode maps a Vault error to a safe, fixed reason code for inclusion
// in audit result fields. The raw error message is NEVER placed in audit results.
func vaultErrorCode(err error) string {
	if err == nil {
		return "success"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "403") || strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "forbidden"):
		return "vault_403"
	case strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "timeout"):
		return "vault_network"
	case strings.Contains(msg, "404") || strings.Contains(msg, "not found"):
		return "vault_404"
	default:
		return "vault_error"
	}
}

// bearerFromHeader extracts the raw token from a "Bearer <token>" header.
// Returns "" if the header is absent or malformed.
func bearerFromHeader(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// immediateResponse builds a ProcessingResponse with an ImmediateResponse that
// terminates the proxied request with the given HTTP status.
func immediateResponse(statusCode int, body string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: httpStatusToEnvoy(statusCode),
				},
				Body: []byte(body),
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:   "Content-Type",
								Value: "text/plain",
							},
						},
					},
				},
			},
		},
	}
}

// headerValue extracts the first value of a header by key (case-insensitive) from
// an Envoy HeaderMap.
func headerValue(hdrs *corev3.HeaderMap, key string) string {
	if hdrs == nil {
		return ""
	}
	lkey := toLower(key)
	for _, h := range hdrs.GetHeaders() {
		if toLower(h.GetKey()) == lkey {
			// Envoy ext_proc puts the value in the string `value` field OR the
			// bytes `raw_value` field. agentgateway uses raw_value, so fall back
			// to it when value is empty — otherwise every header reads blank.
			if v := h.GetValue(); v != "" {
				return v
			}
			return string(h.GetRawValue())
		}
	}
	return ""
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// httpStatusToEnvoy maps a standard HTTP status code to the Envoy StatusCode enum.
func httpStatusToEnvoy(code int) typev3.StatusCode {
	switch code {
	case http.StatusOK:
		return typev3.StatusCode_OK
	case http.StatusUnauthorized:
		return typev3.StatusCode_Unauthorized
	case http.StatusForbidden:
		return typev3.StatusCode_Forbidden
	case http.StatusBadRequest:
		return typev3.StatusCode_BadRequest
	case 413:
		return typev3.StatusCode_PayloadTooLarge
	default:
		return typev3.StatusCode_InternalServerError
	}
}
