// Package extproc implements the Envoy ExternalProcessor gRPC service.
// Each bidirectional stream drives the following state machine:
//
//	RequestHeaders -> RequestBody -> ResponseHeaders
//
// The service performs credential delegation: it extracts the caller's identity,
// exchanges it for a downstream token (Keycloak), fetches tool secrets (Vault),
// injects the downstream token into the upstream request, and strips credential
// headers from the upstream response.
//
// The service is fail-closed: any error in the exchange or Vault legs causes
// an ImmediateResponse 403 and denies the request.
//
// Fail-closed on body-less / headers-only requests: a downstream credential is
// minted ONLY in the RequestBody leg. If a stream reaches ResponseHeaders
// without a successful exchange (body-less request, empty body, a
// processing-mode downgrade, or a streamed upstream), the request is DENIED —
// the service never emits an allow/inject with an empty downstream token.
package extproc

import (
	"context"
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
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/inject"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/mcp"
	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/rbac"
)

// Exchanger is the interface for the Keycloak token exchange leg.
type Exchanger interface {
	Exchange(ctx context.Context, callerToken, audience string) (string, error)
}

// VaultClient is the interface for the Vault secret retrieval leg.
type VaultClient interface {
	FetchToolSecret(ctx context.Context, tool string) (map[string]interface{}, error)
}

// JITVerifier verifies a jit-approver session JWT and returns its tool_scope.
type JITVerifier interface {
	Verify(ctx context.Context, raw string) (*jwks.VerifiedToken, error)
}

// Server implements extprocv3.ExternalProcessorServer.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	cfg      *config.Config
	kc       Exchanger
	vault    VaultClient
	verifier claims.Verifier
	jit      JITVerifier
	policy   rbac.Policy
}

// NewServer creates a new ext_proc server. verifier independently verifies the
// caller's JWT (defense in depth — the gateway is not trusted). jit may be nil
// (JIT gate disabled — dangerous tools then require admin only).
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

// Process handles a single bidirectional gRPC stream from Envoy.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	// per-stream state
	var (
		identity       *claims.Identity
		authHeader     string
		reqPath        string
		jitJWT         string
		sessionID      string
		traceID        string
		spanID         string
		mcpReq         *mcp.Request
		downToken      string
		delegationDone bool // true only after BOTH exchange legs minted a real downstream credential
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

			// Independently verify the caller token against Keycloak JWKS
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

			// Tool-level RBAC: enforce the kyverno authz policies here (the
			// gateway forwards no claims to ext_authz, and the deployed
			// kyverno-envoy-plugin lacks the mcp CEL lib). For dangerous tools,
			// verify the jit-approver session JWT (X-JIT-Session-JWT) and require
			// the tool in its tool_scope.
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
					emitter.SetKeycloakExchange(string(s.cfg.ExchangeMode), s.cfg.DownstreamAudience, "error:"+err.Error())
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
					emitter.SetVault("error:"+err.Error(), secretPath, "error:"+err.Error())
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
			emitter.SetKeycloakExchange(string(s.cfg.ExchangeMode), s.cfg.DownstreamAudience, "success")
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
