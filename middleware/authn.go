package middleware

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/odpf/shield-go/pkg"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	RestEndpoint = strings.TrimSpace(os.Getenv("SHIELD_REST_ENDPOINT"))
)

type contextKey struct {
	name string
}

func (c *contextKey) String() string { return "context value " + c.name }

var (
	// AuthenticatedUserContextKey is context key that contains the user object
	AuthenticatedUserContextKey = contextKey{name: "auth-user"}

	// UserTokenContextKey context key that contains jwt token
	UserTokenContextKey = contextKey{"user-token"}

	// TokenClaimsContextKey context key that contains jwt token claims
	TokenClaimsContextKey = contextKey{"token-claims"}
)

type AuthHandler struct {
	// resourceControlStore is a map of resource path to resource control
	// TODO(kushsharma): add support for multiple resource control per path
	resourceControlStore map[ResourcePath]ResourceControlFunc

	ctx           context.Context
	shieldHost    *url.URL
	httpClient    pkg.HTTPClient
	denyByDefault bool
	jwkCache      pkg.ShieldJWKCache
}

// WithRESTEndpoint provides url for shield server
// For e.g. http://localhost:7400
func WithRESTEndpoint(endpoint *url.URL) func(*AuthHandler) {
	return func(ensureAuth *AuthHandler) {
		ensureAuth.shieldHost = endpoint
	}
}

func WithHTTPClient(client pkg.HTTPClient) func(*AuthHandler) {
	return func(ensureAuth *AuthHandler) {
		ensureAuth.httpClient = client
	}
}

func WithResourceControlMapping(rcm map[ResourcePath]ResourceControlFunc) func(*AuthHandler) {
	return func(ensureAuth *AuthHandler) {
		ensureAuth.resourceControlStore = rcm
	}
}

func WithAuthzAllowByDefault() func(*AuthHandler) {
	return func(ensureAuth *AuthHandler) {
		ensureAuth.denyByDefault = false
	}
}

func WithJWKSetCache(jwkSetCache pkg.ShieldJWKCache) func(*AuthHandler) {
	return func(ensureAuth *AuthHandler) {
		ensureAuth.jwkCache = jwkSetCache
	}
}

// NewAuthHandler creates a middleware for net/http router that
// checks all incoming requests for valid authorization.
// WithAuthorization is done using either user json web token in
// WithAuthorization header or session cookies.
// Add this middleware on routes that needs to be protected via Shield
func NewAuthHandler(opts ...func(auth *AuthHandler)) (*AuthHandler, error) {
	var hostURL *url.URL
	if len(RestEndpoint) > 0 {
		if url, err := url.Parse(RestEndpoint); err != nil {
			return nil, err
		} else {
			hostURL = url
		}
	}

	ea := &AuthHandler{
		ctx:                  context.Background(),
		resourceControlStore: map[ResourcePath]ResourceControlFunc{},
		shieldHost:           hostURL,
		httpClient:           http.DefaultClient,
		denyByDefault:        true,
	}
	for _, o := range opts {
		o(ea)
	}

	// ensure base configurations are set
	if len(ea.shieldHost.Host) == 0 {
		return nil, pkg.ErrMissingHost
	}
	if ea.jwkCache == nil {
		shieldJWKsURL := fmt.Sprintf("%s/%s", ea.shieldHost, pkg.JWKSAccessPath)

		// note that by default refreshes only happen very 15 minutes at the earliest.
		ea.jwkCache = pkg.NewJWKCacheForURL(shieldJWKsURL, ea.ctx)
		if err := ea.jwkCache.Register(jwk.WithHTTPClient(ea.httpClient)); err != nil {
			return nil, err
		}
	}
	return ea, nil
}

func (ea *AuthHandler) WithAuthentication(base http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keySet, err := ea.jwkCache.Get(ea.ctx)
		if err != nil {
			http.Error(w, fmt.Errorf("%s: %w", pkg.ErrJWKsFetch, err).Error(), http.StatusUnauthorized)
			return
		}
		user, claims, token, err := pkg.GetAuthenticatedUser(r, ea.httpClient, ea.shieldHost, keySet)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// enrich request context
		ctxWithUser := context.WithValue(r.Context(), AuthenticatedUserContextKey, user)
		ctxWithToken := context.WithValue(ctxWithUser, UserTokenContextKey, token)
		ctxWithClaims := context.WithValue(ctxWithToken, TokenClaimsContextKey, claims)
		rWithUser := r.WithContext(ctxWithClaims)
		base.ServeHTTP(w, rWithUser)
	}
}
