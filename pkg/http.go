package pkg

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"net/http"
)

const (
	CurrentUserProfilePath   = "/v1beta1/users/self"
	CheckAccessPath          = "/v1beta1/check"
	ServiceUserPublicKeyPath = "/v1beta1/serviceusers/%s/keys/%s"
	JWKSAccessPath           = "/.well-known/jwks.json"
)

type HTTPClient interface {
	Do(r *http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type ShieldJWKCache interface {
	// Get returns jwks set
	Get(ctx context.Context) (jwk.Set, error)
	Refresh(ctx context.Context) (jwk.Set, error)

	// Register registers the URL to be used for fetching JWKs
	// it is mandatory to call this method before calling Get/Refresh
	Register(option ...jwk.RegisterOption) error
}

type JWKCache struct {
	*jwk.Cache
	url string
}

func NewJWKCacheForURL(url string, ctx context.Context, options ...jwk.CacheOption) *JWKCache {
	return &JWKCache{
		Cache: jwk.NewCache(ctx, options...),
		url:   url,
	}
}

func (c *JWKCache) Get(ctx context.Context) (jwk.Set, error) {
	return c.Cache.Get(ctx, c.url)
}

func (c *JWKCache) Refresh(ctx context.Context) (jwk.Set, error) {
	return c.Cache.Refresh(ctx, c.url)
}

func (c *JWKCache) Register(option ...jwk.RegisterOption) error {
	return c.Cache.Register(c.url, option...)
}
