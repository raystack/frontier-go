package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/raystack/frontier/pkg/server/consts"
	frontierv1beta1 "github.com/raystack/frontier/proto/v1beta1"
	"net/http"
	"net/url"
	"strings"
)

const (
	DefaultUserTokenHeader = consts.UserTokenRequestKey
	DefaultSessionID       = consts.SessionRequestKey
)

func GetAuthenticatedUser(r *http.Request, httpClient HTTPClient, frontierHost *url.URL, frontierKeySet jwk.Set) (*frontierv1beta1.User, map[string]any, string, error) {
	// check if context token is present
	userToken := strings.TrimSpace(r.Header.Get(DefaultUserTokenHeader))
	authHeader := r.Header.Get("authorization")
	if authHeader != "" {
		// check for bearer token, if present use that as user token
		if strings.HasPrefix(authHeader, "Bearer ") {
			userToken = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	if userToken != "" {
		// if present, verify token
		claims, err := GetTokenClaims(r.Context(), httpClient, frontierHost, frontierKeySet, []byte(userToken))
		if err != nil {
			return nil, nil, "", err
		}
		return GetUserFromClaims(claims), claims, userToken, nil
	}

	// check for session cookie
	sessionCookie, err := r.Cookie(DefaultSessionID)
	if err != nil || sessionCookie.Valid() != nil {
		return nil, nil, "", ErrInvalidHeader
	}
	// going via session route is slower then token route, but it also fetches full user profile
	u, userToken, err := GetUserProfile(r.Context(), httpClient, frontierHost, r.Header)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%s : %w", ErrInvalidSession.Error(), err)
	}
	claims, err := GetTokenClaims(r.Context(), httpClient, frontierHost, frontierKeySet, []byte(userToken))
	if err != nil {
		return nil, nil, "", fmt.Errorf("%s : %w", ErrInvalidSession.Error(), err)
	}
	return u, claims, userToken, nil
}

// GetTokenClaims parse & verify jwt with frontier public keys or user public keys
func GetTokenClaims(ctx context.Context, httpClient HTTPClient, frontierHost *url.URL, frontierKeySet jwk.Set, userToken []byte) (map[string]any, error) {
	var keySet = frontierKeySet

	// check if token is created by frontier or user
	insecureToken, err := jwt.ParseInsecure(userToken)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidToken.Error(), err)
	}
	if tokenType, ok := insecureToken.Get("gen"); !ok || tokenType != "system" {
		// token is created by user, fetch user public keys
		kid, _ := insecureToken.Get(jwk.KeyIDKey)
		keyUrl := fmt.Sprintf(ServiceUserPublicKeyPath, insecureToken.Subject(), kid)

		// TODO(kushsharma): cache user public keys
		userKeyResp, err := httpClient.Get(frontierHost.ResolveReference(&url.URL{Path: keyUrl}).String())
		if err != nil {
			return nil, fmt.Errorf("failed to fetch user public keys: %w", err)
		}
		// parse user public keys
		keySet, err = jwk.ParseReader(userKeyResp.Body)
		if err != nil {
			return nil, err
		}
	}

	// verify token with jwks
	verifiedToken, err := jwt.Parse(userToken, jwt.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidToken.Error(), err)
	}
	tokenClaims, err := verifiedToken.AsMap(ctx)
	if err != nil {
		return nil, err
	}
	return tokenClaims, nil
}

func GetUserFromClaims(claims map[string]any) *frontierv1beta1.User {
	u := &frontierv1beta1.User{
		Id: claims["sub"].(string),
	}
	if val, ok := claims["email"]; ok {
		u.Email = val.(string)
	}
	if val, ok := claims["name"]; ok {
		u.Name = val.(string)
	}
	return u
}

// GetUserProfile fetches profile of authorized user from frontier server
func GetUserProfile(ctx context.Context, client HTTPClient, frontierHost *url.URL, headers http.Header) (*frontierv1beta1.User, string, error) {
	getUserRequest, err := http.NewRequestWithContext(ctx, http.MethodGet,
		frontierHost.ResolveReference(&url.URL{Path: CurrentUserProfilePath}).String(), nil)
	if err != nil {
		return nil, "", err
	}
	getUserRequest.Header = headers
	resp, err := client.Do(getUserRequest)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", ErrInternalServer
	}
	currentUserResp := &frontierv1beta1.GetCurrentUserResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&currentUserResp); err != nil {
		return nil, "", err
	}
	userToken := resp.Header.Get(consts.UserTokenRequestKey)
	return currentUserResp.GetUser(), userToken, nil
}
