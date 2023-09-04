package pkg

import (
	"crypto/rsa"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/raystack/frontier/pkg/utils"
	frontierv1beta1 "github.com/raystack/frontier/proto/v1beta1"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
	"google.golang.org/protobuf/encoding/protojson"
	"time"
)

type ServiceUserTokenGenerator func() ([]byte, error)

func GetServiceUserTokenGenerator(credential *frontierv1beta1.KeyCredential) (ServiceUserTokenGenerator, error) {
	// generate a token out of key
	rsaKey, err := jwk.ParseKey([]byte(credential.GetPrivateKey()), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	if err = rsaKey.Set(jwk.KeyIDKey, credential.GetKid()); err != nil {
		return nil, err
	}
	return func() ([]byte, error) {
		return utils.BuildToken(rsaKey, "//frontier-go-sdk", credential.GetPrincipalId(), time.Hour*12, nil)
	}, nil
}

func newJWTSource(jsonKey []byte, audience string) (oauth2.TokenSource, error) {
	if audience == "" {
		return nil, fmt.Errorf("missing audience for JWT access token")
	}

	keyCred := &frontierv1beta1.KeyCredential{}
	err := protojson.Unmarshal(jsonKey, keyCred)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON key: %v", err)
	}
	parsedKey, err := jwk.ParseKey([]byte(keyCred.PrivateKey), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("could not parse key: %v", err)
	}
	pk := &rsa.PrivateKey{}
	err = parsedKey.Raw(pk)
	if err != nil {
		return nil, fmt.Errorf("could not extract private key: %v", err)
	}

	ts := &jwtAccessTokenSource{
		principal: keyCred.PrincipalId,
		audience:  audience,
		pk:        pk,
		pkID:      keyCred.Kid,
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	rts := oauth2.ReuseTokenSource(tok, ts)
	return rts, nil
}

type jwtAccessTokenSource struct {
	principal string
	audience  string
	pk        *rsa.PrivateKey
	pkID      string
}

func (ts *jwtAccessTokenSource) Token() (*oauth2.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	cs := &jws.ClaimSet{
		Iss: ts.principal,
		Sub: ts.principal,
		Aud: ts.audience,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     ts.pkID,
	}
	msg, err := jws.Encode(hdr, cs, ts.pk)
	if err != nil {
		return nil, fmt.Errorf("could not encode JWT: %v", err)
	}
	return &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}
