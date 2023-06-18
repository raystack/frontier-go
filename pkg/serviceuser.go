package pkg

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/raystack/shield/pkg/utils"
	shieldv1beta1 "github.com/raystack/shield/proto/v1beta1"
	"time"
)

type ServiceUserTokenGenerator func() ([]byte, error)

func GetServiceUserTokenGenerator(credential *shieldv1beta1.KeyCredential) (ServiceUserTokenGenerator, error) {
	// generate a token out of key
	rsaKey, err := jwk.ParseKey([]byte(credential.GetPrivateKey()), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	if err = rsaKey.Set(jwk.KeyIDKey, credential.GetKid()); err != nil {
		return nil, err
	}
	return func() ([]byte, error) {
		return utils.BuildToken(rsaKey, "//shield-go-sdk", credential.GetPrincipalId(), time.Hour*12, nil)
	}, nil
}
