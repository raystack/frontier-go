/*
Before running this example, you need to start the server first.
See example/server/main.go for more details.

Create a new service user in auth server and generate a key credential.[/v1beta1/serviceusers, /v1beta1/serviceusers/:id/keys]
Then, copy the credential to serviceuser_key.protojson file.
Ensure serviceuser has a role assinged in org for viewer.[/v1beta1/policies]
*/
package main

import (
	_ "embed"
	"fmt"
	"github.com/raystack/shield-go/pkg"
	shieldv1beta1 "github.com/raystack/shield/proto/v1beta1"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"net/http"
)

//go:embed serviceuser_key.protojson
var serviceUserKey []byte

var (
	serverAddr = "http://localhost:12000"
)

func main() {
	credential := &shieldv1beta1.KeyCredential{}
	if err := protojson.Unmarshal(serviceUserKey, credential); err != nil {
		panic(err)
	}
	tokenGenerator, err := pkg.GetServiceUserTokenGenerator(credential)
	if err != nil {
		panic(err)
	}
	tempToken, err := tokenGenerator()
	if err != nil {
		panic(err)
	}

	protectedServerRequest, err := http.NewRequest(http.MethodGet, serverAddr+"/ping?org_id=org1", nil)
	if err != nil {
		panic(err)
	}
	protectedServerRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tempToken))

	resp, err := http.DefaultClient.Do(protectedServerRequest)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(respBody))
}
