package main

import (
	"fmt"
	"github.com/raystack/frontier-go/middleware"
	"log"
	"net/http"
	"net/url"
	"os"
)

var (
	addr                    = ":12000"
	frontierRESTEndpoint, _ = url.Parse("http://localhost:7400")
)

func main() {
	if val := os.Getenv("ADDR"); val != "" {
		addr = val
	}

	router := http.NewServeMux()
	router.Handle("/ping", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Println(request.Header)
		fmt.Println(request.Context())
		_, _ = writer.Write([]byte("pong"))
	}))

	authHandler, err := middleware.NewAuthHandler(
		middleware.WithRESTEndpoint(frontierRESTEndpoint),
		middleware.WithHTTPClient(http.DefaultClient),
		middleware.WithResourceControlMapping(map[middleware.ResourcePath]middleware.ResourceControlFunc{
			{
				Path:   "/ping",
				Method: http.MethodGet,
			}: func(r *http.Request) middleware.ResourceControl {
				organizationID := r.URL.Query().Get("org_id")
				return middleware.ResourceControl{
					Resource:   fmt.Sprintf("organization:%s", organizationID),
					Permission: "get",
				}
			},
		}),
	)
	if err != nil {
		panic(err)
	}

	// middlewares will be applied bottom up
	withAuthz := authHandler.WithAuthorization(router)
	withAuthn := authHandler.WithAuthentication(withAuthz)

	log.Printf("server is listening at %s", addr)
	_ = http.ListenAndServe(addr, withAuthn)
}
