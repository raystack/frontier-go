package client

import (
	"context"
	frontierv1beta1 "github.com/raystack/frontier/proto/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"net/http"
	"time"
)

var (
	DialTimeout     = time.Second * 5
	DefaultDialOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(5<<20), // 5MB
			grpc.MaxCallSendMsgSize(5<<20), // 5MB
		),
	}
)

// GetHeadersAsMetadata converts request headers to grpc metadata
// useful for passing auth headers, cookies to auth server
func GetHeadersAsMetadata(r *http.Request) metadata.MD {
	md := metadata.MD{}
	for k, v := range r.Header {
		md.Set(k, v[0])
	}
	return md
}

func CreateBaseClient(ctx context.Context, host string, opts ...grpc.DialOption) (frontierv1beta1.FrontierServiceClient, func(), error) {
	dialTimeoutCtx, dialCancel := context.WithTimeout(ctx, DialTimeout)
	conn, err := grpc.DialContext(dialTimeoutCtx, host, opts...)
	if err != nil {
		dialCancel()
		return nil, nil, err
	}
	cancel := func() {
		dialCancel()
		conn.Close()
	}

	client := frontierv1beta1.NewFrontierServiceClient(conn)
	client.GetCurrentUser(ctx, &frontierv1beta1.GetCurrentUserRequest{}, grpc.Header(&metadata.MD{}))
	return client, cancel, nil
}

func CreateAdminClient(ctx context.Context, host string, opts ...grpc.DialOption) (frontierv1beta1.AdminServiceClient, func(), error) {
	dialTimeoutCtx, dialCancel := context.WithTimeout(ctx, DialTimeout)
	conn, err := grpc.DialContext(dialTimeoutCtx, host, opts...)
	if err != nil {
		dialCancel()
		return nil, nil, err
	}
	cancel := func() {
		dialCancel()
		conn.Close()
	}

	client := frontierv1beta1.NewAdminServiceClient(conn)
	return client, cancel, nil
}
