package core

import (
	"context"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

// CryptoEngine returns a gRPC client using CRYPTO_GRPC_ADDR or localhost.
func CryptoEngine(ctx context.Context) (types.CryptoProvider, func(), error) {
	addr := os.Getenv("CRYPTO_GRPC_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9191"
	}
	return CreateCryptoEngine(ctx, addr, insecure.NewCredentials())
}

// CreateCryptoEngine builds a gRPC client using the modern NewClient API.
func CreateCryptoEngine(
	ctx context.Context,
	addr string,
	transportCredentials credentials.TransportCredentials,
) (types.CryptoProvider, func(), error) {
	if addr == "" {
		return nil, nil, errors.New("crypto grpc address is empty")
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(transportCredentials),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create crypto provider client: %w", err)
	}

	cleanup := func() {
		_ = conn.Close()
	}

	if err := waitForReady(ctx, conn); err != nil {
		cleanup()
		return nil, nil, err
	}

	client := pb.NewCryptoProviderServiceClient(conn)

	return types.NewCryptoProviderClient(client), cleanup, nil
}

func waitForReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()

	for {
		state := conn.GetState()

		if state == connectivity.Ready {
			return nil
		}

		if state == connectivity.Shutdown {
			return errors.New("crypto provider connection is shutdown")
		}

		if !conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf(
				"crypto provider not ready: %w",
				ctx.Err(),
			)
		}
	}
}
