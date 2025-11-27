package core

import (
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

// CryptoEngine returns a gRPC client using CRYPTO_GRPC_ADDR or localhost.
func CryptoEngine() (types.CryptoProvider, func()) {
	addr := os.Getenv("CRYPTO_GRPC_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9191"
	}
	return CreateCryptoEngine(addr, insecure.NewCredentials())
}

// CreateCryptoEngine builds a gRPC client using the modern NewClient API.
func CreateCryptoEngine(addr string, transportCredentials credentials.TransportCredentials) (types.CryptoProvider, func()) {
	if addr == "" {
		return nil, nil
	}

	// Modern gRPC client constructor
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(transportCredentials),
	)

	if err != nil {
		panic("failed to create gRPC client: " + err.Error())
	}

	cleanup := func() {
		conn.Close()
	}

	client := pb.NewCryptoProviderServiceClient(conn)

	return types.NewCryptoProviderClient(client), cleanup
}
