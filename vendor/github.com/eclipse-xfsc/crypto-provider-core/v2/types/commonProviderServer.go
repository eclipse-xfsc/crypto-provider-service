package types

import (
	"context"
	"fmt"
	"net"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
	"google.golang.org/grpc"
)

type CryptoProviderServer struct {
	pb.UnimplementedCryptoProviderServiceServer
	impl CryptoProvider
}

func NewServer(impl CryptoProvider) *CryptoProviderServer {
	return &CryptoProviderServer{impl: impl}
}

// =========================
// RPC METHOD MAPPINGS
// =========================

// ============================================================================
// RPC METHOD MAPPINGS (pb → local types → impl → pb) WITHOUT LOGGER
// ============================================================================

func (s *CryptoProviderServer) CreateCryptoContext(ctx context.Context, req *pb.CreateContextRequest) (*pb.BoolResponse, error) {
	local := FromProtoContext(req.Ctx)
	err := s.impl.CreateCryptoContext(local)
	return &pb.BoolResponse{Value: err == nil}, err
}

func (s *CryptoProviderServer) DestroyCryptoContext(ctx context.Context, req *pb.DestroyContextRequest) (*pb.BoolResponse, error) {
	local := FromProtoContext(req.Ctx)
	err := s.impl.DestroyCryptoContext(local)
	return &pb.BoolResponse{Value: err == nil}, err
}

func (s *CryptoProviderServer) IsCryptoContextExisting(ctx context.Context, req *pb.IsContextExistingRequest) (*pb.BoolResponse, error) {
	local := FromProtoContext(req.Ctx)
	v, err := s.impl.IsCryptoContextExisting(local)
	return &pb.BoolResponse{Value: v}, err
}

func (s *CryptoProviderServer) GetNamespaces(ctx context.Context, req *pb.GetNamespacesRequest) (*pb.NamespacesResponse, error) {
	local := FromProtoContext(req.Ctx)
	ns, err := s.impl.GetNamespaces(local)
	return &pb.NamespacesResponse{Namespaces: ns}, err
}

func (s *CryptoProviderServer) GenerateRandom(ctx context.Context, req *pb.GenerateRandomRequest) (*pb.RandomResponse, error) {
	local := FromProtoContext(req.Ctx)
	r, err := s.impl.GenerateRandom(local, int(req.Number))
	return &pb.RandomResponse{Random: r}, err
}

func (s *CryptoProviderServer) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	param := FromProtoHashParam(req.Parameter)
	hash, err := s.impl.Hash(param, req.Msg)
	return &pb.HashResponse{Hash: hash}, err
}

func (s *CryptoProviderServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	result, err := s.impl.Encrypt(id, req.Data)
	return &pb.EncryptResponse{Cipher: result}, err
}

func (s *CryptoProviderServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	result, err := s.impl.Decrypt(id, req.Data)
	return &pb.DecryptResponse{Plain: result}, err
}

func (s *CryptoProviderServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	sig, err := s.impl.Sign(id, req.Data)
	return &pb.SignResponse{Signature: sig}, err
}

func (s *CryptoProviderServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	val, err := s.impl.Verify(id, req.Data, req.Signature)
	return &pb.VerifyResponse{Valid: val}, err
}

func (s *CryptoProviderServer) GetKeys(ctx context.Context, req *pb.GetKeysRequest) (*pb.GetKeysResponse, error) {
	filter := FromProtoFilter(req.Filter)
	keys, err := s.impl.GetKeys(filter)
	return &pb.GetKeysResponse{Keys: ToProtoKeySet(keys)}, err
}

func (s *CryptoProviderServer) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	key, err := s.impl.GetKey(id)
	if err != nil {
		return nil, err
	}
	return &pb.GetKeyResponse{Key: ToProtoKey(*key)}, nil
}

func (s *CryptoProviderServer) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.BoolResponse, error) {
	param := FromProtoKeyParam(req.Parameter)
	err := s.impl.GenerateKey(param)
	return &pb.BoolResponse{Value: err == nil}, err
}

func (s *CryptoProviderServer) IsKeyExisting(ctx context.Context, req *pb.IsKeyExistingRequest) (*pb.BoolResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	val, err := s.impl.IsKeyExisting(id)
	return &pb.BoolResponse{Value: val}, err
}

func (s *CryptoProviderServer) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.BoolResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	err := s.impl.DeleteKey(id)
	return &pb.BoolResponse{Value: err == nil}, err
}

func (s *CryptoProviderServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.BoolResponse, error) {
	id := FromProtoIdentifier(req.Identifier)
	err := s.impl.RotateKey(id)
	return &pb.BoolResponse{Value: err == nil}, err
}

func (s *CryptoProviderServer) GetSupportedKeysAlgs(ctx context.Context, _ *pb.Empty) (*pb.SupportedKeyTypesResponse, error) {
	local := s.impl.GetSupportedKeysAlgs()

	// map []types.KeyType → []pb.KeyType
	out := make([]pb.KeyType, len(local))
	for i, k := range local {
		out[i] = ToProtoKeyType(k)
	}

	return &pb.SupportedKeyTypesResponse{Types: out}, nil
}

func (s *CryptoProviderServer) GetSupportedHashAlgs(ctx context.Context, _ *pb.Empty) (*pb.SupportedHashTypesResponse, error) {
	local := s.impl.GetSupportedHashAlgs()

	// map []types.HashAlgorithm → []pb.HashAlgorithm
	out := make([]pb.HashAlgorithm, len(local))
	for i, h := range local {
		out[i] = ToProtoHashAlgorithm(h)
	}

	return &pb.SupportedHashTypesResponse{Algorithms: out}, nil
}

// =========================
// START SERVER
// =========================

func Start(provider CryptoProvider, addr string) (error, func()) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err), nil
	}

	s := grpc.NewServer()
	pb.RegisterCryptoProviderServiceServer(s, NewServer(provider))

	fmt.Println("CryptoProvider gRPC server running at", addr)
	return s.Serve(lis), func() {
		lis.Close()
		s.Stop()
	}
}
