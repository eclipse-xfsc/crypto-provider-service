package types

import (
	"context"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type grpcCryptoProviderClient struct {
	client pb.CryptoProviderServiceClient
}

func NewCryptoProviderClient(pbClient pb.CryptoProviderServiceClient) CryptoProvider {
	return &grpcCryptoProviderClient{client: pbClient}
}

// ===============================
//   RPC → Local Interface MAPPING
// ===============================

func (c *grpcCryptoProviderClient) CreateCryptoContext(ctx CryptoContext) error {
	_, err := c.client.CreateCryptoContext(context.Background(), &pb.CreateContextRequest{
		Ctx: ToProtoContext(ctx),
	})
	return err
}

func (c *grpcCryptoProviderClient) DestroyCryptoContext(ctx CryptoContext) error {
	_, err := c.client.DestroyCryptoContext(context.Background(), &pb.DestroyContextRequest{
		Ctx: ToProtoContext(ctx),
	})
	return err
}

func (c *grpcCryptoProviderClient) IsCryptoContextExisting(ctx CryptoContext) (bool, error) {
	r, err := c.client.IsCryptoContextExisting(context.Background(), &pb.IsContextExistingRequest{
		Ctx: ToProtoContext(ctx),
	})
	if err != nil {
		return false, err
	}
	return r.Value, nil
}

func (c *grpcCryptoProviderClient) GetNamespaces(ctx CryptoContext) ([]string, error) {
	r, err := c.client.GetNamespaces(context.Background(), &pb.GetNamespacesRequest{
		Ctx: ToProtoContext(ctx),
	})
	if err != nil {
		return nil, err
	}
	return r.Namespaces, nil
}

func (c *grpcCryptoProviderClient) GenerateRandom(ctx CryptoContext, number int) ([]byte, error) {
	r, err := c.client.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{
		Ctx:    ToProtoContext(ctx),
		Number: int32(number),
	})
	if err != nil {
		return nil, err
	}
	return r.Random, nil
}

func (c *grpcCryptoProviderClient) Hash(p CryptoHashParameter, msg []byte) ([]byte, error) {
	r, err := c.client.Hash(context.Background(), &pb.HashRequest{
		Parameter: ToProtoHashParam(p),
		Msg:       msg,
	})
	if err != nil {
		return nil, err
	}
	return r.Hash, nil
}

func (c *grpcCryptoProviderClient) Encrypt(id CryptoIdentifier, data []byte) ([]byte, error) {
	r, err := c.client.Encrypt(context.Background(), &pb.EncryptRequest{
		Identifier: ToProtoIdentifier(id),
		Data:       data,
	})
	if err != nil {
		return nil, err
	}
	return r.Cipher, nil
}

func (c *grpcCryptoProviderClient) Decrypt(id CryptoIdentifier, data []byte) ([]byte, error) {
	r, err := c.client.Decrypt(context.Background(), &pb.DecryptRequest{
		Identifier: ToProtoIdentifier(id),
		Data:       data,
	})
	if err != nil {
		return nil, err
	}
	return r.Plain, nil
}

func (c *grpcCryptoProviderClient) Sign(id CryptoIdentifier, data []byte) ([]byte, error) {
	r, err := c.client.Sign(context.Background(), &pb.SignRequest{
		Identifier: ToProtoIdentifier(id),
		Data:       data,
	})
	if err != nil {
		return nil, err
	}
	return r.Signature, nil
}

func (c *grpcCryptoProviderClient) Verify(id CryptoIdentifier, data []byte, signature []byte) (bool, error) {
	r, err := c.client.Verify(context.Background(), &pb.VerifyRequest{
		Identifier: ToProtoIdentifier(id),
		Data:       data,
		Signature:  signature,
	})
	if err != nil {
		return false, err
	}
	return r.Valid, nil
}

func (c *grpcCryptoProviderClient) GetKeys(f CryptoFilter) (*CryptoKeySet, error) {
	r, err := c.client.GetKeys(context.Background(), &pb.GetKeysRequest{
		Filter: ToProtoFilter(f),
	})
	if err != nil {
		return nil, err
	}
	set := FromProtoKeySet(r.Keys)
	return &set, nil
}

func (c *grpcCryptoProviderClient) GetKey(id CryptoIdentifier) (*CryptoKey, error) {
	r, err := c.client.GetKey(context.Background(), &pb.GetKeyRequest{
		Identifier: ToProtoIdentifier(id),
	})
	if err != nil {
		return nil, err
	}
	k := FromProtoKey(r.Key)
	return &k, nil
}

func (c *grpcCryptoProviderClient) GenerateKey(p CryptoKeyParameter) error {
	_, err := c.client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{
		Parameter: ToProtoKeyParam(p),
	})
	return err
}

func (c *grpcCryptoProviderClient) IsKeyExisting(id CryptoIdentifier) (bool, error) {
	r, err := c.client.IsKeyExisting(context.Background(), &pb.IsKeyExistingRequest{
		Identifier: ToProtoIdentifier(id),
	})
	if err != nil {
		return false, err
	}
	return r.Value, nil
}

func (c *grpcCryptoProviderClient) DeleteKey(id CryptoIdentifier) error {
	_, err := c.client.DeleteKey(context.Background(), &pb.DeleteKeyRequest{
		Identifier: ToProtoIdentifier(id),
	})
	return err
}

func (c *grpcCryptoProviderClient) RotateKey(id CryptoIdentifier) error {
	_, err := c.client.RotateKey(context.Background(), &pb.RotateKeyRequest{
		Identifier: ToProtoIdentifier(id),
	})
	return err
}

func (c *grpcCryptoProviderClient) GetSupportedKeysAlgs() []KeyType {
	r, err := c.client.GetSupportedKeysAlgs(context.Background(), &pb.Empty{})
	if err != nil {
		return nil
	}
	out := make([]KeyType, len(r.Types))
	for i, v := range r.Types {
		out[i] = FromProtoKeyType(v)
	}
	return out
}

func (c *grpcCryptoProviderClient) GetSupportedHashAlgs() []HashAlgorithm {
	r, err := c.client.GetSupportedHashAlgs(context.Background(), &pb.Empty{})
	if err != nil {
		return nil
	}
	out := make([]HashAlgorithm, len(r.Algorithms))
	for i, v := range r.Algorithms {
		out[i] = FromProtoHashAlgorithm(v)
	}
	return out
}
