package types

import (
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoKey struct {
	Key     []byte //pem format expected in case of key pair
	Version string
	CryptoKeyParameter
}

func FromProtoKey(p *pb.CryptoKey) CryptoKey {
	if p == nil {
		return CryptoKey{}
	}

	kp := FromProtoKeyParam(p.KeyParameter)

	return CryptoKey{
		Key:                p.Key,
		Version:            p.Version,
		CryptoKeyParameter: kp,
	}
}

func ToProtoKey(t CryptoKey) *pb.CryptoKey {
	return &pb.CryptoKey{
		Key:          t.Key,
		Version:      t.Version,
		KeyParameter: ToProtoKeyParam(t.CryptoKeyParameter),
	}
}
