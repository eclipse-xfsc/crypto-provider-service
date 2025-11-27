package types

import (
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoHashParameter struct {
	Identifier    CryptoIdentifier
	HashAlgorithm HashAlgorithm
}

func FromProtoHashParam(p *pb.CryptoHashParameter) CryptoHashParameter {
	if p == nil {
		return CryptoHashParameter{}
	}

	return CryptoHashParameter{
		Identifier:    FromProtoIdentifier(p.Identifier),
		HashAlgorithm: HashAlgorithm(p.HashAlgorithm),
	}
}

func ToProtoHashParam(t CryptoHashParameter) *pb.CryptoHashParameter {
	return &pb.CryptoHashParameter{
		Identifier:    ToProtoIdentifier(t.Identifier),
		HashAlgorithm: ToProtoHashAlgorithm(t.HashAlgorithm),
	}
}
