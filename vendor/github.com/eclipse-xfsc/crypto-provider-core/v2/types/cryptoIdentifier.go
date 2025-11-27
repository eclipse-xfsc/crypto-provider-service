package types

import (
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoIdentifier struct {
	KeyId         string
	CryptoContext CryptoContext
}

func FromProtoIdentifier(p *pb.CryptoIdentifier) CryptoIdentifier {
	if p == nil {
		return CryptoIdentifier{}
	}

	return CryptoIdentifier{
		KeyId:         p.KeyId,
		CryptoContext: FromProtoContext(p.Ctx),
	}
}

func ToProtoIdentifier(t CryptoIdentifier) *pb.CryptoIdentifier {
	return &pb.CryptoIdentifier{
		KeyId: t.KeyId,
		Ctx:   ToProtoContext(t.CryptoContext),
	}
}
