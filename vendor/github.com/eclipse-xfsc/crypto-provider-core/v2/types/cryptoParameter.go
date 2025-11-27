package types

import (
	"encoding/json"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoKeyParameter struct {
	Identifier CryptoIdentifier
	KeyType    KeyType
	Params     json.RawMessage
}

func FromProtoKeyParam(p *pb.CryptoKeyParameter) CryptoKeyParameter {
	if p == nil {
		return CryptoKeyParameter{}
	}

	return CryptoKeyParameter{
		Identifier: FromProtoIdentifier(p.Identifier),
		KeyType:    FromProtoKeyType(p.KeyType),
		Params:     p.Params,
	}
}

func ToProtoKeyParam(t CryptoKeyParameter) *pb.CryptoKeyParameter {
	return &pb.CryptoKeyParameter{
		Identifier: ToProtoIdentifier(t.Identifier),
		KeyType:    ToProtoKeyType(t.KeyType),
		Params:     t.Params,
	}
}
