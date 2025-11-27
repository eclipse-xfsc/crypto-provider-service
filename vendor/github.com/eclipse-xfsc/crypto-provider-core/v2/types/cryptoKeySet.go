package types

import (
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoKeySet struct {
	Keys []CryptoKey
}

func FromProtoKeySet(p *pb.CryptoKeySet) CryptoKeySet {
	if p == nil {
		return CryptoKeySet{}
	}

	out := CryptoKeySet{
		Keys: make([]CryptoKey, len(p.Keys)),
	}

	for i, k := range p.Keys {
		out.Keys[i] = FromProtoKey(k)
	}

	return out
}

func ToProtoKeySet(t *CryptoKeySet) *pb.CryptoKeySet {
	if t == nil {
		return &pb.CryptoKeySet{}
	}

	out := &pb.CryptoKeySet{
		Keys: make([]*pb.CryptoKey, len(t.Keys)),
	}

	for i, k := range t.Keys {
		out.Keys[i] = ToProtoKey(k)
	}

	return out
}
