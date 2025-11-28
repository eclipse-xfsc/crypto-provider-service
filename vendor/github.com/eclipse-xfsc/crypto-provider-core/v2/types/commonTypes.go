package types

import (
	"slices"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type HashAlgorithm string
type KeyType string
type CryptoLogLevel string

const (
	Sha2224 HashAlgorithm = "sha2-224"
	Sha2256 HashAlgorithm = "sha2-256"
	Sha2384 HashAlgorithm = "sha2-384"
	Sha2512 HashAlgorithm = "sha2-512"
	Sha3224 HashAlgorithm = "sha3-224"
	Sha3256 HashAlgorithm = "sha3-256"
	Sha3384 HashAlgorithm = "sha3-384"
	Sha3512 HashAlgorithm = "sha3-512"
)

func ValidateHashFunction(HashAlgorithm HashAlgorithm) bool {
	return slices.Contains[[]string, string]([]string{"sha2-224", "sha2-256", "sha2-384", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}, string(HashAlgorithm))
}

const (
	Aes256GCM KeyType = "aes256-gcm96"
	Ed25519   KeyType = "ed25519"
	Ecdsap256 KeyType = "ecdsa-p256"
	Ecdsap384 KeyType = "ecdsa-p384"
	Ecdsap512 KeyType = "ecdsa-p512"
	Rsa2048   KeyType = "rsa-2048"
	Rsa3072   KeyType = "rsa-3072"
	Rsa4096   KeyType = "rsa-4096"
	KeyValue  KeyType = "keyValue"
)

const (
	DEBUG CryptoLogLevel = "DEBUG"
	INFO  CryptoLogLevel = "INFO"
	FATAL CryptoLogLevel = "FATAL"
	LOG   CryptoLogLevel = "LOG"
)

func ValidateMethod(KeyType KeyType) bool {
	return slices.Contains[[]string, string]([]string{"aes256-gcm96", "ed25519", "ecdsa-p256", "ecdsa-p384", "ecdsa-p512", "rsa-2048", "rsa-3072", "rsa-4096"}, string(KeyType))
}

func ToProtoKeyType(k KeyType) pb.KeyType {
	switch k {
	case Aes256GCM:
		return pb.KeyType_KEY_TYPE_AES256_GCM96
	case Ed25519:
		return pb.KeyType_KEY_TYPE_ED25519
	case Ecdsap256:
		return pb.KeyType_KEY_TYPE_ECDSA_P256
	case Ecdsap384:
		return pb.KeyType_KEY_TYPE_ECDSA_P384
	case Ecdsap512:
		return pb.KeyType_KEY_TYPE_ECDSA_P512
	case Rsa2048:
		return pb.KeyType_KEY_TYPE_RSA_2048
	case Rsa3072:
		return pb.KeyType_KEY_TYPE_RSA_3072
	case Rsa4096:
		return pb.KeyType_KEY_TYPE_RSA_4096
	case KeyValue:
		return pb.KeyType_KEY_TYPE_KEYVALUE

	default:
		return pb.KeyType_KEY_TYPE_UNKNOWN
	}
}

// Proto → Local
func FromProtoKeyType(k pb.KeyType) KeyType {
	switch k {

	case pb.KeyType_KEY_TYPE_AES256_GCM96:
		return Aes256GCM
	case pb.KeyType_KEY_TYPE_ED25519:
		return Ed25519
	case pb.KeyType_KEY_TYPE_ECDSA_P256:
		return Ecdsap256
	case pb.KeyType_KEY_TYPE_ECDSA_P384:
		return Ecdsap384
	case pb.KeyType_KEY_TYPE_ECDSA_P512:
		return Ecdsap512
	case pb.KeyType_KEY_TYPE_RSA_2048:
		return Rsa2048
	case pb.KeyType_KEY_TYPE_RSA_3072:
		return Rsa3072
	case pb.KeyType_KEY_TYPE_RSA_4096:
		return Rsa4096
	case pb.KeyType_KEY_TYPE_KEYVALUE:
		return KeyValue

	default:
		return KeyType("unknown")
	}
}

// Local → Proto
func ToProtoHashAlgorithm(h HashAlgorithm) pb.HashAlgorithm {
	switch h {

	case Sha2224:
		return pb.HashAlgorithm_HASH_SHA2_224
	case Sha2256:
		return pb.HashAlgorithm_HASH_SHA2_256
	case Sha2384:
		return pb.HashAlgorithm_HASH_SHA2_384
	case Sha2512:
		return pb.HashAlgorithm_HASH_SHA2_512

	case Sha3224:
		return pb.HashAlgorithm_HASH_SHA3_224
	case Sha3256:
		return pb.HashAlgorithm_HASH_SHA3_256
	case Sha3384:
		return pb.HashAlgorithm_HASH_SHA3_384
	case Sha3512:
		return pb.HashAlgorithm_HASH_SHA3_512

	default:
		return pb.HashAlgorithm_HASH_UNKNOWN
	}
}

// Proto → Local
func FromProtoHashAlgorithm(h pb.HashAlgorithm) HashAlgorithm {
	switch h {

	case pb.HashAlgorithm_HASH_SHA2_224:
		return Sha2224
	case pb.HashAlgorithm_HASH_SHA2_256:
		return Sha2256
	case pb.HashAlgorithm_HASH_SHA2_384:
		return Sha2384
	case pb.HashAlgorithm_HASH_SHA2_512:
		return Sha2512

	case pb.HashAlgorithm_HASH_SHA3_224:
		return Sha3224
	case pb.HashAlgorithm_HASH_SHA3_256:
		return Sha3256
	case pb.HashAlgorithm_HASH_SHA3_384:
		return Sha3384
	case pb.HashAlgorithm_HASH_SHA3_512:
		return Sha3512

	default:
		return HashAlgorithm("unknown")
	}
}
