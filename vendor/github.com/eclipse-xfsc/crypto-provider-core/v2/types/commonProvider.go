package types

type CryptoLogger interface {
	Log(level CryptoLogLevel, msg string, err error)
}

type CryptoContextError struct {
	Err error
}

func (e *CryptoContextError) Error() string {
	return e.Err.Error()
}

/*
Crypto Provider Interface Behavior:

1. Crypto Context must be created before use of any function. Funcs must return CryptoContext Error, when Context not initialized.
2. Crypto Context should be destroyed when Context is not more required.
*/
type CryptoProvider interface {
	/*
		Crypto Context Creation Methods. Create the context before any other method.
	*/
	CreateCryptoContext(context CryptoContext) error
	DestroyCryptoContext(context CryptoContext) error
	IsCryptoContextExisting(context CryptoContext) (bool, error)

	/*
		Methods which are just working with created Crypto Context. Ensure that the existing context is checked before execute operations.
	*/
	GetNamespaces(context CryptoContext) ([]string, error)
	GenerateRandom(context CryptoContext, number int) ([]byte, error)
	Hash(parameter CryptoHashParameter, msg []byte) ([]byte, error)
	Encrypt(parameter CryptoIdentifier, data []byte) ([]byte, error)
	Decrypt(parameter CryptoIdentifier, data []byte) ([]byte, error)
	Sign(parameter CryptoIdentifier, data []byte) ([]byte, error)
	GetKeys(parameter CryptoFilter) (*CryptoKeySet, error)
	GetKey(parameter CryptoIdentifier) (*CryptoKey, error)
	Verify(parameter CryptoIdentifier, data []byte, signature []byte) (bool, error)
	GenerateKey(parameter CryptoKeyParameter) error
	IsKeyExisting(parameter CryptoIdentifier) (bool, error)
	DeleteKey(parameter CryptoIdentifier) error
	RotateKey(parameter CryptoIdentifier) error
	GetSupportedKeysAlgs() []KeyType
	GetSupportedHashAlgs() []HashAlgorithm
}
