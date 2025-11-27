package types

import jwk "github.com/lestrrat-go/jwx/v2/jwk"

type KeyFetcher interface {
	GetKeys() (jwk.Set, error)
	Stop()
}
