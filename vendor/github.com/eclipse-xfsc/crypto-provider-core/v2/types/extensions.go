package types

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func (key CryptoKey) GetPem() (p *pem.Block, err error) {
	if !strings.Contains(string(key.KeyType), "aes") {

		block, _ := pem.Decode(key.Key)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}

		return block, nil

	}
	return nil, errors.New("Unsupported")
}

func (key CryptoKey) GetJwk() ([]jwk.Key, error) {
	var pemData = key.Key
	block, rest := pem.Decode(pemData)

	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	var err error
	var j jwk.Key

	if len(rest) > 0 {
		// Parse cert chain
		j, err = jwk.ParseKey(pemData, jwk.WithPEM(true))
		if err != nil {
			return nil, err
		}

		var certs []*x509.Certificate
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, crt)

		for {
			var b *pem.Block
			b, pemData = pem.Decode(pemData)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			crt, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, crt)
		}

		// x5c chain
		chain := []string{}
		for _, c := range certs {
			chain = append(chain, base64.StdEncoding.EncodeToString(c.Raw))
		}
		j.Set("x5c", chain)

	} else {
		// Plain RSA/ECDSA/Ed25519 pubkey
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		j, err = jwk.FromRaw(pubKey)
		if err != nil {
			return nil, err
		}
	}

	// kid setzen
	if err := j.Set("kid", key.Identifier.KeyId); err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------
	// 🔧 kty setzen (lestrrat tut das häufig automatisch — wir erzwingen es)
	// -----------------------------------------------------------------
	switch j.KeyType() {
	case jwa.RSA:
		j.Set("kty", "RSA")
	case jwa.EC:
		j.Set("kty", "EC")
	case jwa.OKP:
		j.Set("kty", "OKP")
	default:
		j.Set("kty", "oct")
	}

	// -----------------------------------------------------------------
	// 🔐 Algorithmusabhängige Ausgabe
	// -----------------------------------------------------------------

	switch key.KeyType {

	// RSA → zwei Varianten erzeugen
	case Rsa2048:
		return cloneWithAlgs(j, "RS256", "PS256")
	case Rsa3072:
		return cloneWithAlgs(j, "RS384", "PS384")
	case Rsa4096:
		return cloneWithAlgs(j, "RS512", "PS512")

	// EC
	case Ecdsap256:
		j.Set("alg", "ES256")
		return []jwk.Key{j}, nil
	case Ecdsap384:
		j.Set("alg", "ES384")
		return []jwk.Key{j}, nil
	case Ecdsap512:
		j.Set("alg", "ES512")
		return []jwk.Key{j}, nil

	// Ed25519
	case Ed25519:
		j.Set("alg", "EdDSA")
		return []jwk.Key{j}, nil

	// AES
	case Aes256GCM:
		j.Set("alg", "A256GCM")
		return []jwk.Key{j}, nil

	case KeyValue:
		return []jwk.Key{j}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.KeyType)
	}
}

func cloneWithAlgs(base jwk.Key, algRS, algPS string) ([]jwk.Key, error) {
	// Clone RSA JWK for RSxxx
	jRS, err := base.Clone()
	if err != nil {
		return nil, err
	}
	if err := jRS.Set("alg", algRS); err != nil {
		return nil, err
	}

	// Clone RSA JWK for PSxxx
	jPS, err := base.Clone()
	if err != nil {
		return nil, err
	}
	if err := jPS.Set("alg", algPS); err != nil {
		return nil, err
	}

	return []jwk.Key{jRS, jPS}, nil
}
