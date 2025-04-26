# JWT

## Introduction

This library contains common JWT extensions for usage in SSI context. 

## Self Signed Token

To create a self signed token use the following: 

```
headers := jws.NewHeaders()
headers.Set("jwk", pubkey)
signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, privkey, jws.WithProtectedHeaders(headers)))

```

To verify the Self signed token use: 

```
token, err := self.ParseSelfSigned(string(signed))
```

Options can be appended by using: 

```
options = append(options, ljwt.WithAudience("http://test"))
token, err := self.ParseSelfSigned(string(signed),options)
```

## Use of multiple JWKS/DID Key Verifications

The library extends the standard JWKS fetching by adding support for multiple sources (multiple Authorization Servers). The sources can be DIDs or JWKS Urls.

DID Usage: 

```
didFetcher := new(fetcher.DidFetcher)
err = didFetcher.Initialize([]string{"did:web:12345"}, time.Second)

if err != nil {
		t.Error()
}

jwt.RegisterFetcher("DID1", didFetcher)
```

or 

JWKS Usage:

```
jwksFetcher := new(fetcher.JwksFetcher)
jwksFetcher.Initialize([]string{jwks.URL}, time.Second)

jwt.RegisterFetcher("JWKS1", jwksFetcher)
```

within the API:

```
tok, err := jwt.ParseRequest(r)
```

Sources will be cached and updated automatically.

## Use of External Crypto Provider

To sign tokens with external providers the signing interceptor can be enabled/disabled by using: 

```
EnableCryptoProvider("yournamespace", provider)
DisableCryptoProvider()
```

After this, a normal signing and verify action can be used, with the only difference that the "key" in "WithKey" function must carry the keyID of the key in the cryptoprovider namespace. The cryptoprovider will intercept all signing/verify calls and redirect it to the external provider.

```
signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, "tenant_space:testK"))
```

Note: the namespace is the first part of the key followed by ":" and the key name. Means for namespace and group namespace/test:key1
