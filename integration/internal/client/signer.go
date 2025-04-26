package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/eclipse-xfsc/crypto-provider-service/gen/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/config"
	sign "github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer"
	"github.com/kelseyhightower/envconfig"
	"github.com/piprate/json-gold/ld"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"

	"go.uber.org/zap"
)

var wg sync.WaitGroup

type Signer struct {
	cryptoProvider *types.CryptoProvider
	loader         *ld.CachingDocumentLoader
	cfg            config.Config
}

func NewSigner(cryptoprovider *types.CryptoProvider, loader *ld.CachingDocumentLoader) *Signer {
	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("cannot load configuration: %v", err)
	}

	return &Signer{cryptoProvider: cryptoprovider, loader: loader, cfg: cfg}
}

func (s *Signer) CreateCredentialLDPVCProof(key string, vc []byte) ([]byte, error) {
	var cred map[string]interface{}
	if err := json.Unmarshal(vc, &cred); err != nil {
		return nil, err
	}

	k, err := (*s.cryptoProvider).GetKey(types.CryptoIdentifier{KeyId: key, CryptoContext: types.CryptoContext{
		Namespace: "transit",
		Engine:    "transit",
	}})

	if err != nil {
		return nil, err
	}

	jwk, err := k.GetJwk()

	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(jwk)

	if err != nil {
		return nil, err
	}

	cred["issuer"] = "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)

	payload := map[string]interface{}{
		"namespace":  "transit",
		"group":      "",
		"key":        key,
		"credential": cred,
		"format":     "ldp_vc",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CredentialProofRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CredentialProof(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential/proof", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) VerifyCredentialLDPVcProof(vc []byte) error {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		p := new(signer.VerifyCredentialRequest)

		body, err := io.ReadAll(r.Body)
		p.Credential = body
		p.XFormat = "ldp_vc"
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := svc.VerifyCredential(r.Context(), p)

		if err != nil {
			json.NewEncoder(w).Encode(res)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential/verify", bytes.NewReader(vc))
	if err != nil {
		return err
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newErrorResponse(resp)
	}

	var response struct {
		Valid               bool `json:"valid"`
		DisclosedCredential any  `json:"disclosedCredential"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&response); err != nil {
		return err
	}

	if !response.Valid {
		return fmt.Errorf("invalid credential")
	}

	return nil
}

func (s *Signer) VerifyCredentialSdJwtProof(vc []byte, disclosureFrame []string) error {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		p := new(signer.VerifyCredentialRequest)

		body, err := io.ReadAll(r.Body)
		p.Credential = []byte(strings.Replace(strings.Replace(string(body), `"`, "", -1), "\n", "", -1))
		p.XFormat = "vc+sd-jwt"
		p.DisclosureFrame = disclosureFrame
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := svc.VerifyCredential(r.Context(), p)

		if err != nil {
			json.NewEncoder(w).Encode(res)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential/verify", bytes.NewReader(vc))
	if err != nil {
		return err
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newErrorResponse(resp)
	}

	var response struct {
		Valid               bool `json:"valid"`
		DisclosedCredential any  `json:"disclosedCredential"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&response); err != nil {
		return err
	}

	if !response.Valid {
		return fmt.Errorf("invalid credential")
	}

	return nil
}

func (s *Signer) CreateCredentialSdJwtProof(key string, vc []byte) ([]byte, error) {
	var cred map[string]interface{}
	if err := json.Unmarshal(vc, &cred); err != nil {
		return nil, err
	}

	k, err := (*s.cryptoProvider).GetKey(types.CryptoIdentifier{KeyId: key, CryptoContext: types.CryptoContext{
		Namespace: "transit",
		Engine:    "transit",
	}})

	if err != nil {
		return nil, err
	}

	jwk, err := k.GetJwk()

	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(jwk)

	if err != nil {
		return nil, err
	}

	cred["issuer"] = "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)
	sub := cred["credentialSubject"].(map[string]interface{})
	sub["cnf"] = make(map[string]interface{})
	cnf := sub["cnf"].(map[string]interface{})
	cnf["jwk"] = string(b)

	payload := map[string]interface{}{
		"namespace":       "transit",
		"group":           "",
		"key":             key,
		"credential":      cred,
		"format":          "vc+sd-jwt",
		"signatureType":   "ES256",
		"disclosureFrame": []string{"allow"},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CredentialProofRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CredentialProof(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential/proof", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) CreateCredentialSdJwtPresentation(key, aud, group, sdjwt, nonce string, disclosureFrame []string) ([]byte, error) {

	payload := map[string]interface{}{
		"namespace":      "transit",
		"group":          group,
		"key":            key,
		"presentation":   sdjwt,
		"nonce":          nonce,
		"aud":            aud,
		"discloureFrame": disclosureFrame,
		"format":         "vc+sd-jwt",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.PresentationProofRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.PresentationProof(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/presentation/proof", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) CreatePresentationProof(key string, vp []byte) ([]byte, error) {
	var pres map[string]interface{}
	if err := json.Unmarshal(vp, &pres); err != nil {
		return nil, err
	}

	k, err := (*s.cryptoProvider).GetKey(types.CryptoIdentifier{KeyId: key, CryptoContext: types.CryptoContext{
		Namespace: "transit",
		Engine:    "transit",
	}})

	if err != nil {
		return nil, err
	}

	jwk, err := k.GetJwk()

	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(jwk)

	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"issuer":       "did:jwk:" + base64.RawURLEncoding.EncodeToString(b),
		"namespace":    "transit",
		"key":          key,
		"presentation": pres,
		"format":       "ldp_vc",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.PresentationProofRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.PresentationProof(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/presentation/proof", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) VerifyPresentationProof(vp []byte, aud, nonce *string, disclosureFrame []string, format string) error {

	payload := map[string]interface{}{
		"presentation":    vp,
		"aud":             aud,
		"nonce":           nonce,
		"disclosureFrame": disclosureFrame,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.VerifyPresentationRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		p.XFormat = r.Header.Get("XFormat")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.VerifyPresentation(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/presentation/verify", bytes.NewReader(payloadJSON))
	if err != nil {
		return err
	}

	req.Header.Add("XFormat", format)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newErrorResponse(resp)
	}

	var response struct {
		Valid               bool `json:"valid"`
		DisclosedCredential any  `json:"disclosedCredential"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&response); err != nil {
		return err
	}

	if !response.Valid {
		return fmt.Errorf("invalid presentation")
	}

	return nil
}

func (s *Signer) CreatePresentation(data []byte, issuer, namespace, key, nonce, signaturetype, format string, disclosureFrame []string) ([]byte, error) {

	payload := map[string]interface{}{
		"data":            data,
		"issuer":          issuer,
		"nonce":           nonce,
		"disclosureFrame": disclosureFrame,
		"namespace":       namespace,
		"key":             key,
		"signatureType":   signaturetype,
		"format":          format,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CreatePresentationRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CreatePresentation(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/presentation", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) CreatePresentationPlain(cred []byte) ([]byte, error) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CreatePresentationRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CreatePresentation(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/presentation", bytes.NewReader(cred))
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) CreateCredential(data []byte, issuer, namespace, key, nonce, signaturetype, format string, disclosureFrame, t []string) ([]byte, error) {

	payload := map[string]interface{}{
		"credentialSubject": data,
		"issuer":            issuer,
		"nonce":             nonce,
		"disclosureFrame":   disclosureFrame,
		"namespace":         namespace,
		"key":               key,
		"signatureType":     signaturetype,
		"format":            format,
		"type":              t,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CreateCredentialRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CreateCredential(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential", bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

func (s *Signer) CreateCredentialPlain(cred []byte) ([]byte, error) {

	var c map[string]interface{}

	json.Unmarshal(cred, &c)

	_, ok := c["key"].(string)
	_, ok2 := c["issuer"].(string)
	if ok && ok2 {

		k, err := (*s.cryptoProvider).GetKey(types.CryptoIdentifier{KeyId: string(c["key"].(string)), CryptoContext: types.CryptoContext{
			Namespace: c["namespace"].(string),
			Engine:    "transit",
		}})

		if err != nil {
			return nil, err
		}

		jwk, err := k.GetJwk()

		if err != nil {
			return nil, err
		}

		b, err := json.Marshal(jwk)

		if err != nil {
			return nil, err
		}

		c["issuer"] = "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)
	}
	b2, _ := json.Marshal(c)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		svc := sign.New(*s.cryptoProvider, []sign.Verifier{}, []string{string(types.Ecdsap256)}, s.loader, zap.NewNop(), s.cfg.Nats.Host, s.cfg.Nats.Topic, s.cfg.Nats.StatusTopic, &wg, s.cfg.SdJwt.Url)
		var p *signer.CreateCredentialRequest

		err := json.NewDecoder(r.Body).Decode(&p)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := svc.CreateCredential(r.Context(), p)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/credential", bytes.NewReader(b2))
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrorResponse(resp)
	}

	return io.ReadAll(resp.Body)
}

type errorResponse struct {
	Code     int
	Status   string
	Response string
}

func (e *errorResponse) Error() string {
	return fmt.Sprintf("Status: %s\nResponse: %s", e.Status, e.Response)
}

func newErrorResponse(resp *http.Response) *errorResponse {
	e := &errorResponse{Code: resp.StatusCode, Status: resp.Status}
	msg, err := io.ReadAll(resp.Body)
	if err == nil {
		e.Response = string(msg)
	}
	return e
}
