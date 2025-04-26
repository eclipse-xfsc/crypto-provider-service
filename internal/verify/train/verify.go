package train

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"gitlab.eclipse.org/eclipse/xfsc/train/trusted-content-resolver/clients/go/tcr"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
)

const (
	trustSchemesKey = "trustScheme"
	termsOfUseKey   = "termsOfUse"
	idKey           = "id"
)

type Verifier struct {
	client       *tcr.APIClient
	trustSchemes []string
}

func New(httpClient *http.Client, addr string, schemes []string) (*Verifier, error) {
	if addr == "" {
		return nil, errors.New(errors.Internal, "train server address cannot be empty")
	}

	client := trainClient(httpClient, addr)

	return &Verifier{
		client:       client,
		trustSchemes: schemes,
	}, nil
}

func (v *Verifier) VerifyCredential(ctx context.Context, vc *verifiable.Credential) error {
	if len(vc.TermsOfUse) == 0 {
		return errors.New(errors.BadRequest, "terms of use cannot be empty")
	}

	ss, ok := vc.TermsOfUse[0].CustomFields[trustSchemesKey].([]interface{})
	if !ok {
		return errors.New(errors.BadRequest, "invalid terms of use: trustScheme field is expected to be an array")
	}

	if len(ss) == 0 {
		return errors.New(errors.BadRequest, "invalid terms of use: trustScheme field cannot be empty")
	}

	err := v.verify(ctx, vc.TermsOfUse[0].ID, ss)
	if err != nil {
		return err
	}

	return nil
}

func (v *Verifier) VerifyPresentation(ctx context.Context, vp *verifiable.Presentation) error {
	terms, ok := vp.CustomFields[termsOfUseKey].([]interface{})
	if !ok {
		return errors.New(errors.BadRequest, "terms of use must be an array")
	}

	if len(terms) == 0 {
		return errors.New(errors.BadRequest, "terms of use cannot be empty")
	}

	m, ok := terms[0].(map[string]interface{})
	if !ok {
		return errors.New(errors.BadRequest, "invalid terms of use: must contain an array of map[string]interface{}")
	}

	issuer, ok := m[idKey].(string)
	if !ok {
		return errors.New(errors.BadRequest, "invalid terms of use: missing id key")
	}

	ss, ok := m[trustSchemesKey].([]interface{})
	if !ok {
		return errors.New(errors.BadRequest, "invalid terms of use: trustScheme field is expected to be an array")
	}
	if len(ss) == 0 {
		return errors.New(errors.BadRequest, "invalid terms of use: trustScheme field cannot be empty")
	}

	err := v.verify(ctx, issuer, ss)
	if err != nil {
		return err
	}

	return nil
}

// verify verifies the terms of use against the TRAIN service.
func (v *Verifier) verify(ctx context.Context, issuer string, ss []interface{}) error {
	var schemes []string
	for _, scheme := range ss {
		scheme := scheme.(string)
		if !contains(v.trustSchemes, scheme) {
			return errors.New(errors.BadRequest, fmt.Sprintf("invalid terms of use: unsupported trust scheme %s", scheme))
		}
		schemes = append(schemes, scheme)
	}

	resolveRequest := *tcr.NewResolveRequest(issuer, schemes)

	resp, r, err := v.client.TrustedContentResolverAPI.ResolveTrustList(ctx).ResolveRequest(resolveRequest).Execute()
	if err != nil {
		return errors.New(errors.Internal, err)
	}

	if r.StatusCode != http.StatusOK {
		return errors.New(errors.GetKind(r.StatusCode), getErrorBody(r))
	}

	if err = v.validate(resp); err != nil {
		return err
	}

	return nil
}

func (v *Verifier) validate(resp *tcr.ResolveResponse) error {
	if len(resp.ResolvedResults) == 0 {
		return errors.New("train validation failed: resolved result cannot be empty")
	}

	for _, r := range resp.ResolvedResults {
		if !r.ResolvedDoc.DidVerified {
			return errors.New("train validation failed: did is not verified")
		}
		if len(r.ResolvedDoc.Endpoints) == 0 {
			return errors.New("train validation failed: resolved endpoints cannot be empty")
		}
		for _, e := range r.ResolvedDoc.Endpoints {
			if !e.VcVerified {
				return errors.New("train validation failed: endpoint VC is not verified")
			}
		}
	}

	return nil
}

// trainClient creates and returns a new tcr.APIClient using the provided httpClient and address.
func trainClient(httpClient *http.Client, addr string) *tcr.APIClient {
	cfg := &tcr.Configuration{
		DefaultHeader: map[string]string{
			"Accept":       "application/json",
			"Content-Type": "application/json",
		},
		Servers: tcr.ServerConfigurations{
			{
				URL: addr,
			},
		},
		HTTPClient: httpClient,
	}

	return tcr.NewAPIClient(cfg)
}

// contains checks if a string slice contains a specific string.
func contains(ss []string, s string) bool {
	for _, a := range ss {
		if a == s {
			return true
		}
	}
	return false
}

// getErrorBody retrieves the body of the HTTP response and returns it as a string.
func getErrorBody(resp *http.Response) string {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return ""
	}
	return string(body)
}
