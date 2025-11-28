package helper

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

type ContentType string

const (
	ApplicationJson    ContentType = "application/json"
	ApplicationUrlForm ContentType = "application/x-www-form-urlencoded"
)

func DisableTlsVerification() {
	tr := http.DefaultTransport.(*http.Transport)
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.InsecureSkipVerify = true
}

func Get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("can not make get request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can not read body of response with status %s: %w ", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get request failed! "+
			"response code: %d status: %s data: %s", resp.StatusCode, resp.Status, string(respBody))
	}

	return respBody, nil
}

func Post(url string, body []byte, contentType ContentType, token *string) ([]byte, error) {
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("can not build request: %w", err)
	}

	// Set the Content-Type header to application/json
	request.Header.Set("Content-Type", string(contentType))

	if token != nil {
		request.Header.Set("Authorization", "Bearer "+*token)
	}

	// Send the HTTP request
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("can not send request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can not read body of response with status %s: %w ", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post request failed! "+
			"response code: %d status: %s data: %s", resp.StatusCode, resp.Status, string(respBody))
	}

	return respBody, nil
}
