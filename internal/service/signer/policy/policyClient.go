package policy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

func GetPolicyResult(input map[string]interface{}, policy string) (map[string]interface{}, error) {
	policyUrl, b := os.LookupEnv(policy)

	if b {
		body, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}

		r, err := http.NewRequest("POST", policyUrl, bytes.NewBuffer(body))
		r.Header.Add("Content-Type", "application/json")
		if err != nil {
			return nil, err
		}

		client := &http.Client{}
		res, err := client.Do(r)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()

		var post map[string]interface{}

		derr := json.NewDecoder(res.Body).Decode(&post)
		if derr != nil {
			panic(derr)
		}

		return post, nil
	} else {
		return nil, nil
	}
}
