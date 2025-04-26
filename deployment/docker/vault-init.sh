#curl --header "X-Vault-Token: test" --request POST --data '{"type":"kv","options":{"version":"2"}}' localhost:8200/v1/sys/mounts/kv

curl --header "X-Vault-Token: test" --request POST --data '{"type":"transit"}' vault:8200/v1/sys/mounts/transit
curl --header "X-Vault-Token: test" --request POST --data '{"type":"ecdsa-p256"}' vault:8200/v1/transit/keys/eckey
curl --header "X-Vault-Token: test" --request POST --data '{"type":"ed25519"}' vault:8200/v1/transit/keys/edkey

PEM_CONTENT=$(cat /usr/local/bin/test.pem)

curl --header "X-Vault-Token: test" --request POST --data "{\"data\": {\"pem\": \"$(echo "$PEM_CONTENT" | awk '{printf "%s\\n", $0}')\"}}" \
 vault:8200/v1/secret/data/trustanchor
