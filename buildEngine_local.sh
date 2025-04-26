#!/bin/bash
rm -rf .engines
mkdir .engines
cd .engines
git clone https://gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/plugins/local-provider.git --branch v0.0.6 .local
git clone https://gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/plugins/hashicorp-vault-provider.git --branch v1.2.4 .vault

cd .local
rm localProvider_test.go
go build -buildmode=plugin -gcflags="all=-N"
cd .. 

cd .vault
rm vaultProvider_test.go
go build -buildmode=plugin -gcflags="all=-N"
cd .. 
