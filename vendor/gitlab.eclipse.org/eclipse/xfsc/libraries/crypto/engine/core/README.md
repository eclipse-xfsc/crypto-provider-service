# Crypto Core

## Introduction

This package is a library to abstract crypto providers for go. The providers can be loaded during startup by adding the respective module in the local folder.

## Usage

Implement/Choose an Plugin which implements the commonProvider Interface and put it in the docker container in an folder which is identified by the environment variable CRYPTO_CORE_MODULE_PATH next to your application (e.g. in Docker File)

## Compilation of Modules

Compilation

```
go build -buildmode=plugin
```

Plugin

```
func GetCryptoProvider() CryptoProvider {
    return provider
}

var Plugin CryptoProviderModule //export Plugin Symbol, dont change this name:) 
```
