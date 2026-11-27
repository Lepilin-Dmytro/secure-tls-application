#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs

# Generate Certificate Authority
openssl genrsa -out certs/ca.key 4096

openssl req -x509 -new -nodes \
    -key certs/ca.key \
    -sha256 \
    -days 3650 \
    -subj "/CN=SecureTLS-Root-CA" \
    -out certs/ca.crt

# Generate server private key
openssl genrsa -out certs/server.key 2048

# Generate server certificate request
openssl req -new \
    -key certs/server.key \
    -subj "/CN=localhost" \
    -out certs/server.csr

# Create server certificate signed by CA
openssl x509 -req \
    -in certs/server.csr \
    -CA certs/ca.crt \
    -CAkey certs/ca.key \
    -CAcreateserial \
    -out certs/server.crt \
    -days 825 \
    -sha256 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Remove temporary certificate request
rm certs/server.csr

echo "TLS certificates successfully generated."
