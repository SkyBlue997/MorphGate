#!/usr/bin/env bash
# Regenerates the TLS test fixtures of edge/tests/tls.rs (test use only; the
# private keys here protect nothing). Loopback names only.
#
#   server-ca.pem              CA that signs edge.pem (the tests' client trusts it)
#   edge.pem / edge.key        server certificate for edge.test, localhost, 127.0.0.1
#   client-ca.pem              the "owner AOP" CA an origin_mtls listener trusts
#   client.pem / client.key    client certificate signed by client-ca
#   rogue-chain.pem / rogue.key  client certificate from an untrusted CA, sent with
#                              its intermediate (two certificates on the chain)
set -euo pipefail
cd "$(dirname "$0")"
days=36500
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ca() { # ca NAME CN
  key "$tmp/$1.key"
  openssl req -x509 -new -key "$tmp/$1.key" -subj "/CN=$2" -days "$days" -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$tmp/$1.pem"
}
sign() { # sign NAME CN ISSUER EXT
  key "$tmp/$1.key"
  openssl req -new -key "$tmp/$1.key" -subj "/CN=$2" -out "$tmp/$1.csr"
  printf '%s\n' "$4" >"$tmp/$1.ext"
  openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$3.pem" -CAkey "$tmp/$3.key" -CAcreateserial \
    -days "$days" -sha256 -extfile "$tmp/$1.ext" -out "$tmp/$1.pem" 2>/dev/null
}

ca server-ca "MorphGate test server CA"
sign edge edge.test server-ca "subjectAltName=DNS:edge.test,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE"
ca client-ca "MorphGate test AOP client CA"
sign client "MorphGate test AOP client" client-ca "extendedKeyUsage=clientAuth
basicConstraints=critical,CA:FALSE"
ca rogue-ca "Untrusted test CA"
sign rogue-int "Untrusted test intermediate" rogue-ca "basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign"
sign rogue "Untrusted test client" rogue-int "extendedKeyUsage=clientAuth
basicConstraints=critical,CA:FALSE"

cp "$tmp/server-ca.pem" "$tmp/client-ca.pem" .
cp "$tmp/edge.pem" "$tmp/edge.key" "$tmp/client.pem" "$tmp/client.key" "$tmp/rogue.key" .
cat "$tmp/rogue.pem" "$tmp/rogue-int.pem" >rogue-chain.pem
chmod 0644 ./*.pem ./*.key
