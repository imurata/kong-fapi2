#!/usr/bin/env bash
# Regenerate the local CA and the Keycloak server / Kong RP client certs
# used in 検証 3 (Kong = RP × mTLS). Run from the tls/ directory.
#
# Output files (committed to git as PoC fixtures):
#   ca-cert.pem / ca-key.pem               - local CA
#   keycloak-cert.pem / keycloak-key.pem   - Keycloak HTTPS server cert
#   kong-rp-mtls-cert.pem / .._key.pem     - Kong RP client cert
#   keycloak-truststore.p12                - PKCS12 truststore with CA
#                                            (Keycloak validates Kong's
#                                            client cert with this)
#
# After regenerating, you must also update:
#   - keycloak/realm-import/fapi2-realm.json
#       kong-rp-mtls-client.attributes."x509.subjectdn.regexp"
#       (if the client subject DN changes)
#
set -euo pipefail
cd "$(dirname "$0")"

# 1. CA
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca-key.pem
openssl req -x509 -new -nodes -key ca-key.pem -days 3650 \
  -out ca-cert.pem -subj "/CN=Kong FAPI2 PoC CA"

# 2. Keycloak server cert (SAN for keycloak.localhost / keycloak / localhost)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keycloak-key.pem
openssl req -new -key keycloak-key.pem -out keycloak.csr -config server.cnf
openssl x509 -req -in keycloak.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -days 825 -out keycloak-cert.pem \
  -extfile server.cnf -extensions ext

# 3. Kong RP client cert
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kong-rp-mtls-key.pem
openssl req -new -key kong-rp-mtls-key.pem -out kong-rp-mtls.csr -config client.cnf
openssl x509 -req -in kong-rp-mtls.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -days 825 -out kong-rp-mtls-cert.pem \
  -extfile client.cnf -extensions ext

# 4. PKCS12 truststore for Keycloak (just the CA cert)
openssl pkcs12 -export -nokeys -in ca-cert.pem \
  -out keycloak-truststore.p12 -passout pass:changeit

# Cleanup intermediates
rm -f keycloak.csr kong-rp-mtls.csr ca-cert.srl

echo "Done. Subject of Kong client cert:"
openssl x509 -in kong-rp-mtls-cert.pem -subject -noout
echo "SHA-256 fingerprint of Kong client cert:"
openssl x509 -in kong-rp-mtls-cert.pem -fingerprint -sha256 -noout
