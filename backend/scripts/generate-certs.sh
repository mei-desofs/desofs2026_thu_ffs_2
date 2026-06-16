#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# 1. Generate Internal CA
openssl req -new -x509 -days 3650 -nodes -text -out ca.crt \
  -keyout ca.key -subj "/CN=KryptosInternalCA"

# 2. Generate Server Certificate for Postgres
openssl req -new -nodes -text -out server.csr \
  -keyout server.key -subj "/CN=db"
openssl x509 -req -in server.csr -text -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 3. Generate Client Certificate for Spring Boot
# Common Name (CN) must match the database user (kryptos)
openssl req -new -nodes -text -out client.csr \
  -keyout client.key -subj "/CN=kryptos"
openssl x509 -req -in client.csr -text -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# 4. Convert Client Key to PKCS#8 (required by PostgreSQL JDBC Driver)
openssl pkcs8 -topk8 -inform PEM -outform DER -in client.key -out client.pk8 -nocrypt

# Set permissions for Postgres
chmod 0600 server.key client.key client.pk8
