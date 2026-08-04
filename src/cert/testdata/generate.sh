#!/bin/bash
# Regenerates the certificate fixtures in this directory.
#
# Private keys are generated into keys/ and deleted at the end: committing one
# would trip the pem-private-key gitleaks rule, and nothing here needs to sign
# at test time.
#
# Validity is 100 years so the fixtures never expire out from under the tests.
# Tests that care about expiry pass an explicit timestamp instead.

set -euo pipefail
cd "$(dirname "$0")"

KEYS=keys
mkdir -p "$KEYS"
trap 'rm -rf "$KEYS"' EXIT

DAYS=36500
EC="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc"

# Every leaf carries digitalSignature + keyEncipherment + a SAN. That is the
# exact shape the removed heuristic read as "Server", so eku-none.pem is the
# fixture proving an absent EKU is no longer inferred.
LEAF_KU="keyUsage=digitalSignature,keyEncipherment"

selfsigned() {
	local name=$1 eku=$2
	local args=(-x509 $EC -keyout "$KEYS/$name.key" -out "$name.pem"
		-days $DAYS -subj "/C=CA/O=Example Org/CN=$name"
		-addext "$LEAF_KU" -addext "subjectAltName=DNS:$name.example.test")
	[ -n "$eku" ] && args+=(-addext "extendedKeyUsage=$eku")
	openssl req "${args[@]}" 2>/dev/null
}

# --- EKU variants: self-signed, exercise the parser only ---
selfsigned eku-client        clientAuth
selfsigned eku-server        serverAuth
selfsigned eku-client-server clientAuth,serverAuth
selfsigned eku-none          ''
selfsigned eku-unknown       1.3.6.1.4.1.99999.1

# --- A real hierarchy: root -> intermediate -> leaf, for path building ---
ca() {
	local name=$1 cn=$2 pathlen=$3
	openssl req -x509 $EC -keyout "$KEYS/$name.key" -out "$name.pem" \
		-days $DAYS -subj "/C=CA/O=Example Org/CN=$cn" \
		-addext "basicConstraints=critical,CA:TRUE${pathlen}" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

ca ca-root       "Example Root CA"  ""
ca ca-other-root "Unrelated Root CA" ""

# Intermediate: CSR signed by the root.
openssl req -new $EC -keyout "$KEYS/ca-intermediate.key" -out "$KEYS/ca-intermediate.csr" \
	-subj "/C=CA/O=Example Org/CN=Example Intermediate CA" 2>/dev/null
openssl x509 -req -in "$KEYS/ca-intermediate.csr" -days $DAYS \
	-CA ca-root.pem -CAkey "$KEYS/ca-root.key" -out ca-intermediate.pem \
	-extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') 2>/dev/null

# Leaves signed by the intermediate. leaf-noeku exists so verification can
# prove an EKU-less certificate is accepted for any purpose.
leaf() {
	local name=$1 eku=$2
	openssl req -new $EC -keyout "$KEYS/$name.key" -out "$KEYS/$name.csr" \
		-subj "/C=CA/O=Example Org/CN=$name" 2>/dev/null
	local ext="$LEAF_KU"$'\n'"subjectAltName=DNS:$name.example.test"
	[ -n "$eku" ] && ext="$ext"$'\n'"extendedKeyUsage=$eku"
	openssl x509 -req -in "$KEYS/$name.csr" -days $DAYS \
		-CA ca-intermediate.pem -CAkey "$KEYS/ca-intermediate.key" -out "$name.pem" \
		-extfile <(printf '%s\n' "$ext") 2>/dev/null
}

leaf leaf-client clientAuth
leaf leaf-server serverAuth
leaf leaf-noeku  ''

# Chain files, ordered leaf-first as Vault returns them.
cat leaf-client.pem ca-intermediate.pem ca-root.pem >chain-with-root.pem
cat leaf-client.pem ca-intermediate.pem >chain-no-root.pem

echo "regenerated $(ls ./*.pem | wc -l) fixtures"
