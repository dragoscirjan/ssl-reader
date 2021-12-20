#! /bin/bash

rm -rf ./test/data
mkdir -p ./test/data

# root

openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -passout pass:test -keyout ./test/data/root.key \
-out ./test/data/root.crt -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

# leaf

openssl req -newkey rsa:2048 -passout pass:test -keyout ./test/data/leaf.key \
-out ./test/data/leaf.csr -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

openssl x509 -signkey ./test/data/leaf.key -passin pass:test -in ./test/data/leaf.csr -req -days 365 -out ./test/data/leaf.crt

# sign

cat > ./test/data/leaf.ext <<DATA
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = ./test/data/leaf
DATA

openssl x509 -req -CA ./test/data/root.crt -passin pass:test -CAkey ./test/data/root.key -in ./test/data/leaf.csr \
-out ./test/data/leaf.crt -days 365 -CAcreateserial -extfile ./test/data/leaf.ext

# chain

cat ./test/data/leaf.crt >> ./test/data/chain.crt
cat ./test/data/root.crt >> ./test/data/chain.crt

node ./src/index.js --file ./test/data/leaf.crt --file ./test/data/leaf.key
node ./src/index.js --file ./test/data/chain.crt --file ./test/data/leaf.key

openssl x509 -outform der -in ./test/data/leaf.crt -out ./test/data/leaf.der

node ./src/index.js --file ./test/data/leaf.der --file ./test/data/leaf.key

# openssl crl2pkcs7 -nocrl -certfile ./test/data/leaf.cer -out ./test/data/leaf.p7b -certfile ./test/data/root.crt

# node ./src/index.js --file ./test/data/leaf.p7b --file ./test/data/leaf.key

openssl pkcs12 -passin pass:test -inkey ./test/data/leaf.key -in ./test/data/leaf.crt -certfile ./test/data/root.crt -export -passout pass:test -out ./test/data/leaf.pfx

node ./src/index.js --file ./test/data/leaf.pfx
