#! /bin/bash
set -ex

rm -rf ./test/data
mkdir -p ./test/data

# for pass in "thepassword" ""; do
for pass in "thepassword"; do
    # for pass in ""; do

    pass_out=(-nodes)
    pass_in=()
    suffix=""
    if [ "$pass" != "" ]; then
        pass_out=(-passout pass:$pass)
        pass_in=(-passin pass:$pass)
        suffix="_$pass"
    fi

    # root

    openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 "${pass_out[@]}" -keyout ./test/data/root$suffix.key \
    -out ./test/data/root$suffix.crt -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

    # leaf

    openssl req -newkey rsa:2048 "${pass_out[@]}" -keyout ./test/data/leaf$suffix.key \
    -out ./test/data/leaf$suffix.csr -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

    openssl x509 -signkey ./test/data/leaf$suffix.key "${pass_in[@]}" -in ./test/data/leaf$suffix.csr -req -days 365 -out ./test/data/leaf$suffix.crt

    # sign

    cat > ./test/data/leaf$suffix.ext <<DATA
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = ./test/data/leaf
DATA

    openssl x509 -req -CA ./test/data/root$suffix.crt "${pass_in[@]}" -CAkey ./test/data/root$suffix.key -in ./test/data/leaf$suffix.csr \
    -out ./test/data/leaf$suffix.crt -days 365 -CAcreateserial -extfile ./test/data/leaf$suffix.ext

    # chain

    cat ./test/data/leaf$suffix.crt >> ./test/data/chain$suffix.crt
    cat ./test/data/root$suffix.crt >> ./test/data/chain$suffix.crt

    node ./src/index.js --file ./test/data/leaf$suffix.crt --file ./test/data/leaf$suffix.key
    # node ./src/index.js --file ./test/data/chain$suffix.crt --file ./test/data/leaf$suffix.key

    # # DER

    # openssl x509 -outform der -in ./test/data/leaf$suffix.crt -out ./test/data/leaf$suffix.der

    # node ./src/index.js --file ./test/data/leaf$suffix.der --file ./test/data/leaf$suffix.key

    # # # PKCS#7

    # # openssl crl2pkcs7 -nocrl -certfile ./test/data/leaf.cer -out ./test/data/leaf.p7b -certfile ./test/data/root$suffix.crt

    # # node ./src/index.js --file ./test/data/leaf.p7b --file ./test/data/leaf$suffix.key

    # # PKCS#12

    # openssl pkcs12 "${pass_in[@]}" -inkey ./test/data/leaf$suffix.key -in ./test/data/leaf$suffix.crt -certfile ./test/data/root$suffix.crt -export "${pass_out[@]}" -out ./test/data/leaf$suffix.pfx

    # node ./src/index.js --file ./test/data/leaf$suffix.pfx
done
