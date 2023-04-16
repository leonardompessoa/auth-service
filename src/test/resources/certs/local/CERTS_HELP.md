# Self Signed Certificates Quickstart

### Create Root CA certificate and Key
> openssl req -x509 -sha256 -days 3560 -newkey rsa:4096 -subj "/CN=leop.com/C=PL/L=Katowice" -passout pass:changeit  -keyout rootCA.key -out rootCA.crt

### Create CSR and Private Key for server
> openssl req -new -newkey rsa:4096 -subj "/CN=localhost/C=PL/L=Katowice"  -passout pass:changeit -keyout localhost.key -out localhost.csr

### Create localhost.ext
> echo -ne "authorityKeyIdentifier=keyid,issuer\nbasicConstraints=CA:FALSE\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = localhost" > localhost.ext

### Create Server certificate and Self Sign
> openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -passin pass:changeit -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext

### Create PKCS12 archive for keystore
> openssl pkcs12 -export -out localhost.p12 -name "localhost" -passin pass:changeit -passout pass:changeit  -inkey localhost.key -in localhost.crt

### Create truststore with RootCA
> keytool -import -trustcacerts -noprompt -alias rootCA -file rootCA.crt -keystore truststore.p12 -keypass changeit -storepass changeit

### Create rsa key pair
> openssl genrsa -out keypair.pem 2048

### Extract public key
> openssl rsa -in keypair.pem -pubout -out public.pem

### Create private key in PKCS#8 format
> openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem