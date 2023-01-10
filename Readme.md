# Purpose

This sample shows how to expose public keys in a OIDC way. It means we will expose two endpoints **/.well-known/openid-configuration** and **/.well-known/jwks.json**

# Generation of the private and public keys

Only the public key is required by the program, but It is based on a private kye. So here are the two magic commands to create them
**openssl genrsa -out private_key_mgu.pem 2048** and **openssl rsa -in private_key_mgu.pem -pubout -out public_key_mgu.pub**. You can verify it is valid by running
**openssl rsa -noout -text -inform PEM -in public_key_mgu.pub -pubin**

# Run

Run the app, **go run \*.go**. The server is listening on port 8080. So the two URLs are:

- http://localhost:8080/.well-known/openid-configuration
- http://localhost:8080/.well-known/jwks.json
