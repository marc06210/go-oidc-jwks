package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
)

type PublicKeysData struct {
	Keys []KeyData `json:"keys"`
}

type KeyData struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type WellKnownData struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri,omitempty"`
}

var (
	issuer     string
	port       = "8080"
	pubKeyPath = "public_key_mgu.pub"
	verifyKey  *rsa.PublicKey
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	issuer = fmt.Sprintf("http://localhost:%s", port)
	// signBytes, err := ioutil.ReadFile(privKeyPath)
	// log.Fatal(err)

	// signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	// log.Fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
}

func serveRoot(response http.ResponseWriter, request *http.Request) {
	log.Printf("[HTTP] / requested")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte("ok"))
}

// func serveFavIcon(response http.ResponseWriter) {
// 	log.Printf("[HTTP] favicon requested")
// 	fileBytes, err := ioutil.ReadFile("openid-connect-oauth-logo.png")
// 	if err != nil {
// 		panic(err)
// 	}
// 	response.WriteHeader(http.StatusOK)
// 	response.Header().Set("Content-Type", "application/octet-stream")
// 	_, _ = response.Write(fileBytes)
// }

func serveJWKs(response http.ResponseWriter, request *http.Request) {
	log.Printf("[HTTP] jwks requested")
	n := base64.URLEncoding.EncodeToString((*verifyKey.N).Bytes())
	e := base64.StdEncoding.EncodeToString(big.NewInt(int64(verifyKey.E)).Bytes())
	keys := PublicKeysData{
		Keys: []KeyData{KeyData{"RSA", "go-ext-authz", "sig", n, e}},
	}

	response.WriteHeader(http.StatusOK)

	b, _ := json.Marshal(keys)
	_, _ = response.Write([]byte(b))
}

func serveOIDC(response http.ResponseWriter, request *http.Request) {
	log.Printf("[HTTP] jwks requested")
	wkd := WellKnownData{issuer, issuer + "/.well-known/jwks.json"}
	b, _ := json.Marshal(wkd)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
	response.Header().Set("Expires", "0")
	response.Header().Set("Pragma", "no-cache")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte(b))
}

func main() {
	log.Printf("done")
	http.HandleFunc("/", serveRoot)
	http.HandleFunc("/.well-known/openid-configuration", serveOIDC)
	http.HandleFunc("/.well-known/jwks.json", serveJWKs)

	http.ListenAndServe(":8080", nil)
}
