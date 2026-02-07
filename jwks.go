package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"` // "RSA"
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // "RS256"
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func rsaPublicKeyToJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (s *Service) BuildJWKS() ([]byte, error) {
	now := Now()

	keys := make([]JWK, 0, 1)
	if !s.ActiveKey.IsExpired(now) {
		keys = append(keys, rsaPublicKeyToJWK(s.ActiveKey.KID, s.ActiveKey.Pub))
	}
	// IMPORTANT: do NOT include expired keys in JWKS response
	// per assignment requirement: "Only serve keys that have not expired."

	jwks := JWKS{Keys: keys}
	return json.Marshal(jwks)
}
