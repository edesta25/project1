package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"
)

type KeyPair struct {
	KID     string
	Expires time.Time
	Priv    *rsa.PrivateKey
	Pub     *rsa.PublicKey
}

func GenerateRSAKeyPair(bits int, expires time.Time) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	kidBytes := make([]byte, 16)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}

	return &KeyPair{
		KID:     hex.EncodeToString(kidBytes),
		Expires: expires,
		Priv:    priv,
		Pub:     &priv.PublicKey,
	}, nil
}

func (k *KeyPair) IsExpired(now time.Time) bool {
	return !k.Expires.After(now)
}
