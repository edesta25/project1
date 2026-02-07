package main

import (
	"log"
	"net/http"
	"time"
)

type Service struct {
	ActiveKey  *KeyPair
	ExpiredKey *KeyPair
}

func NewService() (*Service, error) {
	active, err := GenerateRSAKeyPair(2048, time.Now().Add(24*time.Hour))
	if err != nil {
		return nil, err
	}

	expired, err := GenerateRSAKeyPair(2048, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}

	return &Service{
		ActiveKey:  active,
		ExpiredKey: expired,
	}, nil
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}
