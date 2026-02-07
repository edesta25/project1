package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)


var Now = func() time.Time { return time.Now().UTC() }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Service) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	b, err := s.BuildJWKS()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to build jwks"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Service) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	now := Now()
	useExpired := r.URL.Query().Has("expired")

	var key *KeyPair
	if useExpired {
		key = s.ExpiredKey
	} else {
		key = s.ActiveKey
	}

	
	exp := key.Expires
	if !useExpired {
		candidate := now.Add(15 * time.Minute)
		if candidate.Before(key.Expires) {
			exp = candidate
		}
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID

	signed, err := token.SignedString(key.Priv)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token": signed,
		"kid":   key.KID,
	})
}
