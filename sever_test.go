package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) (*Service, *http.ServeMux) {
	t.Helper()

	svc, err := NewService()
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", svc.HandleJWKS)
	mux.HandleFunc("/auth", svc.HandleAuth)
	return svc, mux
}

func TestJWKSOnlyServesNonExpiredKeys(t *testing.T) {
	_, mux := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var jwks JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KID == "" {
		t.Fatalf("expected kid present")
	}
	if jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Alg != "RS256" || jwks.Keys[0].Use != "sig" {
		t.Fatalf("unexpected jwk fields: %+v", jwks.Keys[0])
	}
}

func TestAuthIssuesValidJWTWithKid(t *testing.T) {
	svc, mux := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Token string `json:"token"`
		KID   string `json:"kid"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Token == "" || resp.KID == "" {
		t.Fatalf("expected token and kid in response")
	}

	parsed, _, err := new(jwt.Parser).ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid != svc.ActiveKey.KID {
		t.Fatalf("expected kid %s, got %s", svc.ActiveKey.KID, kid)
	}

	_, err = jwt.Parse(resp.Token, func(tk *jwt.Token) (any, error) {
		return svc.ActiveKey.Pub, nil
	})
	if err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestAuthExpiredQuerySignsWithExpiredKeyAndExpiredExp(t *testing.T) {
	svc, mux := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=1", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Token string `json:"token"`
		KID   string `json:"kid"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	parsed, _, err := new(jwt.Parser).ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid != svc.ExpiredKey.KID {
		t.Fatalf("expected expired kid %s, got %s", svc.ExpiredKey.KID, kid)
	}

	_, err = jwt.Parse(resp.Token, func(tk *jwt.Token) (any, error) {
		return svc.ExpiredKey.Pub, nil
	})
	if err == nil {
	
	} else {
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		_, err2 := parser.Parse(resp.Token, func(tk *jwt.Token) (any, error) {
			return svc.ExpiredKey.Pub, nil
		})
		if err2 != nil {
			t.Fatalf("expected signature valid even if expired; got %v", err2)
		}
	}

	claims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(resp.Token, claims)
	if err != nil {
		t.Fatalf("ParseUnverified claims: %v", err)
	}
	expAny := claims["exp"]
	expFloat, ok := expAny.(float64)
	if !ok {
		t.Fatalf("exp not a number: %T", expAny)
	}
	expTime := time.Unix(int64(expFloat), 0).UTC()
	if expTime.After(Now()) {
		t.Fatalf("expected exp in the past, got %v", expTime)
	}
}

func TestMethodGuards(t *testing.T) {
	_, mux := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", strings.NewReader(""))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr2.Code)
	}
}

func TestRSAKeyType(t *testing.T) {
	svc, _ := setupTestServer(t)
	var _ *rsa.PublicKey = svc.ActiveKey.Pub
}
