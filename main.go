package main

import (
	"log"
	"net/http"
)

func main() {
	svc, err := NewService()
	if err != nil {
		log.Fatalf("init service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", svc.HandleJWKS)
	mux.HandleFunc("/auth", svc.HandleAuth)

	addr := ":8080"
	log.Printf("JWKS server listening on %s", addr)
	log.Printf("JWKS:  http://localhost%s/.well-known/jwks.json", addr)
	log.Printf("AUTH:  POST http://localhost%s/auth  (add ?expired=1 for expired token)", addr)

	if err := http.ListenAndServe(addr, withLogging(mux)); err != nil {
		log.Fatalf("server: %v", err)
	}
}
