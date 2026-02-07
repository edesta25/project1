# JWKS Server Assignment

## What it does
- Generates RSA keypairs with:
  - unique `kid`
  - expiry timestamp
- Serves a JWKS endpoint:
  - `GET /.well-known/jwks.json`
  - only returns **non-expired** public keys
- Issues JWTs from:
  - `POST /auth` (no body required)
  - includes `kid` in JWT header
  - returns a valid, unexpired JWT signed with active key
- If `?expired=1` is present:
  - signs with the expired key
  - sets `exp` to the key's expired expiry (past)

## Run
```bash
go mod tidy
go run .

