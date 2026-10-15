# jwks-server

A JWKS server backed by SQLite written in Go for CSCE 3550 Project 2. The server stores RSA private keys in a SQLite database, serves unexpired public keys via a JWKS endpoint, and creates signed JWTs.

## Features

- Persists RSA private keys in SQLite database `totally_not_my_privateKeys.db`.
- Uses schema `keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)`.
- Keys are serialized and deserialized in PKCS#1 PEM format.
- Uses parameterized SQL queries to prevent SQL injection vulnerabilities.
- Generates and stores at least one unexpired key and at least one expired key.
- Returns unexpired public keys from `GET /.well-known/jwks.json`.
- Issues valid JWTs from `POST /auth`.
- Issues expired JWTs when the `expired` query parameter is present (`POST /auth?expired=true`).
- Supports mock authentication with Basic auth or JSON payloads.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/jwks.json` | Returns unexpired public keys in JWKS format. |
| POST | `/auth` | Returns a JWT signed with an unexpired key from the database. |
| POST | `/auth?expired=true` | Returns a JWT signed with an expired key from the database. |

## Running the Server

Run:

```bash
go run .
```

The server runs on port `8080`.

Test endpoints:

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Testing

Run unit tests:

```bash
go test ./...
```

Run tests with statement coverage:

```bash
go test -cover ./...
```

Test coverage is above the required 80%.