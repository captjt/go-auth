# go-auth

`go-auth` is a Go-native authentication framework inspired by Better Auth's feature surface, designed for idiomatic Go services.

## Current Capabilities

- Go-native server constructor and handler mounting (`net/http` first)
- Core auth flows: email/password sign-up, sign-in, sign-out, get-session
- Session cookies, trusted origins, in-memory rate limiting
- OpenAPI emission endpoint (`/auth/v1/openapi.json`)
- Extensible plugin runtime with route conflict detection
- First plugin wave:
  - Username
  - Magic Link
  - Email OTP
  - Passkey with begin/finish challenge flow
  - Two-Factor with persistent TOTP secret + backup code hashes
- Storage backends behind `storage.Primary`:
  - Memory
  - SQL adapters: PostgreSQL, MySQL, SQLite
- Migration package and CLI support for schema generation/apply
- Bootstrap package to wire auth server + adapters + plugins from one YAML config file

## Install

```bash
go get github.com/captjt/go-auth
```

## Quick Start (Memory)

```go
package main

import (
	"log"
	"net/http"

	"github.com/captjt/go-auth/auth"
	"github.com/captjt/go-auth/storage/memory"
)

func main() {
	server, err := auth.New(auth.Config{
		Secret:       "01234567890123456789012345678901",
		PrimaryStore: memory.New(),
		EmailPassword: auth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", server.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Quick Start (Single YAML Bootstrap)

```yaml
# go-auth.yaml
appName: "My App"
basePath: "/auth/v1"
secret: "01234567890123456789012345678901"
emailPassword:
  enabled: true
database:
  dialect: "sqlite"
  dsn: "file:go-auth.db"
  autoMigrate: true
plugins:
  username:
    enabled: true
  passkey:
    enabled: true
  twoFactor:
    enabled: true
    exposeCodeInResponse: true
```

```bash
go run ./cmd/go-auth serve --config go-auth.yaml --addr :8080
```

## CLI

Generate SQL schema:

```bash
go run ./cmd/go-auth generate --dialect sqlite --output migrations.sql
```

Apply migrations:

```bash
go run ./cmd/go-auth migrate --dialect sqlite --dsn 'file:go-auth.db'
```

Other commands:

```bash
go run ./cmd/go-auth secret
go run ./cmd/go-auth info
go run ./cmd/go-auth init
```

## Default Endpoints

Base path defaults to `/auth/v1`.

- `GET /auth/v1/ok`
- `GET /auth/v1/openapi.json`
- `POST /auth/v1/sign-up/email`
- `POST /auth/v1/sign-in/email`
- `POST /auth/v1/sign-out`
- `GET /auth/v1/get-session`

Plugin endpoints are mounted under `/auth/v1/plugins/...`.

## CI

A GitHub Actions workflow is included for:

- unit tests (`go test ./...`)
- SQL integration tests against PostgreSQL and MySQL services

## Tests

```bash
go test ./...
```

## Status

This is an early implementation release and not yet full Better Auth parity.
