package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/captjt/go-auth/auth"
	"github.com/captjt/go-auth/bootstrap"
	"github.com/captjt/go-auth/migrations"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := strings.ToLower(strings.TrimSpace(os.Args[1]))
	switch cmd {
	case "secret":
		runSecret()
	case "info":
		runInfo()
	case "init":
		runInit()
	case "generate":
		runGenerate(os.Args[2:])
	case "migrate":
		runMigrate(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("go-auth CLI")
	fmt.Println("Usage: go-auth <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  secret                         Generate a high-entropy secret")
	fmt.Println("  info                           Print CLI and build metadata")
	fmt.Println("  init                           Create a starter go-auth config file")
	fmt.Println("  generate [--dialect d] [--output file]")
	fmt.Println("                                 Generate SQL schema for a dialect")
	fmt.Println("  migrate --dialect d --dsn dsn")
	fmt.Println("                                 Apply migrations to a target database")
	fmt.Println("  serve --config path [--addr :8080]")
	fmt.Println("                                 Start go-auth from a single config file")
}

func runSecret() {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate secret: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(base64.RawStdEncoding.EncodeToString(buf))
}

func runInfo() {
	payload := map[string]any{
		"name":              "go-auth",
		"version":           auth.Version,
		"schemaVersion":     migrations.CurrentVersion,
		"supportedDialects": []string{"postgres", "mysql", "sqlite"},
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(b))
}

func runInit() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve current directory: %v\n", err)
		os.Exit(1)
	}

	path := filepath.Join(cwd, "go-auth.example.yaml")
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("%s already exists\n", path)
		return
	}

	content := strings.TrimSpace(`appName: "My App"
basePath: "/auth/v1"
secret: "replace-with-32-char-secret"
trustedOrigins:
  - "http://localhost:3000"
database:
  dialect: "sqlite"
  dsn: "file:go-auth.db"
  autoMigrate: true
emailPassword:
  enabled: true
session:
  cookieName: "go_auth_session"
  duration: "168h"
rateLimit:
  enabled: true
  window: "10s"
  max: 100
plugins:
  username:
    enabled: true
  passkey:
    enabled: true
    challengeTtl: "5m"
    rpId: "localhost"
    rpDisplayName: "My App"
    rpOrigins:
      - "http://localhost:3000"
  twoFactor:
    enabled: true`) + "\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("created %s\n", path)
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	dialectValue := fs.String("dialect", "sqlite", "target dialect: postgres|mysql|sqlite")
	output := fs.String("output", "", "output file path; prints to stdout when empty")
	_ = fs.Parse(args)

	dialect, err := migrations.ParseDialect(*dialectValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid dialect: %v\n", err)
		os.Exit(1)
	}

	script, err := migrations.GenerateSQLScript(dialect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate SQL: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(*output) == "" {
		fmt.Println(script)
		return
	}

	if err := os.WriteFile(*output, []byte(script+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write migration SQL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote migration SQL to %s\n", *output)
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dialectValue := fs.String("dialect", "sqlite", "target dialect: postgres|mysql|sqlite")
	dsn := fs.String("dsn", "", "database connection string")
	timeout := fs.Duration("timeout", 30*time.Second, "migration timeout")
	_ = fs.Parse(args)

	if strings.TrimSpace(*dsn) == "" {
		fmt.Fprintln(os.Stderr, "--dsn is required")
		os.Exit(1)
	}

	dialect, err := migrations.ParseDialect(*dialectValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid dialect: %v\n", err)
		os.Exit(1)
	}

	driverName, err := migrations.DriverName(dialect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unsupported dialect: %v\n", err)
		os.Exit(1)
	}

	db, err := sql.Open(driverName, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", err)
		os.Exit(1)
	}

	if err := migrations.Apply(ctx, db, dialect); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("migrations applied successfully (%s)\n", dialect)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "go-auth.yaml", "path to go-auth YAML config")
	addr := fs.String("addr", ":8080", "listen address")
	_ = fs.Parse(args)

	server, cleanup, err := bootstrap.NewServerFromFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to bootstrap server: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	fmt.Printf("go-auth listening on %s\n", *addr)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "server stopped: %v\n", err)
		os.Exit(1)
	}
}
