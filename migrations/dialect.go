package migrations

import (
	"fmt"
	"strings"
)

type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectMySQL    Dialect = "mysql"
	DialectSQLite   Dialect = "sqlite"
)

func ParseDialect(value string) (Dialect, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case string(DialectPostgres), "postgresql", "pg":
		return DialectPostgres, nil
	case string(DialectMySQL), "mariadb":
		return DialectMySQL, nil
	case string(DialectSQLite), "sqlite3":
		return DialectSQLite, nil
	default:
		return "", fmt.Errorf("unsupported dialect %q", value)
	}
}

func (d Dialect) String() string {
	return string(d)
}

func DriverName(d Dialect) (string, error) {
	switch d {
	case DialectPostgres:
		return "pgx", nil
	case DialectMySQL:
		return "mysql", nil
	case DialectSQLite:
		return "sqlite", nil
	default:
		return "", fmt.Errorf("unsupported dialect %q", d)
	}
}
