package store

import (
	"database/sql"
	"strconv"
	"strings"
)

// This file isolates the SQLite/Postgres dialect differences behind three query
// wrappers (exec/queryRow/query) and an insert helper. The rest of the store
// writes portable SQL with '?' placeholders and relies on these to translate.
//
// Two dialect differences are handled:
//   - Placeholders: SQLite uses '?', Postgres uses '$1','$2',… — rebind() maps them.
//   - Insert ids: instead of LastInsertId() (unsupported by the Postgres driver),
//     inserts use "RETURNING id", supported by both modern SQLite and Postgres.

// rebind converts '?' placeholders to '$N' for Postgres; SQLite keeps '?'.
// Safe because none of our queries contain a literal '?'.
func (s *Store) rebind(q string) string {
	if s.driver != "postgres" {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.db.Exec(s.rebind(q), args...)
}

func (s *Store) queryRow(q string, args ...any) *sql.Row {
	return s.db.QueryRow(s.rebind(q), args...)
}

func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.db.Query(s.rebind(q), args...)
}

// insertReturningID runs an INSERT with a trailing "RETURNING id" and returns
// the new row's id. Works on both SQLite (3.35+) and Postgres.
func (s *Store) insertReturningID(q string, args ...any) (int64, error) {
	var id int64
	err := s.queryRow(q+" RETURNING id", args...).Scan(&id)
	return id, err
}
