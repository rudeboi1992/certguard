package store

import (
	"os"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// TestPostgresRoundTrip exercises the Postgres dialect (identity columns,
// $N placeholders, RETURNING id) against a real server. It is skipped unless
// CERTGUARD_TEST_PG_DSN is set, e.g.:
//
//	docker run -d --name pg -e POSTGRES_PASSWORD=p -e POSTGRES_USER=cg \
//	    -e POSTGRES_DB=certguard -p 5433:5432 postgres:15-alpine
//	CERTGUARD_TEST_PG_DSN='postgres://cg:p@localhost:5433/certguard?sslmode=disable' \
//	    go test ./internal/store -run TestPostgresRoundTrip -v
func TestPostgresRoundTrip(t *testing.T) {
	dsn := os.Getenv("CERTGUARD_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set CERTGUARD_TEST_PG_DSN to run the Postgres integration test")
	}
	st, err := Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer st.Close()

	// Insert (RETURNING id) + query (rebind).
	u, err := st.CreateUser(uniqueEmail(), "hash", "admin")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("expected non-zero id from RETURNING")
	}
	got, err := st.GetUserByEmail(u.Email)
	if err != nil || got.ID != u.ID {
		t.Fatalf("get user by email: %v (got %+v)", err, got)
	}

	c, err := st.AddCert(&model.Cert{Name: "pg.example.com", Kind: model.KindManual,
		ExpiresAt: time.Now().UTC().AddDate(0, 0, 10)})
	if err != nil {
		t.Fatalf("add cert: %v", err)
	}
	list, err := st.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, x := range list {
		if x.ID == c.ID {
			found = true
		}
	}
	if !found {
		t.Error("added cert not in List()")
	}

	ch, err := st.CreateChannel(u.ID, model.ChannelWebhook, "http://x/y", "30,7,3")
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if err := st.DeleteChannel(ch.ID, u.ID); err != nil {
		t.Fatalf("delete channel: %v", err)
	}
}

// uniqueEmail avoids UNIQUE collisions across repeated test runs against a
// persistent database. time.Now is fine here (test-only, not resumed).
func uniqueEmail() string {
	return "pgtest+" + time.Now().Format("150405.000000") + "@x.com"
}
