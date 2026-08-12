package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func authStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestConsumeTOTPStepRejectsReplay(t *testing.T) {
	st := authStore(t)
	u, err := st.CreateUser("a@x.com", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	const step = int64(58000000)

	fresh, err := st.ConsumeTOTPStep(u.ID, step)
	if err != nil || !fresh {
		t.Fatalf("first consume = %v, %v; want true, nil", fresh, err)
	}
	// Same step again: a replay, must be refused.
	if again, _ := st.ConsumeTOTPStep(u.ID, step); again {
		t.Error("second consume of the same step succeeded — replay not blocked")
	}
	// An older step (the -1 window edge of a code seen earlier) must also fail.
	if older, _ := st.ConsumeTOTPStep(u.ID, step-1); older {
		t.Error("consuming an older step succeeded — replay floor not enforced")
	}
	// A newer step (a genuinely new code later) is accepted.
	if next, _ := st.ConsumeTOTPStep(u.ID, step+1); !next {
		t.Error("a newer step was refused — legitimate later login blocked")
	}
}

func TestConsumeTOTPStepIsAtomicUnderConcurrency(t *testing.T) {
	st := authStore(t)
	u, err := st.CreateUser("b@x.com", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	const step = int64(58000123)

	// Many goroutines present the same code at once; exactly one may win, or
	// the conditional UPDATE is not truly atomic and the replay guard is a lie.
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := st.ConsumeTOTPStep(u.ID, step); err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Errorf("%d goroutines consumed the same TOTP step; want exactly 1", wins)
	}
}

func TestSetUserTOTPResetsReplayFloor(t *testing.T) {
	st := authStore(t)
	u, err := st.CreateUser("c@x.com", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeTOTPStep(u.ID, 58000000); err != nil {
		t.Fatal(err)
	}
	// Reconfiguring the secret must clear the floor, or a re-enrolled user could
	// be unable to use a code whose step is below the old high-water mark.
	if err := st.SetUserTOTP(u.ID, "NEWSECRET", true); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPLastStep != 0 {
		t.Errorf("TOTPLastStep = %d after re-enroll, want 0", got.TOTPLastStep)
	}
}
