package oauth

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSingleUseUnderConcurrency exercises the mutex-guarded single-use guarantees
// under concurrent redemption: exactly one caller may consume an auth code or
// rotate a refresh token, and concurrent map mutations must not lose updates. Run
// under `go test -race` to catch a widened critical section or a dropped lock —
// a regression these sequential-only assertions would otherwise miss.
func TestSingleUseUnderConcurrency(t *testing.T) {
	const n = 50

	t.Run("auth code consumed once", func(t *testing.T) {
		codes := newAuthCodeStore(time.Minute)
		code, err := codes.issue(authGrant{})
		if err != nil {
			t.Fatal(err)
		}
		var wins int64
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok := codes.consume(code); ok {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("auth code consumed %d times, want exactly 1", wins)
		}
	})

	t.Run("refresh token exchanged once", func(t *testing.T) {
		store := newRefreshStore(NewMemStore())
		token, err := store.issue("client", "mcp", PrincipalGrant{})
		if err != nil {
			t.Fatal(err)
		}
		var wins int64
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok, _ := store.exchange(token); ok {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("refresh token exchanged %d times, want exactly 1", wins)
		}
	})

	t.Run("jsonMapStore no lost update", func(t *testing.T) {
		m := jsonMapStore[int]{store: NewMemStore(), key: "k"}
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				_ = m.mutate(func(mm map[string]int) bool {
					mm[strconv.Itoa(v)] = v
					return true
				})
			}(i)
		}
		wg.Wait()
		final, err := m.load()
		if err != nil {
			t.Fatal(err)
		}
		if len(final) != n {
			t.Errorf("concurrent mutate kept %d keys, want %d (lost update)", len(final), n)
		}
	})
}
