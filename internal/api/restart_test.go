package api

import (
	"net/http/httptest"
	"testing"
)

func TestRestartRequiresAuthentication(t *testing.T) {
	calls := 0
	s, _, err := New(nil, Options{Token: "test", Restart: func() { calls++ }})
	if err != nil {
		t.Fatal(err)
	}
	for _, authorized := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/api/restart", nil)
		if authorized {
			req.Header.Set("Authorization", "Bearer test")
		}
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		want := 401
		if authorized {
			want = 202
		}
		if w.Code != want {
			t.Fatalf("got %d, want %d", w.Code, want)
		}
	}
	if calls != 1 {
		t.Fatalf("restart called %d times", calls)
	}
}
