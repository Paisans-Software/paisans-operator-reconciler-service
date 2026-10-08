package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The healthcheck passes only on a 200, and a reconciler that does not answer
// fails it.
func TestHealthcheckFollowsTheStatus(t *testing.T) {
	for code, want := range map[int]int{200: 0, 503: 1} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		if got := healthcheck(srv.URL); got != want {
			t.Errorf("status %d: exit %d, want %d", code, got, want)
		}
		srv.Close()
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if got := healthcheck(url); got != 1 {
		t.Errorf("no answer: exit %d, want 1", got)
	}
}
