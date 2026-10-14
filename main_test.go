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

// The reconciler refuses to start without the operators, the member group
// and a management it knows.
func TestCheckedRefusesAnIncompleteEnvironment(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	full := map[string]string{"PAISANS_OPERATORS": "alice, bob", "PAISANS_MEMBER_GROUP": "members", "PAISANS_MANAGEMENT": "paisans"}
	ops, group, management, err := checked(env(full))
	if err != nil || len(ops) != 2 || ops[1] != "bob" || group != "members" || management != "paisans" {
		t.Fatalf("%v %q %q %v", ops, group, management, err)
	}
	for _, missing := range []string{"PAISANS_OPERATORS", "PAISANS_MEMBER_GROUP", "PAISANS_MANAGEMENT"} {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		delete(m, missing)
		if _, _, _, err := checked(env(m)); err == nil {
			t.Errorf("started without %s", missing)
		}
	}
	full["PAISANS_MANAGEMENT"] = "both"
	if _, _, _, err := checked(env(full)); err == nil {
		t.Error("started with an unknown management")
	}
}
