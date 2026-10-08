package adminreconciler_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/adminreconciler"
	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

const key = "static-key-0123456789"

// fakeUser is one Pocket ID user as the fake holds it.
type fakeUser struct {
	ID       string
	Username string
	IsAdmin  bool
	Disabled bool
	LdapID   string
	Groups   []string // group IDs
}

// fakePocketID is a Pocket ID that keeps users and groups, answers the
// routes the reconciler is allowed to use, and records every request. A request to
// any other route is answered 405 and recorded as forbidden.
type fakePocketID struct {
	mu        sync.Mutex
	users     []*fakeUser
	groups    map[string]string // ID to name
	writes    []string          // "PUT /api/users/<id>/user-groups <ids>"
	forbidden []string
	failWrite map[string]bool // user IDs whose write answers 500
	down      bool
	// beforeWrite runs between the reconciler's fresh read and its write, to
	// change a user under it.
	onRead func(id string)
}

func newFake() *fakePocketID {
	return &fakePocketID{groups: map[string]string{"gA": "admins", "gM": "members"}, failWrite: map[string]bool{}}
}

func (f *fakePocketID) add(u fakeUser) *fakePocketID {
	f.users = append(f.users, &u)
	return f
}

func (f *fakePocketID) find(id string) *fakeUser {
	for _, u := range f.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func (f *fakePocketID) dto(u *fakeUser) map[string]any {
	groups := []map[string]string{}
	for _, g := range u.Groups {
		groups = append(groups, map[string]string{"id": g, "name": f.groups[g]})
	}
	out := map[string]any{"id": u.ID, "username": u.Username, "isAdmin": u.IsAdmin, "disabled": u.Disabled, "userGroups": groups}
	if u.LdapID != "" {
		out["ldapId"] = u.LdapID
	}
	return out
}

func (f *fakePocketID) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.down {
		w.WriteHeader(502)
		return
	}
	if r.Header.Get("X-API-Key") != key {
		w.WriteHeader(401)
		return
	}
	page := func(items []any) {
		json.NewEncoder(w).Encode(map[string]any{"data": items, "pagination": map[string]int{"totalPages": 1}})
	}
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/api/user-groups":
		f.mu.Lock()
		var items []any
		ids := make([]string, 0, len(f.groups))
		for id := range f.groups {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if strings.Contains(f.groups[id], r.URL.Query().Get("search")) {
				items = append(items, map[string]string{"id": id, "name": f.groups[id]})
			}
		}
		f.mu.Unlock()
		page(items)
	case r.Method == "GET" && path == "/api/users":
		f.mu.Lock()
		var items []any
		for _, u := range f.users {
			items = append(items, f.dto(u))
		}
		f.mu.Unlock()
		page(items)
	case r.Method == "GET" && strings.HasPrefix(path, "/api/users/") && strings.Count(path, "/") == 3:
		id := strings.TrimPrefix(path, "/api/users/")
		if f.onRead != nil {
			f.onRead(id)
		}
		f.mu.Lock()
		u := f.find(id)
		f.mu.Unlock()
		if u == nil {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(f.dto(u))
	case r.Method == "PUT" && strings.HasPrefix(path, "/api/users/") && strings.HasSuffix(path, "/user-groups"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/users/"), "/user-groups")
		var body struct {
			UserGroupIDs []string `json:"userGroupIds"`
		}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.writes = append(f.writes, fmt.Sprintf("PUT %s %s", id, strings.Join(body.UserGroupIDs, ",")))
		if f.failWrite[id] {
			w.WriteHeader(500)
			io.WriteString(w, `{"error":"database is locked"}`)
			return
		}
		u := f.find(id)
		if u == nil {
			w.WriteHeader(404)
			return
		}
		u.Groups = body.UserGroupIDs
		w.WriteHeader(200)
	default:
		f.mu.Lock()
		f.forbidden = append(f.forbidden, r.Method+" "+path)
		f.mu.Unlock()
		w.WriteHeader(405)
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func reconcilerFor(t *testing.T, f *fakePocketID, standby bool) (*adminreconciler.Reconciler, *clock, *strings.Builder) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := &clock{now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	log := &strings.Builder{}
	g := &adminreconciler.Reconciler{
		API:     &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: key},
		Standby: func() bool { return standby },
		Now:     c.Now,
		Log:     func(format string, args ...any) { fmt.Fprintf(log, format+"\n", args...) },
	}
	t.Cleanup(func() {
		if len(f.forbidden) > 0 {
			t.Errorf("the reconciler made requests it may not make: %q", f.forbidden)
		}
		// Every write is the one sanctioned shape: a user's own groups plus
		// admins, nothing taken away.
		for _, w := range f.writes {
			if !strings.HasSuffix(w, "gA") && !strings.Contains(w, "gA,") {
				t.Errorf("a write that does not add admins: %q", w)
			}
		}
	})
	return g, c, log
}

func status(g *adminreconciler.Reconciler) (int, string) { return g.Status() }

// A Pocket ID administrator outside admins is added, keeping their other
// groups, and the pass is healthy once two are in.
func TestAMissingAdministratorIsAdded(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", IsAdmin: true, Groups: []string{"gM"}}).
		add(fakeUser{ID: "c", Username: "carol", Groups: []string{"gM"}})
	g, _, log := reconcilerFor(t, f, false)
	g.Pass()

	if want := []string{"PUT b gM,gA"}; fmt.Sprint(f.writes) != fmt.Sprint(want) {
		t.Fatalf("writes %q, want %q", f.writes, want)
	}
	if code, body := status(g); code != 200 || !strings.Contains(body, "2 members") {
		t.Errorf("status %d %q", code, body)
	}
	if !strings.Contains(log.String(), "bob") || !strings.Contains(log.String(), "added") {
		t.Errorf("the write was not logged: %q", log.String())
	}
}

// The static key's synthetic user, an LDAP managed user and a disabled user
// are never added, and none of them counts.
func TestExcludedUsersAreNeitherAddedNorCounted(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: adminreconciler.SyntheticUserID, Username: "static-api-user-x1y2z3", IsAdmin: true, Groups: []string{"gA"}}).
		add(fakeUser{ID: "l", Username: "lara", IsAdmin: true, LdapID: "cn=lara"}).
		add(fakeUser{ID: "d", Username: "dave", IsAdmin: true, Disabled: true}).
		add(fakeUser{ID: "e", Username: "erin", Disabled: true, Groups: []string{"gA"}}).
		add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}})
	g, _, _ := reconcilerFor(t, f, false)
	g.Pass()

	if len(f.writes) != 0 {
		t.Errorf("wrote %q, want nothing", f.writes)
	}
	code, body := status(g)
	if code != 503 || !strings.Contains(body, "1 member") || !strings.Contains(body, "alice") {
		t.Errorf("status %d %q, want 503 naming the one member", code, body)
	}
	if strings.Contains(body, "static-api-user") || strings.Contains(body, "erin") {
		t.Errorf("counted an excluded user: %q", body)
	}
}

// Members of admins who are not Pocket ID administrators stay: the reconciler
// never removes anyone.
func TestNobodyIsRemoved(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: "a", Username: "alice", Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", Groups: []string{"gA", "gM"}})
	g, _, _ := reconcilerFor(t, f, false)
	g.Pass()
	if len(f.writes) != 0 {
		t.Errorf("wrote %q, want nothing", f.writes)
	}
	if code, _ := status(g); code != 200 {
		t.Errorf("status %d, want 200 with two members", code)
	}
}

// The user is read again just before the write, and the write carries the
// groups that read found, so a group added since the list is kept.
func TestTheWriteUsesAFreshRead(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", IsAdmin: true})
	f.groups["gX"] = "editors"
	f.onRead = func(id string) {
		f.mu.Lock()
		if id == "b" {
			f.find("b").Groups = []string{"gX"}
		}
		f.mu.Unlock()
	}
	g, _, _ := reconcilerFor(t, f, false)
	g.Pass()
	if want := []string{"PUT b gX,gA"}; fmt.Sprint(f.writes) != fmt.Sprint(want) {
		t.Fatalf("writes %q, want %q", f.writes, want)
	}
}

// A user who joined admins, or stopped being an administrator, between the
// list and the fresh read is left alone.
func TestAUserWhoChangedSinceTheListIsLeftAlone(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", IsAdmin: true}).
		add(fakeUser{ID: "c", Username: "carol", IsAdmin: true})
	f.onRead = func(id string) {
		f.mu.Lock()
		switch id {
		case "b":
			f.find("b").Groups = []string{"gA"}
		case "c":
			f.find("c").IsAdmin = false
		}
		f.mu.Unlock()
	}
	g, _, _ := reconcilerFor(t, f, false)
	g.Pass()
	if len(f.writes) != 0 {
		t.Errorf("wrote %q, want nothing", f.writes)
	}
}

// A standby asks Pocket ID nothing and reports healthy.
func TestAStandbyDoesNothing(t *testing.T) {
	f := newFake()
	f.down = true
	g, _, _ := reconcilerFor(t, f, true)
	g.Pass()
	if code, body := status(g); code != 200 || body != "standby" {
		t.Errorf("status %d %q", code, body)
	}
}

func TestUnhealthyStates(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakePocketID)
		want  string
	}{
		{"no admins group", func(f *fakePocketID) {
			delete(f.groups, "gA")
			f.add(fakeUser{ID: "a", Username: "alice", IsAdmin: true})
		}, "no group named admins"},
		{"pocket id does not answer", func(f *fakePocketID) { f.down = true }, "502"},
		{"a write fails", func(f *fakePocketID) {
			f.add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}})
			f.add(fakeUser{ID: "b", Username: "bob", IsAdmin: true})
			f.add(fakeUser{ID: "c", Username: "carol", IsAdmin: true})
			f.failWrite["b"] = true
		}, "could not add bob"},
		{"one member", func(f *fakePocketID) {
			f.add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Groups: []string{"gA"}})
		}, "at least 2"},
		{"no members", func(f *fakePocketID) {}, "0 members"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			c.setup(f)
			g, _, _ := reconcilerFor(t, f, false)
			g.Pass()
			code, body := status(g)
			if code != 503 || !strings.Contains(body, c.want) {
				t.Errorf("status %d %q, want 503 containing %q", code, body, c.want)
			}
			if strings.Contains(body, key) {
				t.Errorf("the body carries the key: %q", body)
			}
			if strings.Contains(body, "\n") {
				t.Errorf("the body is more than one line: %q", body)
			}
		})
	}
}

// Before any pass the reconciler is starting, and a pass older than the stale
// limit is reported as stale rather than as its old answer.
func TestStartingAndStale(t *testing.T) {
	f := newFake().
		add(fakeUser{ID: "a", Username: "alice", Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", Groups: []string{"gA"}})
	g, c, _ := reconcilerFor(t, f, false)
	if code, body := status(g); code != 503 || body != "starting" {
		t.Errorf("before a pass: %d %q", code, body)
	}
	g.Pass()
	c.now = c.now.Add(adminreconciler.StaleAfter - time.Minute)
	if code, _ := status(g); code != 200 {
		t.Errorf("a recent pass: %d", code)
	}
	c.now = c.now.Add(2 * time.Minute)
	if code, body := status(g); code != 503 || !strings.HasPrefix(body, "stale") {
		t.Errorf("an old pass: %d %q", code, body)
	}
}

// A pass that could not read Pocket ID asks to be retried soon, because the
// reconciler and Pocket ID start together and the first pass may find it still
// starting. A pass that read Pocket ID waits the full interval, whatever it
// found.
func TestOnlyAnUnreadablePocketIDIsRetriedSoon(t *testing.T) {
	down := newFake()
	down.down = true
	g, _, _ := reconcilerFor(t, down, false)
	if r := g.Pass(); !r.Retry {
		t.Errorf("Pocket ID did not answer, and the pass did not ask for a retry: %+v", r)
	}
	for name, f := range map[string]*fakePocketID{
		"no group":   func() *fakePocketID { f := newFake(); delete(f.groups, "gA"); return f }(),
		"one member": newFake().add(fakeUser{ID: "a", Username: "alice", Groups: []string{"gA"}}),
	} {
		g, _, _ := reconcilerFor(t, f, false)
		if r := g.Pass(); r.Retry {
			t.Errorf("%s: a pass that read Pocket ID asked for a retry: %+v", name, r)
		}
	}
}

// Liveness is not health: the container is alive before the first pass and
// while admins is short, so apply's health gate does not hold a deployment
// back on a group nobody has made yet. Only a hung pass loop is not alive.
func TestLivenessIgnoresTheCount(t *testing.T) {
	f := newFake()
	delete(f.groups, "gA")
	g, c, _ := reconcilerFor(t, f, false)
	if !g.Live() {
		t.Error("not alive before the first pass")
	}
	g.Pass()
	if !g.Live() {
		t.Error("not alive with no admins group")
	}
	c.now = c.now.Add(adminreconciler.StaleAfter + time.Minute)
	if g.Live() {
		t.Error("alive with a stale pass")
	}
}
