package operatorreconciler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paisans-software/pocketid-go"

	"github.com/paisans-software/paisans-operator-reconciler-service/internal/operatorreconciler"
)

const key = "static-key-0123456789"

// fakeUser is one Pocket ID user as the fake holds it.
type fakeUser struct {
	ID       string
	Username string
	IsAdmin  bool
	Disabled bool
	Email    string
	Groups   []string // group IDs
}

// fakePocketID is a Pocket ID that keeps users and groups, answers the two
// reads the reconciler makes, and records every request that is not a GET as
// forbidden: the reconciler writes nothing.
type fakePocketID struct {
	mu        sync.Mutex
	users     []*fakeUser
	groups    map[string]string // ID to name
	forbidden []string
	down      bool
	// secondPageFails makes the user list two pages long and the second one
	// a 502, so a reader that stops at the first page sees a partial list.
	secondPageFails bool
}

func newFake() *fakePocketID {
	return &fakePocketID{groups: map[string]string{"gM": "members", "gO": "operators", "gA": "admins"}}
}

func (f *fakePocketID) add(u fakeUser) *fakePocketID {
	f.users = append(f.users, &u)
	return f
}

func (f *fakePocketID) dto(u *fakeUser) map[string]any {
	groups := []map[string]string{}
	for _, g := range u.Groups {
		groups = append(groups, map[string]string{"id": g, "name": f.groups[g]})
	}
	out := map[string]any{"id": u.ID, "username": u.Username, "isAdmin": u.IsAdmin, "disabled": u.Disabled, "userGroups": groups}
	if u.Email != "" {
		out["email"] = u.Email
	}
	return out
}

func (f *fakePocketID) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.forbidden = append(f.forbidden, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(405)
		return
	}
	if f.down {
		w.WriteHeader(502)
		return
	}
	if r.Header.Get("X-API-Key") != key {
		w.WriteHeader(401)
		return
	}
	pages := 1
	if f.secondPageFails {
		pages = 2
		if r.URL.Query().Get("pagination[page]") != "1" {
			w.WriteHeader(502)
			return
		}
	}
	page := func(items []any) {
		json.NewEncoder(w).Encode(map[string]any{"data": items, "pagination": map[string]int{"totalPages": pages}})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/user-groups":
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
		page(items)
	case "/api/users":
		var items []any
		for _, u := range f.users {
			items = append(items, f.dto(u))
		}
		page(items)
	default:
		w.WriteHeader(404)
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// reconcilerFor is a reconciler over f with the operators alice and bob,
// the member group members, and the management given.
func reconcilerFor(t *testing.T, f *fakePocketID, standby bool, management string) (*operatorreconciler.Reconciler, *clock, *strings.Builder) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	log := &strings.Builder{}
	g := &operatorreconciler.Reconciler{
		API:         &pocketid.Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: key},
		Operators:   []string{"bob", "alice"},
		MemberGroup: "members",
		Management:  management,
		Standby:     func() bool { return standby },
		Now:         c.Now,
		Log:         func(format string, args ...any) { fmt.Fprintf(log, format+"\n", args...) },
	}
	t.Cleanup(func() {
		if len(f.forbidden) > 0 {
			t.Errorf("the reconciler made requests other than GET: %q", f.forbidden)
		}
	})
	return g, c, log
}

// operator is an enabled operator in members and operators.
func operator(id, name string) fakeUser {
	return fakeUser{ID: id, Username: name, Email: name + "@example.org", Groups: []string{"gM", "gO"}}
}

// healthyFake is alice and bob as operators, carol a member, and the static
// key's user, which is an administrator and never counts.
func healthyFake() *fakePocketID {
	return newFake().
		add(operator("a", "alice")).
		add(operator("b", "bob")).
		add(fakeUser{ID: "c", Username: "carol", Groups: []string{"gM"}}).
		add(fakeUser{ID: operatorreconciler.SyntheticUserID, Username: "static-api-user", IsAdmin: true})
}

// The group and management values are a contract with the paisans CLI's
// pocket-id blueprint, which states the same three; each side pins them, so
// either side changing one fails its own tests.
func TestTheContractValues(t *testing.T) {
	if operatorreconciler.OperatorsGroup != "operators" {
		t.Errorf("OperatorsGroup is %q", operatorreconciler.OperatorsGroup)
	}
	if operatorreconciler.ManagementPaisans != "paisans" || operatorreconciler.ManagementPocketID != "pocket-id" {
		t.Errorf("management values are %q and %q", operatorreconciler.ManagementPaisans, operatorreconciler.ManagementPocketID)
	}
}

// Each case is the healthy fake with one thing changed, under each
// management where it matters.
func TestThePassChecksOperatorsAndAdministrators(t *testing.T) {
	cases := []struct {
		name       string
		management string
		change     func(f *fakePocketID)
		want       string // "" is healthy
	}{
		{"every operator present", "paisans", func(*fakePocketID) {}, ""},
		{"every operator present under pocket-id", "pocket-id", func(*fakePocketID) {}, ""},
		{"an operator missing", "paisans", func(f *fakePocketID) { f.users = f.users[1:] }, "operator alice has no pocket id account"},
		{"an operator disabled", "paisans", func(f *fakePocketID) { f.users[0].Disabled = true }, "operator alice is disabled"},
		{"an operator outside members", "paisans", func(f *fakePocketID) { f.users[1].Groups = []string{"gO"} }, "operator bob is not in members"},
		{"an operator outside operators", "paisans", func(f *fakePocketID) { f.users[1].Groups = []string{"gM"} }, "operator bob is not in operators"},
		{"an operator outside both", "paisans", func(f *fakePocketID) { f.users[1].Groups = nil }, "operator bob is not in members or operators"},
		{"no operators group", "paisans", func(f *fakePocketID) { delete(f.groups, "gO") }, "no group named operators"},
		{"an operator administrator under pocket-id", "pocket-id", func(f *fakePocketID) { f.users[0].IsAdmin = true }, ""},
		{"an operator administrator under paisans", "paisans", func(f *fakePocketID) { f.users[0].IsAdmin = true }, "alice is a pocket id administrator, and under management paisans nobody is"},
		{"a member administrator under pocket-id", "pocket-id", func(f *fakePocketID) { f.users[2].IsAdmin = true }, "carol is a pocket id administrator and not an operator"},
		{"a member administrator under paisans", "paisans", func(f *fakePocketID) { f.users[2].IsAdmin = true }, "carol is a pocket id administrator, and under management paisans nobody is"},
		{"a disabled administrator", "paisans", func(f *fakePocketID) { f.users[2].IsAdmin, f.users[2].Disabled = true, true }, ""},
		// 3. Every enabled member of operators is an operator: an operator
		// taken out of the yaml who still holds the group is named.
		{"a member in operators", "paisans", func(f *fakePocketID) { f.users[2].Groups = []string{"gM", "gO"} }, "carol is in operators and not an operator"},
		{"a member in operators under pocket-id", "pocket-id", func(f *fakePocketID) { f.users[2].Groups = []string{"gO"} }, "carol is in operators and not an operator"},
		{"a disabled user in operators", "paisans", func(f *fakePocketID) { f.users[2].Groups, f.users[2].Disabled = []string{"gM", "gO"}, true }, ""},
		{"the static key's user in operators", "paisans", func(f *fakePocketID) { f.users[3].Groups = []string{"gO"} }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := healthyFake()
			c.change(f)
			g, _, _ := reconcilerFor(t, f, false, c.management)
			r := g.Pass()
			code, body := g.Status()
			if c.want == "" {
				if !r.Healthy || code != 200 {
					t.Errorf("unhealthy: %d %q", code, body)
				}
				return
			}
			if r.Healthy || code != 503 || !strings.Contains(body, c.want) {
				t.Errorf("status %d %q, want 503 naming %q", code, body, c.want)
			}
			if strings.Contains(body, "@") || strings.Contains(body, "\n") {
				t.Errorf("the body names an address or is more than one line: %q", body)
			}
		})
	}
}

// A healthy pass says who the operators are and who administers Pocket ID.
func TestAHealthyPassNamesTheOperators(t *testing.T) {
	g, _, _ := reconcilerFor(t, healthyFake(), false, "paisans")
	if r := g.Pass(); r.Message != "2 operators, each a member (alice, bob); no pocket id administrators" {
		t.Errorf("message %q", r.Message)
	}
	f := healthyFake()
	f.users[0].IsAdmin, f.users[1].IsAdmin = true, true
	g, _, _ = reconcilerFor(t, f, false, "pocket-id")
	if r := g.Pass(); r.Message != "2 operators, each a member (alice, bob); pocket id administrators: alice, bob" {
		t.Errorf("message %q", r.Message)
	}
}

// Two users in operators who are not operators are each named, in order, and
// with no operators group the pass says so once rather than per user.
func TestTheOperatorsGroupHoldsOnlyOperators(t *testing.T) {
	f := healthyFake().add(fakeUser{ID: "d", Username: "dave", Groups: []string{"gO"}})
	f.users[2].Groups = []string{"gM", "gO"}
	g, _, _ := reconcilerFor(t, f, false, "paisans")
	if r := g.Pass(); r.Message != "carol is in operators and not an operator; dave is in operators and not an operator" {
		t.Errorf("message %q", r.Message)
	}
	f = healthyFake()
	delete(f.groups, "gO")
	g, _, _ = reconcilerFor(t, f, false, "paisans")
	if r := g.Pass(); r.Message != "no group named operators" {
		t.Errorf("message %q", r.Message)
	}
}

// Every failure is named, not only the first.
func TestEveryFailureIsNamed(t *testing.T) {
	f := healthyFake()
	f.users = f.users[2:]
	f.users[0].IsAdmin = true
	g, _, log := reconcilerFor(t, f, false, "pocket-id")
	g.Pass()
	_, body := g.Status()
	for _, want := range []string{"operator alice has no pocket id account", "operator bob has no pocket id account", "carol is a pocket id administrator and not an operator"} {
		if !strings.Contains(body, want) || !strings.Contains(log.String(), want) {
			t.Errorf("%q is not in the body %q or the log %q", want, body, log)
		}
	}
}

func TestAStandbyDoesNothing(t *testing.T) {
	f := newFake()
	f.down = true
	g, _, _ := reconcilerFor(t, f, true, "paisans")
	g.Pass()
	if code, body := g.Status(); code != 200 || body != "standby" {
		t.Errorf("status %d %q", code, body)
	}
}

// Pocket ID not answering, or answering one page of two, is a failure that
// is retried soon, since the reconciler and Pocket ID start together.
func TestAnUnreadablePocketIDIsRetriedSoon(t *testing.T) {
	down := healthyFake()
	down.down = true
	partial := healthyFake()
	partial.secondPageFails = true
	for name, f := range map[string]*fakePocketID{"down": down, "partial": partial} {
		g, _, _ := reconcilerFor(t, f, false, "paisans")
		r := g.Pass()
		if r.Healthy || !r.Retry || r.Next() != operatorreconciler.RetryAfter {
			t.Errorf("%s: %+v", name, r)
		}
		if code, body := g.Status(); code != 503 || strings.Contains(body, key) {
			t.Errorf("%s: %d %q", name, code, body)
		}
	}
	f := healthyFake()
	delete(f.groups, "gM")
	g, _, _ := reconcilerFor(t, f, false, "paisans")
	if r := g.Pass(); r.Retry || r.Next() != operatorreconciler.Interval {
		t.Errorf("a pass that read Pocket ID asked for a retry: %+v", r)
	}
}

// Before any pass the reconciler is starting, and a pass older than the stale
// limit is reported as stale rather than as its old answer.
func TestStartingAndStale(t *testing.T) {
	g, c, _ := reconcilerFor(t, healthyFake(), false, "paisans")
	if code, body := g.Status(); code != 503 || body != "starting" {
		t.Errorf("before a pass: %d %q", code, body)
	}
	g.Pass()
	c.now = c.now.Add(operatorreconciler.StaleAfter - time.Minute)
	if code, _ := g.Status(); code != 200 {
		t.Errorf("a recent pass: %d", code)
	}
	c.now = c.now.Add(2 * time.Minute)
	if code, body := g.Status(); code != 503 || !strings.HasPrefix(body, "stale") {
		t.Errorf("an old pass: %d %q", code, body)
	}
}

// Liveness is not health: the container is alive before the first pass and
// while an operator is missing, so apply's health gate does not hold a
// deployment back on operators it has not made yet. Only a hung pass loop is
// not alive.
func TestLivenessIgnoresTheChecks(t *testing.T) {
	f := newFake()
	g, c, _ := reconcilerFor(t, f, false, "paisans")
	if !g.Live() {
		t.Error("not alive before the first pass")
	}
	g.Pass()
	if !g.Live() {
		t.Error("not alive with no operators")
	}
	c.now = c.now.Add(operatorreconciler.StaleAfter + time.Minute)
	if g.Live() {
		t.Error("alive with a stale pass")
	}
}
