package dnscontinuity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	testToken = "fixture-not-a-secret-members"
	testZone  = "example.org"
	accountID = "acc0000000000000000000000000000a"
)

// member is one entry of a fake members list, in Cloudflare's shape.
func member(email, status string, twoFA bool, role string, policy string) map[string]any {
	m := map[string]any{
		"id":     "m-" + email,
		"email":  email,
		"status": status,
		"user":   map[string]any{"email": email, "id": "u-" + email, "two_factor_authentication_enabled": twoFA},
		"roles":  []any{},
	}
	if role != "" {
		m["roles"] = []any{map[string]any{"id": "r", "name": role}}
	}
	if policy != "" {
		m["policies"] = []any{map[string]any{
			"id":                "p",
			"access":            policy,
			"permission_groups": []any{map[string]any{"id": "g", "name": SuperAdministrator}},
			"resource_groups":   []any{map[string]any{"id": "rg", "scope": map[string]any{"key": accountScope + accountID}}},
		}}
	}
	return m
}

// fakeZone is one zone the fake lists for a name.
type fakeZone struct{ status, account string }

// fakeCloudflare serves the two routes the client may call, records every
// request, and pages members by per_page. Without zones it holds one active
// zone, testZone, in accountID, whose members are members; with zones, each
// name lists those zones and each account's members are in accounts.
// failPage, when set, answers that page with 500.
type fakeCloudflare struct {
	mu       sync.Mutex
	requests []string
	members  []map[string]any
	zones    map[string][]fakeZone
	accounts map[string][]map[string]any
	failPage int
	status   int
}

func (f *fakeCloudflare) zonesFor(name string) []fakeZone {
	if f.zones == nil {
		if name == testZone {
			return []fakeZone{{"active", accountID}}
		}
		return nil
	}
	return f.zones[name]
}

func (f *fakeCloudflare) membersOf(account string) ([]map[string]any, bool) {
	if f.accounts == nil {
		return f.members, account == accountID
	}
	m, ok := f.accounts[account]
	return m, ok
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		http.Error(w, `{"success":false}`, http.StatusForbidden)
		return
	}
	if f.status != 0 {
		http.Error(w, `{"success":false,"errors":[{"message":"secret detail"}]}`, f.status)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		zones := []any{}
		name := r.URL.Query().Get("name")
		for _, z := range f.zonesFor(name) {
			// The status filter is honoured or not by the flag a test sets,
			// so the client's own check is exercised either way.
			zones = append(zones, map[string]any{"id": "z", "name": name, "status": z.status, "account": map[string]any{"id": z.account}})
		}
		writeEnvelope(w, zones, 1)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/accounts/") && strings.HasSuffix(r.URL.Path, "/members"):
		members, ok := f.membersOf(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/accounts/"), "/members"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page == f.failPage {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		pages := (len(members) + per - 1) / per
		if pages == 0 {
			pages = 1
		}
		start := min((page-1)*per, len(members))
		end := min(start+per, len(members))
		writeEnvelope(w, members[start:end], pages)
	default:
		http.NotFound(w, r)
	}
}

func writeEnvelope(w http.ResponseWriter, result any, pages int) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "errors": []any{}, "result": result,
		"result_info": map[string]any{"page": 1, "per_page": 50, "total_pages": pages},
	})
}

func newClient(t *testing.T, f *fakeCloudflare) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Client{Token: testToken, Domain: testZone, Base: srv.URL, HTTP: srv.Client()}
}

var hasher = Hasher{Key: []byte("fixture-not-a-secret-hash-key-32")}

// logs collects log lines, so a test can assert none carries an address.
type logs struct{ lines []string }

func (l *logs) printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func evaluate(t *testing.T, admins []Admin, members []map[string]any, mapping map[string]string) (Result, []string) {
	t.Helper()
	f := &fakeCloudflare{members: members}
	got, err := newClient(t, f).Members(context.Background())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d accounts, want 1", len(got))
	}
	l := &logs{}
	r := Evaluate(admins, got, hasher, mapping, l.printf)
	noAddresses(t, r, l.lines, admins, members)
	return r, l.lines
}

// noAddresses fails if any body or log line holds an address.
func noAddresses(t *testing.T, r Result, lines []string, admins []Admin, members []map[string]any) {
	t.Helper()
	text := r.SuperAdmins.Message + "\n" + r.TwoFA.Message + "\n" + strings.Join(lines, "\n")
	for _, a := range admins {
		if a.Email != "" && strings.Contains(text, a.Email) {
			t.Errorf("output names %s's address: %s", a.Username, text)
		}
	}
	for _, m := range members {
		if strings.Contains(text, m["email"].(string)) {
			t.Errorf("output names a member's address: %s", text)
		}
	}
	if strings.Contains(text, "@") || strings.Contains(text, testToken) {
		t.Errorf("output holds an address or the token: %s", text)
	}
}

func admins(names ...string) []Admin {
	out := make([]Admin, 0, len(names))
	for _, n := range names {
		out = append(out, Admin{Username: n, Email: n + "@example.org"})
	}
	return out
}

func TestEverySuperAdministratorPasses(t *testing.T) {
	r, _ := evaluate(t, admins("alice", "bob"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("Bob@Example.org ", "accepted", true, "", "allow"),
		member("extra@example.org", "accepted", false, "Administrator", ""),
	}, nil)
	if !r.SuperAdmins.Healthy || r.SuperAdmins.Message != "2 of 2 operators are cloudflare super admins" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
	if !r.TwoFA.Healthy {
		t.Errorf("2fa = %+v; the extra member's 2fa must not count", r.TwoFA)
	}
}

func TestAnAdministratorIsNotEnough(t *testing.T) {
	r, lines := evaluate(t, admins("alice", "bob", "carol"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("bob@example.org", "accepted", true, SuperAdministrator, ""),
		member("carol@example.org", "accepted", true, "Administrator", ""),
	}, nil)
	if r.SuperAdmins.Healthy || r.SuperAdmins.Message != "1 of 3 operators not cloudflare super admin" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "carol") {
		t.Errorf("log = %q, want one line naming carol", lines)
	}
}

func TestPendingAndDeniedDoNotCount(t *testing.T) {
	r, _ := evaluate(t, admins("alice", "bob", "carol"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("bob@example.org", "pending", true, SuperAdministrator, ""),
		member("carol@example.org", "accepted", true, "", "deny"),
	}, nil)
	if r.SuperAdmins.Healthy || r.SuperAdmins.Message != "2 of 3 operators not cloudflare super admin (1 pending)" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
}

func TestOneSuperAdministratorIsBelowTheFloor(t *testing.T) {
	r, _ := evaluate(t, admins("alice"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
	}, nil)
	if r.SuperAdmins.Healthy || r.SuperAdmins.Message != "1 of 1 operators are cloudflare super admins; at least 2 are needed" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
}

func TestAMappedAdminMatchesAtTheMappedAddressOnly(t *testing.T) {
	mapping := map[string]string{hasher.Hash("bob@example.org"): hasher.Hash("bob.work@example.org")}
	r, _ := evaluate(t, admins("alice", "bob"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("bob.work@example.org", "accepted", true, SuperAdministrator, ""),
	}, mapping)
	if !r.SuperAdmins.Healthy {
		t.Errorf("mapped: super admins = %+v", r.SuperAdmins)
	}
	r, _ = evaluate(t, admins("alice", "bob"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("bob@example.org", "accepted", true, SuperAdministrator, ""),
	}, mapping)
	if r.SuperAdmins.Healthy {
		t.Errorf("a mapped admin matched at their pocket id address: %+v", r.SuperAdmins)
	}
}

func TestAnAdminWithNoEmailFails(t *testing.T) {
	r, _ := evaluate(t, []Admin{{Username: "alice", Email: "alice@example.org"}, {Username: "bob"}}, []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
	}, nil)
	if r.SuperAdmins.Healthy || r.SuperAdmins.Message != "1 of 2 operators not cloudflare super admin" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
}

func TestTwoFactorIsCountedOnMatchedAdminsOnly(t *testing.T) {
	r, _ := evaluate(t, admins("alice", "bob", "carol"), []map[string]any{
		member("alice@example.org", "accepted", true, SuperAdministrator, ""),
		member("bob@example.org", "accepted", false, SuperAdministrator, ""),
		member("carol@example.org", "accepted", false, "Administrator", ""),
	}, nil)
	if r.TwoFA.Healthy || r.TwoFA.Message != "1 of 2 operators have 2fa off" {
		t.Errorf("2fa = %+v", r.TwoFA)
	}
}

func TestHashFoldsCaseAndSpaceOnly(t *testing.T) {
	if hasher.Hash(" Alice@Example.org\n") != hasher.Hash("alice@example.org") {
		t.Error("case or surrounding space changed the hash")
	}
	if hasher.Hash("alice+dns@example.org") == hasher.Hash("alice@example.org") {
		t.Error("+tag was folded")
	}
	if (Hasher{Key: []byte("another key")}).Hash("alice@example.org") == hasher.Hash("alice@example.org") {
		t.Error("the key does not change the hash")
	}
}

func TestEveryPageIsRead(t *testing.T) {
	var members []map[string]any
	for i := range 51 {
		members = append(members, member(fmt.Sprintf("m%02d@example.org", i), "accepted", true, SuperAdministrator, ""))
	}
	f := &fakeCloudflare{members: members}
	got, err := newClient(t, f).Members(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 51 {
		t.Errorf("read %v, want one account of 51 members", len(got))
	}
}

func TestAFailedPageIsUnreadable(t *testing.T) {
	var members []map[string]any
	for i := range 51 {
		members = append(members, member(fmt.Sprintf("m%02d@example.org", i), "accepted", true, SuperAdministrator, ""))
	}
	f := &fakeCloudflare{members: members, failPage: 2}
	_, err := newClient(t, f).Members(context.Background())
	if err == nil || err.Error() != "cloudflare unreadable: HTTP 500" {
		t.Errorf("err = %v", err)
	}
}

func TestUnreadableNeverCarriesTheBody(t *testing.T) {
	f := &fakeCloudflare{status: http.StatusForbidden}
	_, err := newClient(t, f).Members(context.Background())
	if err == nil || err.Error() != "cloudflare unreadable: HTTP 403" {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), "secret detail") || strings.Contains(err.Error(), testToken) {
		t.Errorf("err carries the response or token: %v", err)
	}
	c := &Client{Token: testToken, Domain: testZone, Base: "http://127.0.0.1:1"}
	if _, err := c.Members(context.Background()); err == nil || err.Error() != "cloudflare unreadable: no answer" {
		t.Errorf("no answer: err = %v", err)
	}
	g := &fakeCloudflare{}
	c = newClient(t, g)
	c.Domain = "other.example"
	if _, err := c.Members(context.Background()); err == nil || err.Error() != "cloudflare unreadable: zone not visible to the token" {
		t.Errorf("missing zone: err = %v", err)
	}
}

// TestOnlyTheTwoReadsAreMade is the check on what the client may do at
// Cloudflare: GET of the zone list and of the account's members, nothing else.
func TestOnlyTheTwoReadsAreMade(t *testing.T) {
	var members []map[string]any
	for i := range 60 {
		members = append(members, member(fmt.Sprintf("m%02d@example.org", i), "accepted", true, SuperAdministrator, ""))
	}
	f := &fakeCloudflare{members: members}
	if _, err := newClient(t, f).Members(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, req := range f.requests {
		if req != "GET /zones" && req != "GET /accounts/"+accountID+"/members" {
			t.Errorf("request %q is not one of the two reads", req)
		}
	}
	if len(f.requests) != 3 {
		t.Errorf("made %d requests, want 3 (the zone and two pages): %q", len(f.requests), f.requests)
	}
}

// A community domain below the zone apex finds the zone by its suffixes,
// longest first.
func TestTheZoneIsFoundFromASubdomain(t *testing.T) {
	f := &fakeCloudflare{members: []map[string]any{member("a@example.org", "accepted", true, SuperAdministrator, "")}}
	c := newClient(t, f)
	c.Domain = "community.example.org"
	got, err := c.Members(context.Background())
	if err != nil || len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("Members = %v, %v", got, err)
	}
	if f.requests[0] != "GET /zones" || f.requests[1] != "GET /zones" {
		t.Errorf("requests = %q, want two zone lookups first", f.requests)
	}
}

func TestParseMap(t *testing.T) {
	a, b := hasher.Hash("a@example.org"), hasher.Hash("b@example.org")
	got, err := ParseMap(" " + a + "=" + b + " ")
	if err != nil || got[a] != b || len(got) != 1 {
		t.Errorf("ParseMap = %v, %v", got, err)
	}
	for _, bad := range []string{"a@example.org=" + b, a, a + "=" + strings.ToUpper(b)} {
		if _, err := ParseMap(bad); err == nil {
			t.Errorf("ParseMap(%q) accepted", bad)
		} else if strings.Contains(err.Error(), "@") {
			t.Errorf("ParseMap error echoes its input: %v", err)
		}
	}
}

// A delegated subzone's parent is checked too: its account's members can
// point the subzone anywhere, so an admin counts only as a Super
// Administrator of both accounts, with two-factor on in both.
func TestEveryAccountAboveTheDomainIsChecked(t *testing.T) {
	both := func(email string, twoFA bool) map[string]any {
		return member(email, "accepted", twoFA, SuperAdministrator, "")
	}
	f := &fakeCloudflare{
		zones: map[string][]fakeZone{
			"community.example.org": {{"active", "child"}},
			"example.org":           {{"active", "parent"}},
		},
		accounts: map[string][]map[string]any{
			"child":  {both("alice@example.org", true), both("bob@example.org", true)},
			"parent": {both("alice@example.org", true), both("bob@example.org", false), member("carol@example.org", "accepted", true, SuperAdministrator, "")},
		},
	}
	c := newClient(t, f)
	c.Domain = "community.example.org"
	got, err := c.Members(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("Members = %v, %v; want two accounts", got, err)
	}
	l := &logs{}
	r := Evaluate(admins("alice", "bob"), got, hasher, nil, l.printf)
	if !r.SuperAdmins.Healthy {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
	if r.TwoFA.Healthy || r.TwoFA.Message != "1 of 2 operators have 2fa off" {
		t.Errorf("2fa off in the parent's account is not counted: %+v", r.TwoFA)
	}
	// Bob is no Super Administrator of the parent's account: not enough.
	f.accounts["parent"] = []map[string]any{both("alice@example.org", true), member("bob@example.org", "accepted", true, "Administrator", "")}
	got, err = c.Members(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r = Evaluate(admins("alice", "bob"), got, hasher, nil, l.printf)
	if r.SuperAdmins.Healthy || r.SuperAdmins.Message != "1 of 2 operators not cloudflare super admin" {
		t.Errorf("super admins = %+v", r.SuperAdmins)
	}
}

// Two zones in one account read its members once.
func TestOneAccountIsReadOnce(t *testing.T) {
	f := &fakeCloudflare{
		zones: map[string][]fakeZone{
			"community.example.org": {{"active", accountID}},
			"example.org":           {{"active", accountID}},
		},
		accounts: map[string][]map[string]any{accountID: {member("a@example.org", "accepted", true, SuperAdministrator, "")}},
	}
	c := newClient(t, f)
	c.Domain = "community.example.org"
	got, err := c.Members(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("Members = %v, %v; want one account", got, err)
	}
}

// A zone that is not active serves nothing, so its account is not the one
// that matters, even when a stale copy of the name sits in another account.
func TestOnlyAnActiveZoneCounts(t *testing.T) {
	f := &fakeCloudflare{
		zones: map[string][]fakeZone{
			"example.org": {{"pending", "stale"}, {"active", accountID}, {"moved", "old"}},
		},
		accounts: map[string][]map[string]any{accountID: {member("a@example.org", "accepted", true, SuperAdministrator, "")}},
	}
	got, err := newClient(t, f).Members(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("Members = %v, %v; want the active zone's account alone", got, err)
	}
	f.zones["example.org"] = []fakeZone{{"pending", "stale"}}
	if _, err := newClient(t, f).Members(context.Background()); err == nil || err.Error() != "cloudflare unreadable: zone not visible to the token" {
		t.Errorf("only a pending zone: err = %v", err)
	}
}
