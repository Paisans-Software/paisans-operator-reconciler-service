package operatorreconciler_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/dnscontinuity"
	"github.com/paisans-software/paisans-stack/internal/operatorreconciler"
)

// fakeMembers is the DNS provider's members list, counting its reads.
type fakeMembers struct {
	members []dnscontinuity.Member // one account
	err     error
	reads   int
}

func (m *fakeMembers) Members(context.Context) ([][]dnscontinuity.Member, error) {
	m.reads++
	if m.err != nil {
		return nil, m.err
	}
	return [][]dnscontinuity.Member{m.members}, nil
}

var dnsHasher = dnscontinuity.Hasher{Key: []byte("fixture-not-a-secret-hash-key-32")}

func superAdmin(email string, twoFA bool) dnscontinuity.Member {
	return dnscontinuity.Member{Status: "accepted", Email: email, TwoFA: twoFA, SuperAdmin: true}
}

func withDNS(g *operatorreconciler.Reconciler, m *fakeMembers) {
	g.DNS = &operatorreconciler.DNS{Members: m, Hasher: dnsHasher}
}

// twoOperators is alice and bob as operators and carol, a member who is a
// Pocket ID administrator, whom the DNS check does not hold to its rule.
func twoOperators() *fakePocketID {
	return newFake().
		add(operator("a", "alice")).
		add(operator("b", "bob")).
		add(fakeUser{ID: "c", Username: "carol", IsAdmin: true, Email: "carol@example.org", Groups: []string{"gM"}})
}

func TestTheDNSCheckRunsOnThePass(t *testing.T) {
	g, _, log := reconcilerFor(t, twoOperators(), false, "pocket-id")
	m := &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", false)}}
	withDNS(g, m)
	g.Pass()
	if code, body := g.DNSStatus(operatorreconciler.DNSSuperAdmins); code != 200 || body != "2 of 2 operators are cloudflare super admins" {
		t.Errorf("super admins: %d %q", code, body)
	}
	if code, body := g.DNSStatus(operatorreconciler.DNSTwoFA); code != 503 || body != "1 of 2 operators have 2fa off" {
		t.Errorf("2fa: %d %q", code, body)
	}
	if code, body := g.Status(); code != 503 || !strings.Contains(body, "carol") || strings.Contains(body, "cloudflare") {
		t.Errorf("the pass's own status took the DNS check's answer: %d %q", code, body)
	}
	if strings.Contains(log.String(), "@") {
		t.Errorf("the log carries an address: %s", log)
	}
	if !strings.Contains(log.String(), "bob has two-factor authentication off") {
		t.Errorf("the log does not name bob: %s", log)
	}
}

// Only operators are held to the rule: not carol, an administrator who is not
// one, and not a disabled operator.
func TestOnlyEnabledOperatorsAreHeldToTheRule(t *testing.T) {
	f := twoOperators().add(fakeUser{ID: "d", Username: "dave", Disabled: true, Email: "dave@example.org", Groups: []string{"gM", "gO"}})
	g, _, _ := reconcilerFor(t, f, false, "pocket-id")
	g.Operators = append(g.Operators, "dave")
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", true)}})
	g.Pass()
	if code, body := g.DNSStatus(operatorreconciler.DNSSuperAdmins); code != 200 {
		t.Errorf("super admins: %d %q", code, body)
	}
}

func TestAStandbyChecksNoDNS(t *testing.T) {
	f := newFake()
	f.down = true
	g, _, _ := reconcilerFor(t, f, true, "pocket-id")
	m := &fakeMembers{}
	withDNS(g, m)
	g.Pass()
	if m.reads != 0 {
		t.Errorf("a standby read the DNS provider %d times", m.reads)
	}
	if code, body := g.DNSStatus(operatorreconciler.DNSSuperAdmins); code != 200 || body != "standby" {
		t.Errorf("standby: %d %q", code, body)
	}
}

func TestTheDNSCheckRunsWithoutAnOperatorsGroup(t *testing.T) {
	f := twoOperators()
	delete(f.groups, "gO")
	g, _, _ := reconcilerFor(t, f, false, "pocket-id")
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true)}})
	g.Pass()
	if code, body := g.DNSStatus(operatorreconciler.DNSSuperAdmins); code != 503 || body != "1 of 2 operators not cloudflare super admin" {
		t.Errorf("super admins: %d %q", code, body)
	}
}

func TestUnreadableSourcesFailBothDNSPaths(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakePocketID, m *fakeMembers)
		want  string
	}{
		{"pocket id", func(f *fakePocketID, _ *fakeMembers) { f.down = true }, "pocket id unreadable"},
		{"cloudflare", func(_ *fakePocketID, m *fakeMembers) {
			m.err = &dnscontinuity.Unreadable{Status: "HTTP 403"}
		}, "cloudflare unreadable: HTTP 403"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, m := twoOperators(), &fakeMembers{}
			c.setup(f, m)
			g, _, _ := reconcilerFor(t, f, false, "pocket-id")
			withDNS(g, m)
			g.Pass()
			for _, p := range []operatorreconciler.DNSPath{operatorreconciler.DNSSuperAdmins, operatorreconciler.DNSTwoFA} {
				if code, body := g.DNSStatus(p); code != 503 || body != c.want {
					t.Errorf("path %d: %d %q, want 503 %q", p, code, body, c.want)
				}
			}
		})
	}
}

func TestDNSStartingAndStale(t *testing.T) {
	g, c, _ := reconcilerFor(t, twoOperators(), false, "pocket-id")
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", true)}})
	if code, body := g.DNSStatus(operatorreconciler.DNSTwoFA); code != 503 || body != "starting" {
		t.Errorf("before a pass: %d %q", code, body)
	}
	g.Pass()
	c.now = c.now.Add(operatorreconciler.StaleAfter + time.Minute)
	if code, body := g.DNSStatus(operatorreconciler.DNSTwoFA); code != 503 || !strings.HasPrefix(body, "stale") {
		t.Errorf("an old pass: %d %q", code, body)
	}
}

func TestWithoutADNSCheckThePassIsUnchanged(t *testing.T) {
	g, _, _ := reconcilerFor(t, twoOperators(), false, "pocket-id")
	if r := g.Pass(); r.DNS != nil {
		t.Errorf("a reconciler with no DNS check reported one: %+v", r.DNS)
	}
}
