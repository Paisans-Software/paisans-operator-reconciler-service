package adminreconciler_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/adminreconciler"
	"github.com/paisans-software/paisans-stack/internal/dnscontinuity"
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

func withDNS(g *adminreconciler.Reconciler, m *fakeMembers) {
	g.DNS = &adminreconciler.DNS{Members: m, Hasher: dnsHasher}
}

func twoAdmins() *fakePocketID {
	return newFake().
		add(fakeUser{ID: "a", Username: "alice", IsAdmin: true, Email: "alice@example.org", Groups: []string{"gA"}}).
		add(fakeUser{ID: "b", Username: "bob", IsAdmin: true, Email: "bob@example.org", Groups: []string{"gA"}}).
		add(fakeUser{ID: "c", Username: "carol", Email: "carol@example.org"})
}

func TestTheDNSCheckRunsOnThePass(t *testing.T) {
	g, _, log := reconcilerFor(t, twoAdmins(), false)
	m := &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", false)}}
	withDNS(g, m)
	g.Pass()
	if code, body := g.DNSStatus(adminreconciler.DNSSuperAdmins); code != 200 || body != "2 of 2 admins are cloudflare super admins" {
		t.Errorf("super admins: %d %q", code, body)
	}
	if code, body := g.DNSStatus(adminreconciler.DNSTwoFA); code != 503 || body != "1 of 2 admins have 2fa off" {
		t.Errorf("2fa: %d %q", code, body)
	}
	if code, _ := g.Status(); code != 200 {
		t.Errorf("the admins group's own status changed: %d", code)
	}
	if strings.Contains(log.String(), "@") {
		t.Errorf("the log carries an address: %s", log)
	}
	if !strings.Contains(log.String(), "bob has two-factor authentication off") {
		t.Errorf("the log does not name bob: %s", log)
	}
}

func TestADisabledOrNonAdminUserIsNotHeldToTheRule(t *testing.T) {
	f := twoAdmins().add(fakeUser{ID: "d", Username: "dave", IsAdmin: true, Disabled: true, Email: "dave@example.org"})
	g, _, _ := reconcilerFor(t, f, false)
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", true)}})
	g.Pass()
	if code, body := g.DNSStatus(adminreconciler.DNSSuperAdmins); code != 200 {
		t.Errorf("super admins: %d %q", code, body)
	}
}

func TestAStandbyChecksNoDNS(t *testing.T) {
	f := newFake()
	f.down = true
	g, _, _ := reconcilerFor(t, f, true)
	m := &fakeMembers{}
	withDNS(g, m)
	g.Pass()
	if m.reads != 0 {
		t.Errorf("a standby read the DNS provider %d times", m.reads)
	}
	if code, body := g.DNSStatus(adminreconciler.DNSSuperAdmins); code != 200 || body != "standby" {
		t.Errorf("standby: %d %q", code, body)
	}
}

func TestTheDNSCheckRunsWithoutAnAdminsGroup(t *testing.T) {
	f := twoAdmins()
	delete(f.groups, "gA")
	g, _, _ := reconcilerFor(t, f, false)
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true)}})
	g.Pass()
	if code, body := g.DNSStatus(adminreconciler.DNSSuperAdmins); code != 503 || body != "1 of 2 admins not cloudflare super admin" {
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
			f, m := twoAdmins(), &fakeMembers{}
			c.setup(f, m)
			g, _, _ := reconcilerFor(t, f, false)
			withDNS(g, m)
			g.Pass()
			for _, p := range []adminreconciler.DNSPath{adminreconciler.DNSSuperAdmins, adminreconciler.DNSTwoFA} {
				if code, body := g.DNSStatus(p); code != 503 || body != c.want {
					t.Errorf("path %d: %d %q, want 503 %q", p, code, body, c.want)
				}
			}
		})
	}
}

func TestDNSStartingAndStale(t *testing.T) {
	g, c, _ := reconcilerFor(t, twoAdmins(), false)
	withDNS(g, &fakeMembers{members: []dnscontinuity.Member{superAdmin("alice@example.org", true), superAdmin("bob@example.org", true)}})
	if code, body := g.DNSStatus(adminreconciler.DNSTwoFA); code != 503 || body != "starting" {
		t.Errorf("before a pass: %d %q", code, body)
	}
	g.Pass()
	c.now = c.now.Add(adminreconciler.StaleAfter + time.Minute)
	if code, body := g.DNSStatus(adminreconciler.DNSTwoFA); code != 503 || !strings.HasPrefix(body, "stale") {
		t.Errorf("an old pass: %d %q", code, body)
	}
}

func TestWithoutADNSCheckThePassIsUnchanged(t *testing.T) {
	g, _, _ := reconcilerFor(t, twoAdmins(), false)
	if r := g.Pass(); r.DNS != nil {
		t.Errorf("a reconciler with no DNS check reported one: %+v", r.DNS)
	}
}
