// Package operatorreconciler checks Pocket ID against the operators that
// paisans-stack.yaml declares, and writes nothing.
//
// See docs/specs/2026-10-14-operators-and-management.md. Pocket ID is the
// record of who is a member of the community; the operators section is the
// record of who runs the machines. A pass holds the two to each other: every
// operator is an enabled member in the member group and in operators, every
// enabled member of operators is an operator, and every Pocket ID
// administrator is an operator, with none at all under management: paisans. The API key it holds can do anything, so the
// narrowness lives here: its only requests are the GETs in PocketID, and the
// tests fail on any other method.
package operatorreconciler

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paisans-software/paisans-stack/internal/dnscontinuity"
	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

const (
	// OperatorsGroup is the group every operator is in: apply puts them
	// there, and a pass checks it by name. It is blueprints.OperatorsGroup,
	// spelled here so the reconciler's image holds no blueprint.
	OperatorsGroup = "operators"
	// ManagementPaisans is the management under which nobody is a Pocket ID
	// administrator, blueprints.ManagementPaisans.
	ManagementPaisans = "paisans"
	// ManagementPocketID is the management under which the operators are
	// Pocket ID's administrators, blueprints.ManagementPocketID.
	ManagementPocketID = "pocket-id"
	// Interval is the time between passes.
	Interval = 2 * time.Hour
	// RetryAfter is the wait after a pass that could not read Pocket ID. The
	// reconciler and Pocket ID start together, so the first pass can find it still
	// starting, and a two hour wait would hold that answer for two hours.
	RetryAfter = time.Minute
	// StaleAfter is how old the last pass may be before /healthz stops
	// trusting it, half an hour past the interval: a pass loop that hung
	// while the HTTP server still answers would otherwise report its last
	// answer for ever.
	StaleAfter = Interval + 30*time.Minute
	// SyntheticUserID is the user Pocket ID creates for its static API key
	// (common/reserved.go:5 at v2.14.0), an administrator that is the
	// reconciler's own credential rather than a person.
	SyntheticUserID = "00000000-0000-0000-0000-000000000000"
)

// PocketID is the part of the Pocket ID API the reconciler uses. Both are
// reads.
type PocketID interface {
	FindGroup(name string) (*pocketid.Group, error)
	Users() ([]pocketid.User, error)
}

// Result is what one pass found.
type Result struct {
	Healthy bool
	// Message is one line, naming users by username, never by email.
	Message string
	At      time.Time
	// Retry is set when the pass could not read Pocket ID, and the next one
	// should come after RetryAfter rather than Interval.
	Retry bool
	// DNS is what the DNS continuity check found, nil when the reconciler has
	// no DNS check or is on a standby.
	DNS *dnscontinuity.Result
	// standby is set when the pass found this instance a standby.
	standby bool
}

// Next is how long to wait before the pass after r.
func (r Result) Next() time.Duration {
	if r.Retry {
		return RetryAfter
	}
	return Interval
}

// Reconciler runs passes and remembers the last one.
type Reconciler struct {
	API PocketID
	// Operators is the usernames of the operators paisans-stack.yaml
	// declares, from PAISANS_OPERATORS.
	Operators []string
	// MemberGroup is the community's member group, from
	// PAISANS_MEMBER_GROUP.
	MemberGroup string
	// Management is ManagementPaisans or ManagementPocketID, from
	// PAISANS_MANAGEMENT.
	Management string
	// Standby reports whether the local Pocket ID is a standby, from the
	// marker the standby wrapper writes.
	Standby func() bool
	Now     func() time.Time
	// Log records each pass and each failure, by username.
	Log func(format string, args ...any)
	// DNS is the DNS continuity check, nil when the deployment renders none
	// (docs/specs/2026-10-13-dns-admin-continuity.md).
	DNS *DNS

	mu   sync.Mutex
	last *Result
}

// DNS is the DNS continuity check: the account's members, and the keyed
// hash and mapping every address is compared under. It only reads.
type DNS struct {
	Members dnscontinuity.Members
	Hasher  dnscontinuity.Hasher
	// Map is hash of a Pocket ID email to hash of the address that operator
	// uses at the DNS provider, for the operators whose addresses differ.
	Map map[string]string
}

// Pass runs one pass, remembers its result and returns it.
func (g *Reconciler) Pass() Result {
	r := g.pass()
	if g.DNS != nil && !r.standby {
		d := g.dns()
		r.DNS = &d
		g.Log("dns: super admins: %s; 2fa: %s", d.SuperAdmins.Message, d.TwoFA.Message)
	}
	r.At = g.Now()
	g.Log("pass: %s", r.Message)
	g.mu.Lock()
	g.last = &r
	g.mu.Unlock()
	return r
}

// Live reports whether the pass loop is running: true before the first pass
// and whatever the last one found, false only once it is stale. Docker's
// healthcheck reads this rather than Status, so apply's health gate does not
// hold a deployment back on operators apply has not made yet. The uptime
// monitor's per site check of this service reads it too, and the operators
// heartbeat beside it pushes Status (internal/render/operatorsheartbeat.go).
func (g *Reconciler) Live() bool {
	g.mu.Lock()
	last := g.last
	g.mu.Unlock()
	return last == nil || g.Now().Sub(last.At) <= StaleAfter
}

// Status is the HTTP status and one line body /healthz serves: the last
// pass, unless there has been none or it is stale.
func (g *Reconciler) Status() (int, string) {
	g.mu.Lock()
	last := g.last
	g.mu.Unlock()
	if last == nil {
		return http.StatusServiceUnavailable, "starting"
	}
	if g.Now().Sub(last.At) > StaleAfter {
		return http.StatusServiceUnavailable, fmt.Sprintf("stale: the last pass finished at %s", last.At.UTC().Format(time.RFC3339))
	}
	if !last.Healthy {
		return http.StatusServiceUnavailable, last.Message
	}
	return http.StatusOK, last.Message
}

// DNSPath names one of the DNS check's two answers.
type DNSPath int

const (
	DNSSuperAdmins DNSPath = iota
	DNSTwoFA
)

// DNSStatus is the HTTP status and one line body of one of the DNS check's
// paths, with /healthz's contract: standby on a standby, starting before the
// first pass, stale after StaleAfter.
func (g *Reconciler) DNSStatus(path DNSPath) (int, string) {
	g.mu.Lock()
	last := g.last
	g.mu.Unlock()
	if last == nil {
		return http.StatusServiceUnavailable, "starting"
	}
	if g.Now().Sub(last.At) > StaleAfter {
		return http.StatusServiceUnavailable, fmt.Sprintf("stale: the last pass finished at %s", last.At.UTC().Format(time.RFC3339))
	}
	if last.DNS == nil {
		return http.StatusOK, "standby"
	}
	c := last.DNS.SuperAdmins
	if path == DNSTwoFA {
		c = last.DNS.TwoFA
	}
	if !c.Healthy {
		return http.StatusServiceUnavailable, oneLine(c.Message)
	}
	return http.StatusOK, oneLine(c.Message)
}

// dns holds every operator to the DNS rule, by their Pocket ID address,
// found by username. It reads the users itself rather than sharing the
// pass's read, so that a pass that stopped early still checks the zone. An
// operator with no enabled account is left out: check 1 of the pass reports
// them.
func (g *Reconciler) dns() dnscontinuity.Result {
	users, err := g.API.Users()
	if err != nil {
		return dnscontinuity.Failed("pocket id unreadable")
	}
	byName := map[string]pocketid.User{}
	for _, u := range users {
		byName[u.Username] = u
	}
	var operators []dnscontinuity.Admin
	for _, name := range g.sortedOperators() {
		u, ok := byName[name]
		if !ok || !counts(u) {
			continue
		}
		a := dnscontinuity.Admin{Username: u.Username}
		if u.Email != nil {
			a.Email = *u.Email
		}
		operators = append(operators, a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	members, err := g.DNS.Members.Members(ctx)
	if err != nil {
		return dnscontinuity.Failed(err.Error())
	}
	return dnscontinuity.Evaluate(operators, members, g.DNS.Hasher, g.DNS.Map, g.Log)
}

func unhealthy(format string, args ...any) Result {
	return Result{Message: oneLine(fmt.Sprintf(format, args...))}
}

func (g *Reconciler) sortedOperators() []string {
	out := slices.Clone(g.Operators)
	sort.Strings(out)
	return out
}

// pass reads Pocket ID once and holds it to the three checks. A group that
// does not exist is a failure of its own rather than one per operator.
func (g *Reconciler) pass() Result {
	if g.Standby() {
		return Result{Healthy: true, Message: "standby", standby: true}
	}
	users, err := g.API.Users()
	if err != nil {
		r := unhealthy("reading users: %v", err)
		r.Retry = true
		return r
	}
	groups := map[string]*pocketid.Group{}
	for _, name := range []string{g.MemberGroup, OperatorsGroup} {
		grp, err := g.API.FindGroup(name)
		if err != nil {
			r := unhealthy("reading groups: %v", err)
			r.Retry = true
			return r
		}
		groups[name] = grp
	}
	var failures []string
	for _, name := range []string{g.MemberGroup, OperatorsGroup} {
		if groups[name] == nil {
			failures = append(failures, "no group named "+name)
		}
	}

	// 1. Every operator is an enabled member, in the member group and in
	// operators.
	byName := map[string]pocketid.User{}
	for _, u := range users {
		byName[u.Username] = u
	}
	operators := g.sortedOperators()
	for _, name := range operators {
		u, ok := byName[name]
		switch {
		case !ok:
			failures = append(failures, "operator "+name+" has no pocket id account")
			continue
		case u.Disabled:
			failures = append(failures, "operator "+name+" is disabled")
			continue
		}
		var outside []string
		for _, group := range []string{g.MemberGroup, OperatorsGroup} {
			if grp := groups[group]; grp != nil && !u.InGroup(grp.ID) {
				outside = append(outside, group)
			}
		}
		if len(outside) > 0 {
			failures = append(failures, "operator "+name+" is not in "+strings.Join(outside, " or "))
		}
	}

	// 3, read here beside 1. Every enabled member of operators is an
	// operator. An operator taken out of the yaml keeps the group until
	// someone removes it at Pocket ID, and every app that reads operators
	// for operator access would still grant it, so the pass names them. A
	// missing group is reported once above, not once per user.
	if grp := groups[OperatorsGroup]; grp != nil {
		var extra []string
		for _, u := range users {
			if counts(u) && u.InGroup(grp.ID) && !slices.Contains(operators, u.Username) {
				extra = append(extra, u.Username)
			}
		}
		sort.Strings(extra)
		for _, name := range extra {
			failures = append(failures, name+" is in operators and not an operator")
		}
	}

	// 2. Every enabled Pocket ID administrator is an operator, and under
	// management: paisans there is none.
	var admins []string
	for _, u := range users {
		if !u.IsAdmin || !counts(u) {
			continue
		}
		admins = append(admins, u.Username)
		switch {
		case g.Management == ManagementPaisans:
			failures = append(failures, u.Username+" is a pocket id administrator, and under management paisans nobody is")
		case !slices.Contains(operators, u.Username):
			failures = append(failures, u.Username+" is a pocket id administrator and not an operator")
		}
	}
	sort.Strings(admins)

	if len(failures) > 0 {
		for _, f := range failures {
			g.Log("fail: %s", f)
		}
		return unhealthy("%s", strings.Join(failures, "; "))
	}
	msg := fmt.Sprintf("%d %s, each a member (%s)", len(operators), plural(len(operators), "operator", "operators"), strings.Join(operators, ", "))
	if len(admins) == 0 {
		msg += "; no pocket id administrators"
	} else {
		msg += "; pocket id administrators: " + strings.Join(admins, ", ")
	}
	return Result{Healthy: true, Message: msg}
}

// counts is a user who is a person and enabled: not disabled, and not the
// static key's user, which is the reconciler's own credential.
func counts(u pocketid.User) bool {
	return !u.Disabled && u.ID != SyntheticUserID
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
