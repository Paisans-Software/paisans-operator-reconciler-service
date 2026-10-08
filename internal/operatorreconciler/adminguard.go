// Package adminguard keeps Pocket ID's administrators in the admins group and
// reports whether that group is large enough to survive losing one of them.
//
// See docs/specs/2026-10-08-admin-guard.md. Its one write, adding an
// administrator to admins, is a standing exception to the rule that every
// Pocket ID group change needs a human's approval, granted by the founder on
// 2026-10-08 and recorded in docs/decisions.md. The API key it holds can do
// anything, so the narrowness lives here: nothing in this package removes a
// member, changes a user, or touches a group, and the tests fail if it does.
package adminguard

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

const (
	// Group is the group the guard keeps administrators in. It is fixed,
	// not configured: validate warns when an app reads another one.
	Group = "admins"
	// Minimum is the fewest members admins may have and be healthy.
	Minimum = 2
	// Interval is the time between passes.
	Interval = 2 * time.Hour
	// StaleAfter is how old the last pass may be before /healthz stops
	// trusting it, half an hour past the interval: a pass loop that hung
	// while the HTTP server still answers would otherwise report its last
	// answer for ever.
	StaleAfter = Interval + 30*time.Minute
	// SyntheticUserID is the user Pocket ID creates for its static API key
	// (common/reserved.go:5 at v2.14.0), an administrator that is the
	// guard's own credential rather than a person.
	SyntheticUserID = "00000000-0000-0000-0000-000000000000"
)

// PocketID is the part of the Pocket ID API the guard uses. The only method
// here that writes is SetUserGroups.
type PocketID interface {
	FindGroup(name string) (*pocketid.Group, error)
	Users() ([]pocketid.User, error)
	User(id string) (pocketid.User, error)
	SetUserGroups(userID string, groupIDs []string) error
}

// Result is what one pass found.
type Result struct {
	Healthy bool
	// Message is one line, naming users by username, never by email.
	Message string
	At      time.Time
}

// Guard runs passes and remembers the last one.
type Guard struct {
	API PocketID
	// Standby reports whether the local Pocket ID is a standby, from the
	// marker the standby wrapper writes.
	Standby func() bool
	Now     func() time.Time
	// Log records each write and each pass.
	Log func(format string, args ...any)

	mu   sync.Mutex
	last *Result
}

// Pass runs one pass, remembers its result and returns it.
func (g *Guard) Pass() Result {
	r := g.pass()
	r.At = g.Now()
	g.Log("pass: %s", r.Message)
	g.mu.Lock()
	g.last = &r
	g.mu.Unlock()
	return r
}

// Status is the HTTP status and one line body /healthz serves: the last
// pass, unless there has been none or it is stale.
func (g *Guard) Status() (int, string) {
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

func unhealthy(format string, args ...any) Result {
	return Result{Message: oneLine(fmt.Sprintf(format, args...))}
}

func (g *Guard) pass() Result {
	if g.Standby() {
		return Result{Healthy: true, Message: "standby"}
	}
	group, err := g.API.FindGroup(Group)
	if err != nil {
		return unhealthy("reading groups: %v", err)
	}
	if group == nil {
		return unhealthy("no group named %s", Group)
	}
	users, err := g.API.Users()
	if err != nil {
		return unhealthy("reading users: %v", err)
	}

	members := map[string]string{} // ID to username
	var failures []string
	for _, u := range users {
		if counts(u) && u.InGroup(group.ID) {
			members[u.ID] = u.Username
			continue
		}
		if !eligible(u) {
			continue
		}
		added, err := g.add(u.ID, group.ID)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("could not add %s: %v", u.Username, err))
		case added != nil:
			members[added.ID] = added.Username
		}
	}

	names := make([]string, 0, len(members))
	for _, name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	count := fmt.Sprintf("%s has %d %s", Group, len(names), plural(len(names), "member", "members"))
	if len(names) > 0 {
		count += " (" + strings.Join(names, ", ") + ")"
	}
	if len(failures) > 0 {
		return unhealthy("%s; %s", strings.Join(failures, "; "), count)
	}
	if len(names) < Minimum {
		return unhealthy("%s; at least %d are needed so that losing one administrator does not lock the community out", count, Minimum)
	}
	return Result{Healthy: true, Message: count}
}

// add puts one administrator in the group. The user is read again first and
// the write carries the groups that read found, because the route replaces
// the user's whole set: a group added since the list was read is kept. It
// returns the user when they are a member afterwards, whether this write put
// them there or they joined since the list, and nil when they no longer
// qualify.
func (g *Guard) add(id, groupID string) (*pocketid.User, error) {
	u, err := g.API.User(id)
	if err != nil {
		return nil, err
	}
	if u.InGroup(groupID) {
		if counts(u) {
			return &u, nil
		}
		return nil, nil
	}
	if !eligible(u) {
		return nil, nil
	}
	ids := make([]string, 0, len(u.UserGroups)+1)
	for _, grp := range u.UserGroups {
		ids = append(ids, grp.ID)
	}
	ids = append(ids, groupID)
	if err := g.API.SetUserGroups(u.ID, ids); err != nil {
		g.Log("add %s (%s) to %s: failed: %v", u.Username, u.ID, Group, err)
		return nil, err
	}
	g.Log("add %s (%s) to %s: added", u.Username, u.ID, Group)
	return &u, nil
}

// eligible is an administrator the guard puts in the group: enabled, a
// person rather than the static key's user, and not managed by an LDAP sync,
// which owns that user's groups.
func eligible(u pocketid.User) bool {
	return u.IsAdmin && counts(u) && (u.LdapID == nil || *u.LdapID == "")
}

// counts is a member who counts towards Minimum: enabled and a person.
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
