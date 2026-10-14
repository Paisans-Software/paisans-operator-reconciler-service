// Package dnscontinuity checks that every operator is a Super
// Administrator of every Cloudflare account holding the deployment's zone or
// a zone above it, and that each of them has two-factor authentication on.
//
// See docs/specs/2026-10-13-dns-admin-continuity.md. It reads Cloudflare and
// never writes there: its only requests are the two GETs in Client, and the
// tests fail on any other. Its results name nobody. They are counts, because
// they are pushed to the health page; the log names the operators who
// fail by Pocket ID username, and nothing here ever prints an email address.
package dnscontinuity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Minimum is the fewest operators who must be Super Administrators,
	// validate's floor of operators: one is a single loss from none.
	Minimum = 2
	// SuperAdministrator is the role, and the permission group, that can
	// manage an account's members ("Can edit any Cloudflare setting, make
	// purchases, update billing, manage members",
	// https://developers.cloudflare.com/fundamentals/manage-members/roles/,
	// read 2026-10-13). Observed under this name in both roles and policies
	// of a real account's members on 2026-10-13.
	SuperAdministrator = "Super Administrator - All Privileges"
	// accountScope begins the key of a resource group scoped to a whole
	// account, observed as com.cloudflare.api.account.<id> on 2026-10-13.
	accountScope = "com.cloudflare.api.account."
	// API is Cloudflare's API root.
	API = "https://api.cloudflare.com/client/v4"
	// perPage is the members list's maximum page size
	// (https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/).
	perPage = 50
)

// Member is the part of an account member the check reads.
type Member struct {
	Status     string
	Email      string
	TwoFA      bool
	SuperAdmin bool
}

// Members lists the members of every Cloudflare account that holds a zone
// above the community's domain: one list per account, each account once, the
// most specific zone's first.
type Members interface {
	Members(ctx context.Context) ([][]Member, error)
}

// Client is Cloudflare's API, holding a token with Account Settings Read on
// the account and Zone Read on the zone, and nothing else.
//
//   - find the accounts: GET /zones?name=<suffix>, whose zone carries
//     account.id and status
//     https://developers.cloudflare.com/api/resources/zones/methods/list/
//   - list members:     GET /accounts/{account_id}/members?page=&per_page=50
//     https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/
//
// Pages are read up to result_info.total_pages, which the reference omits but
// a real response carries (observed 2026-10-13).
type Client struct {
	Token string
	// Domain is the community's domain. The zone holding it is found by
	// asking about each suffix, longest first, as internal/dns finds a zone,
	// because the domain need not be a zone apex.
	Domain string
	// Base is the API root, API unless a test points it elsewhere.
	Base string
	HTTP *http.Client
}

// Unreadable is a Cloudflare read that failed. Its message is the status or
// "no answer" and never the response body, which could carry anything.
type Unreadable struct{ Status string }

func (e *Unreadable) Error() string { return "cloudflare unreadable: " + e.Status }

type envelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type cfMember struct {
	Status string `json:"status"`
	Email  string `json:"email"`
	User   struct {
		Email string `json:"email"`
		TwoFA bool   `json:"two_factor_authentication_enabled"`
	} `json:"user"`
	Roles []struct {
		Name string `json:"name"`
	} `json:"roles"`
	Policies []struct {
		Access           string `json:"access"`
		PermissionGroups []struct {
			Name string `json:"name"`
		} `json:"permission_groups"`
		ResourceGroups []struct {
			Scope struct {
				Key string `json:"key"`
			} `json:"scope"`
		} `json:"resource_groups"`
	} `json:"policies"`
}

// superAdministrator is a member holding the role, by either of the two
// shapes a member carries: a role of that name, or a policy allowing a
// permission group of that name over the whole account. Either alone counts,
// so an account that drops one shape keeps passing.
func (m cfMember) superAdministrator() bool {
	for _, r := range m.Roles {
		if r.Name == SuperAdministrator {
			return true
		}
	}
	for _, p := range m.Policies {
		if p.Access != "allow" {
			continue
		}
		granted := false
		for _, g := range p.PermissionGroups {
			if g.Name == SuperAdministrator {
				granted = true
			}
		}
		if !granted {
			continue
		}
		for _, rg := range p.ResourceGroups {
			if strings.HasPrefix(rg.Scope.Key, accountScope) {
				return true
			}
		}
	}
	return false
}

// Members reads the accounts of every zone above Domain and every member of
// each.
func (c *Client) Members(ctx context.Context) ([][]Member, error) {
	accounts, err := c.accounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([][]Member, 0, len(accounts))
	for _, account := range accounts {
		members, err := c.members(ctx, account)
		if err != nil {
			return nil, err
		}
		out = append(out, members)
	}
	return out, nil
}

// members is every member of one account.
func (c *Client) members(ctx context.Context, account string) ([]Member, error) {
	var out []Member
	for page := 1; ; page++ {
		var members []cfMember
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}
		pages, err := c.get(ctx, "/accounts/"+url.PathEscape(account)+"/members", query, &members)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			email := m.User.Email
			if email == "" {
				email = m.Email
			}
			out = append(out, Member{Status: m.Status, Email: email, TwoFA: m.User.TwoFA, SuperAdmin: m.superAdministrator()})
		}
		if page >= pages || len(members) == 0 {
			return out, nil
		}
	}
}

// accounts is the account of every active zone that holds Domain or a name
// above it, each once, the most specific zone's first: every suffix of
// Domain is asked about, longest first, the bare top level label never.
//
// All of them, not only the zone that serves Domain's records, because the
// account holding a parent zone controls the delegation to a child: its
// members can point the child's nameservers anywhere. A zone that is not
// active (pending, moved, deactivated) serves nothing, and the same name can
// be pending in more than one account, so only an active zone counts. A
// suffix the token cannot see answers with no zones, which reads the same as
// no zone at all, so the token needs Zone Read on every zone above Domain.
func (c *Client) accounts(ctx context.Context) ([]string, error) {
	labels := strings.Split(strings.TrimSuffix(c.Domain, "."), ".")
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Account struct {
				ID string `json:"id"`
			} `json:"account"`
		}
		if _, err := c.get(ctx, "/zones", url.Values{"name": {candidate}, "status": {"active"}}, &zones); err != nil {
			return nil, err
		}
		for _, z := range zones {
			if !strings.EqualFold(z.Name, candidate) || z.Status != "active" || z.Account.ID == "" {
				continue
			}
			if !seen[z.Account.ID] {
				seen[z.Account.ID] = true
				out = append(out, z.Account.ID)
			}
		}
	}
	if len(out) == 0 {
		return nil, &Unreadable{Status: "zone not visible to the token"}
	}
	return out, nil
}

// get makes one GET and decodes its result, returning result_info's
// total_pages, 1 when absent.
func (c *Client) get(ctx context.Context, path string, query url.Values, into any) (int, error) {
	base := c.Base
	if base == "" {
		base = API
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path+"?"+query.Encode(), nil)
	if err != nil {
		return 0, &Unreadable{Status: "bad request"}
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, &Unreadable{Status: "no answer"}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, &Unreadable{Status: "no answer"}
	}
	if resp.StatusCode != http.StatusOK {
		return 0, &Unreadable{Status: "HTTP " + strconv.Itoa(resp.StatusCode)}
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil || !env.Success {
		return 0, &Unreadable{Status: "unexpected response"}
	}
	if err := json.Unmarshal(env.Result, into); err != nil {
		return 0, &Unreadable{Status: "unexpected response"}
	}
	if env.ResultInfo == nil || env.ResultInfo.TotalPages < 1 {
		return 1, nil
	}
	return env.ResultInfo.TotalPages, nil
}

// Hasher is the keyed hash every address is compared under, so that no
// Cloudflare address is rendered to a host: HMAC-SHA256 of the address
// lowercased with surrounding space trimmed, as lowercase hex. Nothing else
// is folded; folding +tag or dots would match two different people.
type Hasher struct{ Key []byte }

// Hash is an address's keyed hash.
func (h Hasher) Hash(address string) string {
	mac := hmac.New(sha256.New, h.Key)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(address))))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseMap reads PAISANS_DNS_EMAIL_MAP: space separated pairs of
// <hash of the pocket id email>=<hash of the cloudflare address>.
func ParseMap(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Fields(s) {
		from, to, ok := strings.Cut(pair, "=")
		if !ok || !hexHash(from) || !hexHash(to) {
			return nil, errors.New("PAISANS_DNS_EMAIL_MAP: every entry must be two 64 character hex hashes joined by =")
		}
		out[from] = to
	}
	return out, nil
}

func hexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// Admin is one operator the check holds to the rule, by their Pocket ID
// username and address.
type Admin struct {
	Username string
	// Email is the Pocket ID email, empty when the user has none.
	Email string
}

// Check is one monitor's answer.
type Check struct {
	Healthy bool
	Message string
}

// Result is what one check found, for each of the two monitors.
type Result struct {
	SuperAdmins Check
	TwoFA       Check
}

// Failed is both monitors failing for the same reason.
func Failed(reason string) Result {
	c := Check{Message: reason}
	return Result{SuperAdmins: c, TwoFA: c}
}

// Evaluate holds every operator to the rule against the members of
// every account read: an operator counts only as a Super Administrator
// of each of them, and with two-factor authentication on in each. Mapping is
// keyed and valued by hash: an operator whose Pocket ID email's hash is
// mapped is expected at the mapped hash, and otherwise at their own. Members
// who match no operator are not counted. log receives one line per
// failing operator, by username.
func Evaluate(admins []Admin, accounts [][]Member, h Hasher, mapping map[string]string, log func(string, ...any)) Result {
	type state struct{ super, pending, twoFA bool }
	perAccount := make([]map[string]state, 0, len(accounts))
	for _, members := range accounts {
		byHash := map[string]state{}
		for _, m := range members {
			key := h.Hash(m.Email)
			s := byHash[key]
			switch {
			case m.Status == "accepted" && m.SuperAdmin:
				s.super = true
				s.twoFA = s.twoFA || m.TwoFA
			case m.Status == "pending":
				s.pending = true
			}
			byHash[key] = s
		}
		perAccount = append(perAccount, byHash)
	}
	// across is an address's state over every account: a Super Administrator
	// only of all, with two-factor on only if on in all, and pending when
	// pending in an account it is not yet a Super Administrator of.
	across := func(key string) state {
		out := state{super: len(perAccount) > 0, twoFA: true}
		for _, byHash := range perAccount {
			s := byHash[key]
			out.super = out.super && s.super
			out.twoFA = out.twoFA && s.twoFA
			out.pending = out.pending || (!s.super && s.pending)
		}
		return out
	}

	var failing, pending, matched, twoFAOff int
	for _, a := range admins {
		if strings.TrimSpace(a.Email) == "" {
			failing++
			log("dns: %s has no email and no mapping, so no cloudflare membership can match them", a.Username)
			continue
		}
		expected := h.Hash(a.Email)
		if to, ok := mapping[expected]; ok {
			expected = to
		}
		s := across(expected)
		switch {
		case s.super:
			matched++
			if !s.twoFA {
				twoFAOff++
				log("dns: %s has two-factor authentication off at cloudflare", a.Username)
			}
		case s.pending:
			failing++
			pending++
			log("dns: %s has a cloudflare invitation that is still pending", a.Username)
		default:
			failing++
			log("dns: %s is not an accepted cloudflare super admin, at their expected address, of every account holding the zone", a.Username)
		}
	}

	n := len(admins)
	var r Result
	switch {
	case failing > 0:
		msg := fmt.Sprintf("%d of %d operators not cloudflare super admin", failing, n)
		if pending > 0 {
			msg += fmt.Sprintf(" (%d pending)", pending)
		}
		r.SuperAdmins = Check{Message: msg}
	case matched < Minimum:
		r.SuperAdmins = Check{Message: fmt.Sprintf("%d of %d operators are cloudflare super admins; at least %d are needed", matched, n, Minimum)}
	default:
		r.SuperAdmins = Check{Healthy: true, Message: fmt.Sprintf("%d of %d operators are cloudflare super admins", matched, n)}
	}
	if twoFAOff > 0 {
		r.TwoFA = Check{Message: fmt.Sprintf("%d of %d operators have 2fa off", twoFAOff, matched)}
	} else {
		r.TwoFA = Check{Healthy: true, Message: fmt.Sprintf("%d of %d operators have 2fa on", matched, matched)}
	}
	return r
}
