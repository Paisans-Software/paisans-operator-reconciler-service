// Command operator-reconciler runs beside Pocket ID in the pocket-id
// blueprint's stack. It reads Pocket ID and writes nothing: it checks that
// every operator is an enabled member in the member group and in operators,
// that every enabled member of operators is an operator, and that every
// Pocket ID administrator is an operator, with none under management:
// paisans, and serves /healthz, which fails while any of them does not hold. See docs/specs/2026-10-14-operators-and-management.md.
//
//	operator-reconciler               run: a pass now, then one every two hours
//	operator-reconciler healthcheck   exit 0 if the running reconciler is alive (/livez)
//
// It reads its environment from the stack's .env:
//
//	STATIC_API_KEY                Pocket ID's static API key
//	PAISANS_RECONCILER_POCKET_ID  Pocket ID's address on the stack's network
//	PAISANS_OPERATORS             the operators' usernames, comma separated
//	PAISANS_MEMBER_GROUP          the community's member group
//	PAISANS_MANAGEMENT            paisans or pocket-id
//
// and, when the deployment checks its DNS provider's account
// (docs/specs/2026-10-13-dns-admin-continuity.md), all of:
//
//	PAISANS_DNS_MEMBERS_TOKEN   a Cloudflare token that reads the account's members
//	PAISANS_DNS_DOMAIN          the community domain, whose zone's account is checked
//	PAISANS_DNS_EMAIL_HASH_KEY  the key every address is hashed under, hex
//	PAISANS_DNS_EMAIL_MAP       hashed pairs for operators whose address differs
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/paisans-software/pocketid-go"

	"github.com/paisans-software/paisans-stack/internal/dnscontinuity"
	"github.com/paisans-software/paisans-stack/internal/operatorreconciler"
)

const (
	listen = ":1412"
	// standbyMarker is written by the pocket-id blueprint's standby wrapper
	// into a directory both containers mount.
	standbyMarker = "/paisans/run/standby"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck("http://127.0.0.1" + listen + "/livez"))
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	key := os.Getenv("STATIC_API_KEY")
	base := os.Getenv("PAISANS_RECONCILER_POCKET_ID")
	if key == "" || base == "" {
		return errors.New("STATIC_API_KEY and PAISANS_RECONCILER_POCKET_ID must both be set; the pocket-id blueprint's .env renders them")
	}
	operators, memberGroup, management, err := checked(os.Getenv)
	if err != nil {
		return err
	}
	g := &operatorreconciler.Reconciler{
		API:         &pocketid.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, BaseURL: base, APIKey: key},
		Operators:   operators,
		MemberGroup: memberGroup,
		Management:  management,
		Standby:     standby,
		Now:         time.Now,
		Log:         log.Printf,
	}
	dns, err := dnsCheck()
	if err != nil {
		return err
	}
	g.DNS = dns
	go func() {
		for {
			time.Sleep(g.Pass().Next())
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		code, body := g.Status()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		fmt.Fprintln(w, body)
	})
	if g.DNS != nil {
		for path, which := range map[string]operatorreconciler.DNSPath{
			"GET /healthz/dns-super-admins": operatorreconciler.DNSSuperAdmins,
			"GET /healthz/dns-2fa":          operatorreconciler.DNSTwoFA,
		} {
			mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
				code, body := g.DNSStatus(which)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(code)
				fmt.Fprintln(w, body)
			})
		}
	}
	// Docker's healthcheck: alive, whatever the checks found. See Reconciler.Live.
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		if !g.Live() {
			http.Error(w, "stale", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "alive")
	})
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// checked reads the three variables that say what a pass checks, and refuses
// to start without them: a reconciler that knew no operators would report a
// deployment healthy that it had not checked.
func checked(getenv func(string) string) (operators []string, memberGroup, management string, err error) {
	for _, name := range strings.Split(getenv("PAISANS_OPERATORS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			operators = append(operators, name)
		}
	}
	memberGroup = strings.TrimSpace(getenv("PAISANS_MEMBER_GROUP"))
	management = strings.TrimSpace(getenv("PAISANS_MANAGEMENT"))
	if len(operators) == 0 || memberGroup == "" {
		return nil, "", "", errors.New("PAISANS_OPERATORS and PAISANS_MEMBER_GROUP must both be set; the pocket-id blueprint's .env renders them")
	}
	if management != operatorreconciler.ManagementPaisans && management != operatorreconciler.ManagementPocketID {
		return nil, "", "", fmt.Errorf("PAISANS_MANAGEMENT is %q, and must be %s or %s; the pocket-id blueprint's .env renders it", management, operatorreconciler.ManagementPaisans, operatorreconciler.ManagementPocketID)
	}
	return operators, memberGroup, management, nil
}

// dnsCheck is the DNS continuity check the environment describes, nil when it
// names no members token: a deployment without one renders none of the four.
func dnsCheck() (*operatorreconciler.DNS, error) {
	token := os.Getenv("PAISANS_DNS_MEMBERS_TOKEN")
	if token == "" {
		return nil, nil
	}
	domain := os.Getenv("PAISANS_DNS_DOMAIN")
	key, err := hex.DecodeString(os.Getenv("PAISANS_DNS_EMAIL_HASH_KEY"))
	if domain == "" || err != nil || len(key) < 32 {
		return nil, errors.New("PAISANS_DNS_MEMBERS_TOKEN is set, so PAISANS_DNS_DOMAIN and PAISANS_DNS_EMAIL_HASH_KEY, at least 32 bytes as hex, must be too; the pocket-id blueprint's .env renders all three")
	}
	mapping, err := dnscontinuity.ParseMap(os.Getenv("PAISANS_DNS_EMAIL_MAP"))
	if err != nil {
		return nil, err
	}
	return &operatorreconciler.DNS{
		Members: &dnscontinuity.Client{Token: token, Domain: domain, HTTP: &http.Client{Timeout: 30 * time.Second}},
		Hasher:  dnscontinuity.Hasher{Key: key},
		Map:     mapping,
	}, nil
}

func standby() bool {
	_, err := os.Stat(standbyMarker)
	return err == nil
}

// healthcheck is Docker's healthcheck: the image has no shell or curl, so the
// binary asks itself. It asks /livez, not /healthz: a deployment whose
// operators do not check out is alive, and the uptime monitor is what reports
// it.
func healthcheck(url string) int {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Print(string(body))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
