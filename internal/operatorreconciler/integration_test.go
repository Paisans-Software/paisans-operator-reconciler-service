//go:build pocketid_integration

// This file runs reconciler passes against a real ghcr.io/pocket-id/pocket-id
// container, the version the pocket-id blueprint pins, so what the reconciler
// assumes about the API (the list carries each user's groups and flags, and
// the static key's user is an administrator with a fixed ID) is checked
// against Pocket ID rather than against the fake.
//
//	go test -tags pocketid_integration ./internal/operatorreconciler/
package operatorreconciler_test

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/blueprints"
	"github.com/paisans-software/paisans-stack/internal/config"
	"github.com/paisans-software/paisans-stack/internal/operatorreconciler"
	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

func startPocketID(t *testing.T) *pocketid.Client {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH; skipping the Pocket ID integration test")
	}
	// The foundation names a track, which docker cannot run; set
	// PAISANS_POCKET_ID_IMAGE to a tag on it, as the render package's
	// standby test takes PAISANS_STANDBY_IMAGE.
	image, ok := os.Getenv("PAISANS_POCKET_ID_IMAGE"), true
	if image == "" {
		image, ok = blueprints.DefaultImage(config.BlueprintPocketID, "app")
	}
	if !ok {
		t.Fatal("the pocket-id blueprint names no app image")
	}
	name := fmt.Sprintf("paisans-reconciler-it-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::1411",
		"-e", "APP_URL=http://localhost:1411",
		"-e", "ENCRYPTION_KEY=0123456789abcdef0123456789abcdef",
		"-e", "STATIC_API_KEY="+key,
		image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	out, err = exec.Command("docker", "port", name, "1411").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, out)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(out), "\n")[0])
	for deadline := time.Now().Add(90 * time.Second); ; {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				break
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Fatalf("Pocket ID did not become healthy:\n%s", logs)
		}
		time.Sleep(time.Second)
	}
	return &pocketid.Client{HTTP: &http.Client{}, BaseURL: base, APIKey: key}
}

func TestRealPocketIDIsCheckedAndNotWritten(t *testing.T) {
	c := startPocketID(t)
	var groups []string
	for _, name := range []string{"members", "operators"} {
		g, err := c.CreateGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g.ID)
	}
	alice, err := c.CreateUser(pocketid.NewUser{Username: "alice", Email: ptr("alice@example.org"), FirstName: "Alice", DisplayName: "Alice", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := c.CreateUser(pocketid.NewUser{Username: "bob", Email: ptr("bob@example.org"), FirstName: "Bob", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{alice.ID, bob.ID} {
		if err := c.SetUserGroups(id, groups); err != nil {
			t.Fatal(err)
		}
	}
	pass := func(management string) operatorreconciler.Result {
		g := &operatorreconciler.Reconciler{API: c, Operators: []string{"alice", "bob"}, MemberGroup: "members",
			Management: management, Standby: func() bool { return false }, Now: time.Now, Log: t.Logf}
		return g.Pass()
	}
	// The static key's user is an administrator and never counts.
	if r := pass("pocket-id"); !r.Healthy || !strings.Contains(r.Message, "pocket id administrators: alice") {
		t.Fatalf("pocket-id: %+v", r)
	}
	if r := pass("paisans"); r.Healthy || !strings.Contains(r.Message, "alice is a pocket id administrator") {
		t.Fatalf("paisans: %+v", r)
	}
	got, err := c.User(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IsAdmin || len(got.UserGroups) != 2 {
		t.Errorf("bob changed: %+v", got)
	}
	// Taken out of operators, bob fails check 1.
	if err := c.SetUserGroups(bob.ID, groups[:1]); err != nil {
		t.Fatal(err)
	}
	if r := pass("pocket-id"); r.Healthy || !strings.Contains(r.Message, "operator bob is not in operators") {
		t.Fatalf("bob outside operators: %+v", r)
	}
	// carol holds operators and is not one, so check 3 names her: the real
	// user list carries the groups that check reads.
	if err := c.SetUserGroups(bob.ID, groups); err != nil {
		t.Fatal(err)
	}
	carol, err := c.CreateUser(pocketid.NewUser{Username: "carol", Email: ptr("carol@example.org"), FirstName: "Carol", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetUserGroups(carol.ID, groups); err != nil {
		t.Fatal(err)
	}
	if r := pass("pocket-id"); r.Healthy || !strings.Contains(r.Message, "carol is in operators and not an operator") {
		t.Fatalf("carol in operators: %+v", r)
	}
}

func ptr(s string) *string { return &s }
