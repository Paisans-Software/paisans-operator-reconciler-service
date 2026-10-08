//go:build pocketid_integration

// This file runs one guard pass against a real ghcr.io/pocket-id/pocket-id
// container, the version the pocket-id kind pins, so what the guard assumes
// about the API (the list carries each user's groups, the static key's user is
// an administrator with a fixed ID, and the user-groups route replaces a
// user's set) is checked against Pocket ID rather than against the fake.
//
//	go test -tags pocketid_integration ./internal/adminguard/
package adminguard_test

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paisans-software/paisans-stack/internal/adminguard"
	"github.com/paisans-software/paisans-stack/internal/config"
	"github.com/paisans-software/paisans-stack/internal/kinds"
	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

func startPocketID(t *testing.T) *pocketid.Client {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH; skipping the Pocket ID integration test")
	}
	image, ok := kinds.DefaultImage(config.KindPocketID, "app")
	if !ok {
		t.Fatal("the pocket-id kind names no app image")
	}
	name := fmt.Sprintf("paisans-guard-it-%d", time.Now().UnixNano())
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

func TestRealPocketIDAdministratorIsAdded(t *testing.T) {
	c := startPocketID(t)
	admins, err := c.CreateGroup("admins")
	if err != nil {
		t.Fatal(err)
	}
	editors, err := c.CreateGroup("editors")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := c.CreateUser(pocketid.NewUser{Username: "alice", Email: ptr("alice@example.org"), FirstName: "Alice", DisplayName: "Alice", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := c.CreateUser(pocketid.NewUser{Username: "bob", Email: ptr("bob@example.org"), FirstName: "Bob", DisplayName: "Bob", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetUserGroups(alice.ID, []string{admins.ID}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetUserGroups(bob.ID, []string{editors.ID}); err != nil {
		t.Fatal(err)
	}

	g := &adminguard.Guard{API: c, Standby: func() bool { return false }, Now: time.Now, Log: t.Logf}
	r := g.Pass()
	if !r.Healthy || !strings.Contains(r.Message, "2 members (alice, bob)") {
		t.Fatalf("pass: %+v", r)
	}

	got, err := c.User(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.InGroup(admins.ID) || !got.InGroup(editors.ID) {
		t.Errorf("bob's groups after the pass: %+v, want admins and editors", got.UserGroups)
	}
	synthetic, err := c.User(adminguard.SyntheticUserID)
	if err != nil {
		t.Fatal(err)
	}
	if !synthetic.IsAdmin || synthetic.InGroup(admins.ID) {
		t.Errorf("the static key's user: admin %v, in admins %v; want an administrator left out", synthetic.IsAdmin, synthetic.InGroup(admins.ID))
	}
}

func ptr(s string) *string { return &s }
