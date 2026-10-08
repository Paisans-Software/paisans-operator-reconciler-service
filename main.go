// Command admin-guard runs beside Pocket ID in the pocket-id kind's stack. It
// keeps Pocket ID's administrators in the admins group and serves /healthz,
// which fails while that group has fewer than two members. See
// docs/specs/2026-10-08-admin-guard.md.
//
//	admin-guard               run: a pass now, then one every two hours
//	admin-guard healthcheck   exit 0 if the running guard answers 200
//
// It reads its environment from the stack's .env:
//
//	STATIC_API_KEY             Pocket ID's static API key
//	PAISANS_GUARD_POCKET_ID    Pocket ID's address on the stack's network
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/paisans-software/paisans-stack/internal/adminguard"
	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

const (
	listen = ":1412"
	// standbyMarker is written by the pocket-id kind's standby wrapper into a
	// directory both containers mount.
	standbyMarker = "/paisans/run/standby"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck("http://127.0.0.1" + listen + "/healthz"))
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	key := os.Getenv("STATIC_API_KEY")
	base := os.Getenv("PAISANS_GUARD_POCKET_ID")
	if key == "" || base == "" {
		return errors.New("STATIC_API_KEY and PAISANS_GUARD_POCKET_ID must both be set; the pocket-id kind's .env renders them")
	}
	g := &adminguard.Guard{
		API:     &pocketid.Client{HTTP: &http.Client{Timeout: 30 * time.Second}, BaseURL: base, APIKey: key},
		Standby: standby,
		Now:     time.Now,
		Log:     log.Printf,
	}
	go func() {
		for {
			g.Pass()
			time.Sleep(adminguard.Interval)
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		code, body := g.Status()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		fmt.Fprintln(w, body)
	})
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func standby() bool {
	_, err := os.Stat(standbyMarker)
	return err == nil
}

// healthcheck is Docker's healthcheck: the image has no shell or curl, so the
// binary asks itself.
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
