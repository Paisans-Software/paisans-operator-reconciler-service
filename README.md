# paisans-operator-reconciler-service

The operator reconciler runs beside Pocket ID in every paisans deployment, in
the pocket-id blueprint's stack. It reads Pocket ID, and the DNS provider's
account when configured, and writes nothing. It reports, on `/healthz`,
whether the deployment's operators are who its configuration says:

* every operator is an enabled user in the member group and in `operators`,
* every enabled member of `operators` is an operator,
* every Pocket ID administrator is an operator, and under `management:
  paisans` there are none.

A pass runs at start and every two hours. The design is
`docs/specs/2026-10-14-operators-and-management.md` and
`docs/specs/2026-10-13-dns-admin-continuity.md` in the paisans CLI's
repository, `Paisans-Software/paisans-stack`, whose pocket-id blueprint
renders this service and its environment.

## Image

`ghcr.io/paisans-software/operator-reconciler`, for `linux/amd64` and
`linux/arm64`: one static binary on `distroless/static`, as `nonroot`,
listening on port 1412.

| Route | Answers |
|-------|---------|
| `/livez` | 200 while the process runs; the image's healthcheck asks it |
| `/healthz` | 200 when the last pass held; 503 before the first pass, when the last is stale, or when it failed. The body is one line saying which |
| `/healthz/dns-super-admins`, `/healthz/dns-2fa` | the DNS checks, when configured |

The environment, which the pocket-id blueprint's `.env` renders, is listed
at the top of `main.go`.

## Releases

A tag `vX.Y.Z` on `main` publishes `X.Y.Z`, and nothing else publishes. The
core catalog's `foundation.yaml` names the track deployments run,
`operator-reconciler: "ghcr.io/paisans-software/operator-reconciler:0.3.*"`,
so a release reaches a deployment on its next apply when the track admits
it. `CHANGELOG.md` records each release.

## Tests

```sh
go test ./...
go test -tags pocketid_integration ./internal/operatorreconciler/    # needs docker
```

The integration test runs passes against a real Pocket ID container;
`POCKETID_IMAGE` names another release to run against.

## Contract with the paisans CLI

The group `operators` and the management values `paisans` and `pocket-id`
are shared with the CLI's pocket-id blueprint. Each repository's tests pin
the three values, so a change on one side fails that side's tests until the
other follows.

## Licence

AGPL-3.0-or-later. The full text is in `LICENSE`.
