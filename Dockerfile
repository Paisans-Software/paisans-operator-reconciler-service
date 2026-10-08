# The admin reconciler's image: one static binary on distroless, no shell. Built by
# .github/workflows/admin-reconciler-image.yml from the repository root, so the
# build context holds the whole module.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /admin-reconciler ./cmd/admin-reconciler

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /admin-reconciler /admin-reconciler
USER nonroot
EXPOSE 1412
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/admin-reconciler", "healthcheck"]
ENTRYPOINT ["/admin-reconciler"]
