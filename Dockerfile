# The admin guard's image: one static binary on distroless, no shell. Built by
# .github/workflows/admin-guard-image.yml from the repository root, so the
# build context holds the whole module.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /admin-guard ./cmd/admin-guard

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /admin-guard /admin-guard
USER nonroot
EXPOSE 1412
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/admin-guard", "healthcheck"]
ENTRYPOINT ["/admin-guard"]
