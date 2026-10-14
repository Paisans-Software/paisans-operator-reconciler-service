# The operator reconciler's image: one static binary on distroless, no shell. Built by
# .github/workflows/operator-reconciler-image.yml from the repository root, so the
# build context holds the whole module.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /operator-reconciler ./cmd/operator-reconciler

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /operator-reconciler /operator-reconciler
COPY --from=build /src/LICENSE /LICENSE
USER nonroot
EXPOSE 1412
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/operator-reconciler", "healthcheck"]
ENTRYPOINT ["/operator-reconciler"]
