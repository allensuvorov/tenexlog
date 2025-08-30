# ---- Build stage ----
# was: FROM golang:1.22 AS build
FROM golang:1.25 AS build

# Let Go auto-fetch matching toolchains if needed (optional but nice).
ENV GOTOOLCHAIN=auto

WORKDIR /src

# You have no external deps; keep this simple
COPY go.mod ./
RUN go mod download || true

COPY . .

# Build your API
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/tenexlog ./cmd/api

# ---- Run stage ----
FROM gcr.io/distroless/static-debian12
ENV PORT=8080
EXPOSE 8080
COPY --from=build /bin/tenexlog /tenexlog
USER nonroot:nonroot
ENTRYPOINT ["/tenexlog"]