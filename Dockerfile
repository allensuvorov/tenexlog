# ---- Build stage ----
FROM golang:1.22 AS build
WORKDIR /src

# Copy only go.mod (since no go.sum)
COPY go.mod ./
RUN go mod download || true   # this will succeed even with no dependencies

# Copy the rest of the source
COPY . .

# Build the API binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/tenexlog ./cmd/api

# ---- Run stage ----
FROM gcr.io/distroless/static-debian12
ENV PORT=8080
EXPOSE 8080
COPY --from=build /bin/tenexlog /tenexlog
USER nonroot:nonroot
ENTRYPOINT ["/tenexlog"]