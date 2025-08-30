# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.22 AS build
WORKDIR /src

# Preload modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the whole repo (we’ll .dockerignore the UI etc.)
COPY . .

# Build the API binary from cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/tenexlog ./cmd/api

# ---- Run stage (distroless for small attack surface) ----
FROM gcr.io/distroless/static-debian12

# Fly/Render pass PORT; our code will honor it (see step 3).
ENV PORT=8080
EXPOSE 8080

# Copy binary
COPY --from=build /bin/tenexlog /tenexlog

# Drop root
USER nonroot:nonroot

# Run
ENTRYPOINT ["/tenexlog"]