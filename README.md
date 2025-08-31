# TenexLog – Full-Stack Cybersecurity Log Analyzer

TenexLog is a prototype full-stack web application for uploading, parsing, and analyzing server logs. It helps SOC analysts and engineers detect anomalies such as request rate spikes and probing of sensitive paths, with results visualized in a modern web UI.

---

## Features

- **Secure REST API** (Go): HTTP Basic Auth, CORS, health checks, file upload, anomaly detection.
- **Frontend** (Next.js/TypeScript): File upload, summary cards, timeline chart, anomaly list, row highlighting.
- **Anomaly Detection**: Detects both rate spikes and sensitive path probing.
- **Deployment**: Backend on Fly.io, frontend on Vercel.

---

## Local Setup & Running

### Prerequisites

- **Go** ≥ 1.20
- **Node.js** ≥ 18 (with npm)
- **Docker** (optional, for container builds)

### 1. Clone the Repository

```bash
git clone https://github.com/allensuvorov/tenexlog.git
cd tenexlog
```

### 2. Backend (Go API)

Set environment variables for authentication and CORS:

```bash
export BASIC_USER=alice
export BASIC_PASS=s3cret
export CORS_ORIGIN=http://localhost:3000
```

Run the API server:

```bash
go run ./cmd/api
# Server starts on :8080 by default
```

### 3. Frontend (Next.js UI)

In a new terminal, install dependencies and start the dev server:

```bash
cd ui
npm install
npm run dev
# UI runs on http://localhost:3000
```

**Note:** The UI expects the API at `http://localhost:8080` by default. You can override this by setting `NEXT_PUBLIC_API_BASE` in a `.env.local` file in the `ui/` directory.

---

## Anomaly Detection Approach

TenexLog analyzes uploaded log files using two main anomaly detection strategies:

### 1. **Rate Spike Detection**
- For each source IP, the system builds a per-minute timeline of request counts.
- It calculates the average (baseline) request rate for each IP.
- Minutes where the request count significantly exceeds the baseline (using z-score or a fixed threshold) are flagged as "rate spikes".
- Each spike includes the IP, minute, count, baseline, z-score, and a confidence score.

### 2. **Sensitive Path Probing**
- The system checks for repeated access to sensitive URL prefixes (e.g., `/admin`, `/login`, `/.git`, etc.).
- If an IP hits sensitive paths multiple times or probes several distinct sensitive prefixes, it is flagged.
- Each finding includes the IP, time range, hit count, unique prefixes, and a confidence score.

All detected anomalies are merged into a single array for the frontend, where matching rows are highlighted for easy review.

---

## Example Usage

1. Open [http://localhost:3000/upload](http://localhost:3000/upload) in your browser.
2. Enter your Basic Auth credentials (`alice` / `s3cret` by default).
3. Upload a `.log` or `.txt` file (tab-separated columns: `ts, srcIP, dst, method, path, status, bytes, ua`).
4. View summary stats, timeline chart, anomaly list, and highlighted log rows.

---

## Deployment

- **API**: Deployable on Fly.io with Dockerfile and `fly.toml`.
- **UI**: Deployable on Vercel (`ui/` directory).
- Secrets managed via Fly (`flyctl secrets set`) and Vercel Project Settings.