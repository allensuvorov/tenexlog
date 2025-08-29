// This is a single Next.js client page that uploads a log file to your Go API,
// sending the Basic Authorization header, and renders the JSON response.

// "use client" marks this as a client component (we use hooks & browser APIs).
"use client";

import React, { useMemo, useState } from "react"; // React core + hooks for state/memo

// Small TypeScript types mirroring your Go JSON response (trimmed to what we display).
type Summary = { lines: number; uniqueIPs: number; start?: string; end?: string }; // summary basics
type Bucket = { t: string; count: number };                                        // timeline bucket (ISO string)
type Row = { ts?: string; srcIp?: string; dst?: string; method?: string; path?: string; status?: number; bytes?: number; ua?: string }; // table row
type AnyAnom = {
  kind: string; srcIp: string;                                                     // common fields
  minute?: string; firstSeen?: string; lastSeen?: string;                          // time fields (one of these)
  count?: number; baseline?: number; z?: number;                                   // rate spike fields
  hits?: number; uniquePref?: number;                                              // sensitive paths fields
  confidence: number; reason: string;                                              // explanation & confidence
};
type ApiResponse = {
  jobId: string; filename: string; sizeBytes: number; savedTo?: string; received: string;
  summary: Summary; timeline: Bucket[]; rows: Row[]; anomalies: AnyAnom[]; note?: string;
};

// Helper to build the `Authorization: Basic ...` header from username/password.
function basicHeader(user: string, pass: string): string {
  // btoa encodes to base64 in the browser (ASCII-safe). For non-ASCII, use TextEncoder + a polyfill.
  return "Basic " + btoa(`${user}:${pass}`);
}

// Read API base URL from env (configure NEXT_PUBLIC_API_BASE in .env.local).
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080"; // fallback for local dev

export default function UploadPage() {
  // Form state for username/password/file.
  const [user, setUser] = useState("");                 // Basic username input
  const [pass, setPass] = useState("");                 // Basic password input
  const [file, setFile] = useState<File | null>(null);  // chosen file from <input type="file">

  // Request/response/UI state.
  const [busy, setBusy] = useState(false);              // disables button while uploading
  const [error, setError] = useState<string | null>(null); // network/HTTP errors to show
  const [data, setData] = useState<ApiResponse | null>(null); // parsed API JSON response

  // Whether form can be submitted (all required pieces present).
  const canSubmit = useMemo(() => !!user && !!pass && !!file && !busy, [user, pass, file, busy]);

  // Handle the <form> submission: POST multipart/form-data to /api/upload with Basic Auth.
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();                    // prevent full page reload
    setError(null);                        // clear previous error, if any
    setData(null);                         // clear previous data, if any
    if (!file) return;                     // guard: file must be selected

    try {
      setBusy(true);                       // set busy to disable UI interactions
      const fd = new FormData();           // browser FormData for multipart/form-data
      fd.append("file", file);             // the Go handler expects form field name "file"

      const res = await fetch(`${API_BASE}/api/upload`, { // send to your Go API
        method: "POST",                    // upload uses POST
        headers: {                        // include Basic Authorization header
          Authorization: basicHeader(user, pass),
        },
        body: fd,                          // multipart body with the file
        // Note: no need to set Content-Type; the browser sets correct boundary for FormData.
        // mode: "cors" is default when Origin differs; credentials header is allowed via your CORS.
      });

      if (!res.ok) {                       // non-2xx: read text and surface error
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }

      const json = (await res.json()) as ApiResponse; // parse JSON into our typed shape
      setData(json);                      // store for rendering
    } catch (err: any) {                  // network or HTTP errors
      setError(err?.message ?? "Upload failed"); // show error message
    } finally {
      setBusy(false);                     // re-enable the UI
    }
  }

  return (
    <main className="mx-auto max-w-3xl p-6 space-y-6"> {/* centered column with padding & vertical gaps */}
      {/* Title */}
      <h1 className="text-2xl font-semibold">Tenex Log Uploader (Prototype)</h1>

      {/* Small note so future you remembers how this page authenticates */}
      <p className="text-sm text-gray-600">
        This page calls <code>{API_BASE}/api/upload</code> with HTTP Basic Auth and displays the JSON result.
      </p>

      {/* Upload form */}
      <form onSubmit={onSubmit} className="space-y-4 border rounded-lg p-4">
        {/* Username input */}
        <div className="flex flex-col">
          <label className="text-sm font-medium">Username</label>
          <input
            type="text" value={user} onChange={(e) => setUser(e.target.value)}
            placeholder="BASIC_USER" className="border rounded px-3 py-2"
            autoComplete="username" // helps the browser with autofill
            required                // HTML-level required
          />
        </div>

        {/* Password input */}
        <div className="flex flex-col">
          <label className="text-sm font-medium">Password</label>
          <input
            type="password" value={pass} onChange={(e) => setPass(e.target.value)}
            placeholder="BASIC_PASS" className="border rounded px-3 py-2"
            autoComplete="current-password" // helps the browser with autofill
            required
          />
        </div>

        {/* File picker */}
        <div className="flex flex-col">
          <label className="text-sm font-medium">Log file (.log / .txt, TSV)</label>
          <input
            type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            accept=".log,.txt,text/plain" className="border rounded px-3 py-2"
            required
          />
          {/* Tiny hint about expected format */}
          <p className="text-xs text-gray-500 mt-1">
            Expected minimal columns: ts (RFC3339), srcIP, dst, method, path, status, bytes, ua (tab-separated).
          </p>
        </div>

        {/* Submit button */}
        <button
          type="submit" disabled={!canSubmit}
          className={`px-4 py-2 rounded text-white ${canSubmit ? "bg-blue-600 hover:bg-blue-700" : "bg-gray-400 cursor-not-allowed"}`}
          title={canSubmit ? "Upload & analyze" : "Enter credentials and choose a file"}
        >
          {busy ? "Uploading…" : "Upload & Analyze"}
        </button>

        {/* Inline error, if any */}
        {error && (
          <div className="text-sm text-red-600">
            {error}
          </div>
        )}
      </form>

      {/* Render results if present */}
      {data && (
        <section className="space-y-4">
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="border rounded p-3">
              <div className="text-xs text-gray-500">Lines</div>
              <div className="text-lg font-semibold">{data.summary.lines}</div>
            </div>
            <div className="border rounded p-3">
              <div className="text-xs text-gray-500">Unique IPs</div>
              <div className="text-lg font-semibold">{data.summary.uniqueIPs}</div>
            </div>
            <div className="border rounded p-3">
              <div className="text-xs text-gray-500">Start</div>
              <div className="text-sm">{data.summary.start ?? "—"}</div>
            </div>
            <div className="border rounded p-3">
              <div className="text-xs text-gray-500">End</div>
              <div className="text-sm">{data.summary.end ?? "—"}</div>
            </div>
          </div>

          {/* Anomalies list (compact) */}
          <div className="border rounded p-3">
            <div className="font-medium mb-2">Anomalies ({data.anomalies?.length ?? 0})</div>
            {(!data.anomalies || data.anomalies.length === 0) && (
              <div className="text-sm text-gray-500">No anomalies detected.</div>
            )}
            <ul className="space-y-2">
              {(data.anomalies ?? []).map((a, i) => (
                <li key={i} className="border rounded p-2">
                  <div className="text-sm">
                    <b>{a.kind}</b> — {a.reason}
                  </div>
                  <div className="text-xs text-gray-600">
                    IP: {a.srcIp} · Confidence: {(a.confidence * 100).toFixed(0)}%
                    {a.minute && <> · Minute: {a.minute}</>}
                    {a.firstSeen && <> · First: {a.firstSeen}</>}
                    {a.lastSeen && <> · Last: {a.lastSeen}</>}
                  </div>
                </li>
              ))}
            </ul>
          </div>

          {/* Rows table (first 20 for brevity) */}
          <div className="border rounded p-3 overflow-x-auto">
            <div className="font-medium mb-2">Rows (showing up to 20)</div>
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left">
                  <th className="px-2 py-1">ts</th>
                  <th className="px-2 py-1">srcIp</th>
                  <th className="px-2 py-1">dst</th>
                  <th className="px-2 py-1">method</th>
                  <th className="px-2 py-1">path</th>
                  <th className="px-2 py-1">status</th>
                  <th className="px-2 py-1">bytes</th>
                </tr>
              </thead>
              <tbody>
                {(data.rows ?? []).slice(0, 20).map((r, i) => (
                  <tr key={i} className="border-t">
                    <td className="px-2 py-1">{r.ts ?? ""}</td>
                    <td className="px-2 py-1">{r.srcIp ?? ""}</td>
                    <td className="px-2 py-1">{r.dst ?? ""}</td>
                    <td className="px-2 py-1">{r.method ?? ""}</td>
                    <td className="px-2 py-1">{r.path ?? ""}</td>
                    <td className="px-2 py-1">{r.status ?? ""}</td>
                    <td className="px-2 py-1">{r.bytes ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Optional transparency note from API */}
          {data.note && <p className="text-xs text-gray-500">{data.note}</p>}
        </section>
      )}
    </main>
  );
}