"use client";

import React, { useMemo, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer
} from "recharts";

type Summary = { lines: number; uniqueIPs: number; start?: string; end?: string };
type Bucket = { t: string; count: number };
type Row = { ts?: string; srcIp?: string; dst?: string; method?: string; path?: string; status?: number; bytes?: number; ua?: string };
type AnyAnom = {
  kind: string; srcIp: string;
  minute?: string; firstSeen?: string; lastSeen?: string;
  count?: number; baseline?: number; z?: number;
  hits?: number; uniquePref?: number;
  confidence: number; reason: string;
};
type ApiResponse = {
  jobId: string; filename: string; sizeBytes: number; savedTo?: string; received: string;
  summary: Summary; timeline: Bucket[]; rows: Row[]; anomalies: AnyAnom[]; note?: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080";
function basicHeader(user: string, pass: string): string { return "Basic " + btoa(`${user}:${pass}`); }

function hhmm(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  const h = String(d.getUTCHours()).padStart(2, "0");
  const m = String(d.getUTCMinutes()).padStart(2, "0");
  return `${h}:${m}`;
}
function toChartData(buckets: Bucket[]) {
  return (buckets ?? []).map(b => ({ x: hhmm(b.t), y: b.count, iso: b.t }));
}

const SENSITIVE_PREFIXES = [
  "/admin", "/login", "/wp-admin", "/wp-login", "/xmlrpc.php",
  "/.git", "/.env", "/.ds_store", "/.well-known", "/server-status",
  "/phpmyadmin", "/manager", "/actuator", "/console",
];

function isSensitivePath(path?: string): boolean {
  if (!path) return false;
  const p = path.toLowerCase();
  return SENSITIVE_PREFIXES.some(pref => p.startsWith(pref));
}

function buildHighlightIndexes(anoms: AnyAnom[] | undefined) {
  const spikeMinutesByIP = new Map<string, Set<string>>();
  const sensitiveIPs = new Set<string>();

  (anoms ?? []).forEach(a => {
    if (a.kind === "rate_spike" && a.srcIp && a.minute) {
      const set = spikeMinutesByIP.get(a.srcIp) ?? new Set<string>();
      set.add(new Date(a.minute).toISOString().slice(0, 16));
      spikeMinutesByIP.set(a.srcIp, set);
    }
    if (a.kind === "sensitive_paths" && a.srcIp) {
      sensitiveIPs.add(a.srcIp);
    }
  });

  return { spikeMinutesByIP, sensitiveIPs };
}

function classifyRow(r: Row, spikeMinutesByIP: Map<string, Set<string>>, sensitiveIPs: Set<string>) {
  let spike = false, sensitive = false;

  if (r.ts && r.srcIp) {
    const minuteKey = new Date(r.ts).toISOString().slice(0, 16);
    const set = spikeMinutesByIP.get(r.srcIp);
    if (set && set.has(minuteKey)) {
      spike = true;
    }
  }

  if (r.srcIp && sensitiveIPs.has(r.srcIp) && isSensitivePath(r.path)) {
    sensitive = true;
  }

  return { spike, sensitive };
}

function TimelineChart({ timeline }: { timeline: Bucket[] }) {
  const data = useMemo(() => toChartData(timeline), [timeline]);
  if (!data.length) {
    return <div className="border rounded p-3 text-sm text-gray-500">No timeline data to display.</div>;
  }
  return (
    <div className="border rounded p-3">
      <div className="font-medium mb-2">Timeline (events per minute, UTC)</div>
      <div style={{ width: "100%", height: 240 }}>
        <ResponsiveContainer>
          <LineChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="x" tick={{ fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
            <Tooltip formatter={(v: number) => [v, "Count"]} labelFormatter={(l: string) => `UTC ${l}`} />
            <Line type="monotone" dataKey="y" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default function UploadPage() {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ApiResponse | null>(null);

  const canSubmit = useMemo(() => !!user && !!pass && !!file && !busy, [user, pass, file, busy]);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setData(null);
    if (!file) return;
    try {
      setBusy(true);
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        headers: { Authorization: basicHeader(user, pass) },
        body: fd,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const json = (await res.json()) as ApiResponse;
      setData(json);
    } catch (err) {
      if (err instanceof Error) setError(err.message);
      else setError("Upload failed");
    } finally {
      setBusy(false);
    }
  }

  const highlight = useMemo(() => buildHighlightIndexes(data?.anomalies), [data?.anomalies]);

  return (
    <main className="mx-auto max-w-3xl p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Tenex Log Uploader (Prototype)</h1>
      <p className="text-sm text-gray-600">
        This page calls <code>{API_BASE}/api/upload</code> with HTTP Basic Auth and displays the JSON result.
      </p>

      <form onSubmit={onSubmit} className="space-y-4 border rounded-lg p-4">
        <div className="flex flex-col">
          <label className="text-sm font-medium">Username</label>
          <input className="border rounded px-3 py-2" type="text" value={user} onChange={(e) => setUser(e.target.value)} placeholder="BASIC_USER" autoComplete="username" required />
        </div>
        <div className="flex flex-col">
          <label className="text-sm font-medium">Password</label>
          <input className="border rounded px-3 py-2" type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="BASIC_PASS" autoComplete="current-password" required />
        </div>
        <div className="flex flex-col">
          <label className="text-sm font-medium">Log file (.log / .txt, TSV)</label>
          <input className="border rounded px-3 py-2" type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} accept=".log,.txt,text/plain" required />
          <p className="text-xs text-gray-500 mt-1">
            Expected minimal columns: ts (RFC3339), srcIP, dst, method, path, status, bytes, ua (tab-separated).
          </p>
        </div>
        <button
          type="submit"
          disabled={!canSubmit}
          className={`px-4 py-2 rounded text-white ${canSubmit ? "bg-blue-600 hover:bg-blue-700" : "bg-gray-400 cursor-not-allowed"}`}
          title={canSubmit ? "Upload & analyze" : "Enter credentials and choose a file"}
        >
          {busy ? "Uploading…" : "Upload & Analyze"}
        </button>
        {error && <div className="text-sm text-red-600">{error}</div>}
      </form>

      {data && <TimelineChart timeline={data.timeline} />}

      {data && (
        <section className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="border rounded p-3"><div className="text-xs text-gray-500">Lines</div><div className="text-lg font-semibold">{data.summary.lines}</div></div>
            <div className="border rounded p-3"><div className="text-xs text-gray-500">Unique IPs</div><div className="text-lg font-semibold">{data.summary.uniqueIPs}</div></div>
            <div className="border rounded p-3"><div className="text-xs text-gray-500">Start</div><div className="text-sm">{data.summary.start ?? "—"}</div></div>
            <div className="border rounded p-3"><div className="text-xs text-gray-500">End</div><div className="text-sm">{data.summary.end ?? "—"}</div></div>
          </div>

          <div className="border rounded p-3">
            <div className="font-medium mb-2">Anomalies ({data.anomalies?.length ?? 0})</div>
            {(!data.anomalies || data.anomalies.length === 0) && (<div className="text-sm text-gray-500">No anomalies detected.</div>)}
            <ul className="space-y-2">
              {(data.anomalies ?? []).map((a, i) => (
                <li key={i} className="border rounded p-2">
                  <div className="text-sm"><b>{a.kind}</b> — {a.reason}</div>
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

          <div className="text-xs text-gray-500">
            <span className="inline-block px-2 py-1 rounded mr-2" style={{ background: "rgba(59,130,246,0.15)" }}>rate spike</span>
            <span className="inline-block px-2 py-1 rounded" style={{ background: "rgba(244,63,94,0.15)" }}>sensitive path</span>
          </div>

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
                {(data.rows ?? []).slice(0, 20).map((r, i) => {
                  const { spike, sensitive } = classifyRow(r, highlight.spikeMinutesByIP, highlight.sensitiveIPs);
                  let bg = "";
                  if (spike && sensitive) bg = "rgba(147,51,234,0.18)";
                  else if (spike)          bg = "rgba(59,130,246,0.15)";
                  else if (sensitive)      bg = "rgba(244,63,94,0.15)";
                  return (
                    <tr key={i} className="border-t" style={{ background: bg }}>
                      <td className="px-2 py-1">{r.ts ?? ""}</td>
                      <td className="px-2 py-1">{r.srcIp ?? ""}</td>
                      <td className="px-2 py-1">{r.dst ?? ""}</td>
                      <td className="px-2 py-1">{r.method ?? ""}</td>
                      <td className="px-2 py-1">{r.path ?? ""}</td>
                      <td className="px-2 py-1">{r.status ?? ""}</td>
                      <td className="px-2 py-1">{r.bytes ?? ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {data.note && <p className="text-xs text-gray-500">{data.note}</p>}
        </section>
      )}
    </main>
  );
}