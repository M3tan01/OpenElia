import { useState } from "react";
import { apiGet, apiPost, Finding, ReportBriefResp, StateResp } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Panel } from "./Panel";

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-400/60",
  high: "text-orange-400 border-orange-400/60",
  medium: "text-amber border-amber/60",
  low: "text-phos border-phos/60",
  info: "text-dim border-line",
};

function sevClass(sev: string): string {
  return SEV_COLOR[(sev || "").toLowerCase()] ?? "text-dim border-line";
}

function cvssClass(score: number): string {
  if (score >= 9.0) return "text-red-400";
  if (score >= 7.0) return "text-orange-400";
  if (score >= 4.0) return "text-amber";
  return "text-phos";
}

// ── shared download helper ────────────────────────────────────────────────────

function download(filename: string, text: string, mime: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

// ── JSON export ───────────────────────────────────────────────────────────────

function exportFindings(findings: Finding[]): void {
  download(
    `openelia-findings-${stamp()}.json`,
    JSON.stringify(findings, null, 2),
    "application/json",
  );
}

// ── CSV export ────────────────────────────────────────────────────────────────

function csvEscape(val: string | number | null | undefined): string {
  const s = val == null ? "" : String(val);
  // Wrap in double-quotes if the value contains a comma, double-quote, or newline;
  // double-up any internal double-quote characters.
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function exportFindingsCsv(findings: Finding[]): void {
  const header = "severity,title,source_agent,mitre_ttp,cvss_score,cvss_vector";
  const rows = findings.map((f) =>
    [
      csvEscape(f.severity),
      csvEscape(f.title),
      csvEscape(f.source_agent),
      csvEscape(f.mitre_ttp),
      csvEscape(f.cvss_score),
      csvEscape(f.cvss_vector),
    ].join(","),
  );
  download(
    `openelia-findings-${stamp()}.csv`,
    [header, ...rows].join("\r\n"),
    "text/csv",
  );
}

// ── Markdown export ───────────────────────────────────────────────────────────

function mdEscape(val: string | number | null | undefined): string {
  // Escape pipe characters so they don't break GFM table cells.
  return (val == null ? "" : String(val)).replace(/\|/g, "\\|");
}

export function exportFindingsMd(findings: Finding[]): void {
  const header = "| Severity | Title | Agent | ATT&CK | CVSS | Vector |";
  const separator = "|---|---|---|---|---|---|";
  const rows = findings.map(
    (f) =>
      `| ${mdEscape(f.severity)} | ${mdEscape(f.title)} | ${mdEscape(f.source_agent)} | ${mdEscape(f.mitre_ttp)} | ${f.cvss_score != null ? f.cvss_score : ""} | ${mdEscape(f.cvss_vector)} |`,
  );
  download(
    `openelia-findings-${stamp()}.md`,
    [header, separator, ...rows].join("\n"),
    "text/markdown",
  );
}

// ── Print / Save as PDF ───────────────────────────────────────────────────────

export function printFindings(
  findings: Finding[],
  onPopupBlocked: () => void,
): void {
  const win = window.open("", "_blank");
  if (!win) {
    onPopupBlocked();
    return;
  }

  const ts = new Date().toLocaleString();

  // Build the document via DOM manipulation (no document.write).
  const doc = win.document;

  // <meta charset>
  const meta = doc.createElement("meta");
  meta.setAttribute("charset", "UTF-8");
  doc.head.appendChild(meta);

  // <title>
  const title = doc.createElement("title");
  title.textContent = "OpenElia Findings";
  doc.head.appendChild(title);

  // <style>
  const style = doc.createElement("style");
  style.textContent = [
    "body{font-family:system-ui,sans-serif;color:#111;background:#fff;margin:2rem}",
    "h1{font-size:1.25rem;margin-bottom:.25rem}",
    "p.ts{font-size:.75rem;color:#555;margin-bottom:1rem}",
    "table{border-collapse:collapse;width:100%;font-size:.8rem}",
    "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;vertical-align:top}",
    "th{background:#f5f5f5;font-weight:600}",
    "tr:nth-child(even) td{background:#fafafa}",
    "@media print{body{margin:.5cm 1cm}}",
  ].join("");
  doc.head.appendChild(style);

  // <h1>
  const h1 = doc.createElement("h1");
  h1.textContent = "OpenElia Findings";
  doc.body.appendChild(h1);

  // timestamp paragraph
  const p = doc.createElement("p");
  p.className = "ts";
  p.textContent = `Exported: ${ts} — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`;
  doc.body.appendChild(p);

  // <table>
  const table = doc.createElement("table");

  // thead
  const thead = doc.createElement("thead");
  const hRow = doc.createElement("tr");
  ["Severity", "Title", "Agent", "ATT&CK", "CVSS", "Vector"].forEach((col) => {
    const th = doc.createElement("th");
    th.textContent = col;
    hRow.appendChild(th);
  });
  thead.appendChild(hRow);
  table.appendChild(thead);

  // tbody
  const tbody = doc.createElement("tbody");
  findings.forEach((f) => {
    const tr = doc.createElement("tr");
    const cells: (string | number | null | undefined)[] = [
      f.severity,
      f.title,
      f.source_agent,
      f.mitre_ttp,
      f.cvss_score != null ? f.cvss_score : "",
      f.cvss_vector,
    ];
    cells.forEach((val) => {
      const td = doc.createElement("td");
      td.textContent = val == null ? "" : String(val);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  doc.body.appendChild(table);

  win.print();
}

// ── component ─────────────────────────────────────────────────────────────────

export function FindingsView() {
  const { data, error: err } = usePoll<StateResp>(
    () => apiGet<StateResp>("/api/state"),
    5000,
  );
  const findings: Finding[] | null = data ? (data.findings ?? []) : null;
  const [printErr, setPrintErr] = useState<boolean>(false);
  const [briefMd, setBriefMd] = useState<string | null>(null);
  const [briefGenerating, setBriefGenerating] = useState<boolean>(false);
  const [briefErr, setBriefErr] = useState<string | null>(null);

  const count = findings?.length ?? 0;
  const disabled = count === 0;

  const btnClass =
    "font-display uppercase tracking-wider bg-amber/15 border border-amber text-amber text-[11px] px-2 py-1 hover:bg-amber/25 disabled:opacity-40";

  function handleGenerateBrief() {
    setBriefErr(null);
    setBriefGenerating(true);
    apiPost<ReportBriefResp>("/api/report/brief", { confirm: true, brain_tier: "local" })
      .then((r) => { setBriefMd(r.markdown); })
      .catch((e: unknown) => { setBriefErr(e instanceof Error ? e.message : String(e)); })
      .finally(() => { setBriefGenerating(false); });
  }

  const exportButtons = (
    <div className="flex items-center gap-1">
      <button
        className={btnClass}
        disabled={disabled}
        title={disabled ? "no findings to export" : `export ${count} findings as JSON`}
        onClick={() => findings && exportFindings(findings)}
      >
        ↓ JSON
      </button>
      <button
        className={btnClass}
        disabled={disabled}
        title={disabled ? "no findings to export" : `export ${count} findings as CSV`}
        onClick={() => findings && exportFindingsCsv(findings)}
      >
        ↓ CSV
      </button>
      <button
        className={btnClass}
        disabled={disabled}
        title={disabled ? "no findings to export" : `export ${count} findings as Markdown`}
        onClick={() => findings && exportFindingsMd(findings)}
      >
        ↓ MD
      </button>
      <button
        className={btnClass}
        disabled={disabled}
        title={disabled ? "no findings to export" : "print / save as PDF"}
        onClick={() =>
          findings &&
          printFindings(findings, () => {
            setPrintErr(true);
            setTimeout(() => setPrintErr(false), 4000);
          })
        }
      >
        ⎙ Print
      </button>
      <button
        className={btnClass}
        disabled={disabled || briefGenerating}
        title={disabled ? "no findings to brief" : briefGenerating ? "generating…" : "generate executive brief via Reporter agent"}
        onClick={handleGenerateBrief}
      >
        {briefGenerating ? "generating…" : "⚡ Brief"}
      </button>
    </div>
  );

  return (
    <Panel title="Findings" right={exportButtons} className="h-full">
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {printErr && (
        <div className="mb-3">
          <Badge ok={false}>Popup blocked — allow popups to print / save as PDF.</Badge>
        </div>
      )}
      {!findings && !err && <div className="text-dim text-xs italic">loading…</div>}
      {findings?.length === 0 && <div className="text-dim text-xs italic">no findings yet</div>}
      <div className="space-y-1.5 overflow-auto scroll-thin">
        {(findings ?? []).map((f, i) => (
          <div key={i} className={`border-l-2 ${sevClass(f.severity)} bg-surface/40 px-3 py-2`}>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-slate-200">{f.title}</span>
              <div className="flex items-center gap-2 shrink-0">
                <span className={`font-mono text-[10px] uppercase tracking-wider px-1.5 py-0.5 border ${sevClass(f.severity)}`}>
                  {f.severity || "—"}
                </span>
                {typeof f.cvss_score === "number" && (
                  <span className={`font-mono text-xs font-semibold ${cvssClass(f.cvss_score)}`}>
                    CVSS {f.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3 mt-0.5 font-mono text-[11px] text-dim">
              {f.mitre_ttp && <span className="text-amber/70">{f.mitre_ttp}</span>}
              {f.cvss_vector && <span className="truncate">{f.cvss_vector}</span>}
              <span className="text-phos/80 font-mono text-[10px]" title="source agent">{f.source_agent || "—"}</span>
            </div>
          </div>
        ))}
      </div>
      {briefErr && (
        <div className="mt-3">
          <Badge ok={false}>{briefErr}</Badge>
        </div>
      )}
      {briefMd && (
        <div className="mt-4 border border-line bg-surface/60 p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="font-display uppercase tracking-wider text-amber text-[11px]">Findings Brief</span>
            <div className="flex items-center gap-1">
              <button
                className={btnClass}
                title="download brief as Markdown"
                onClick={() => download(`openelia-findings-brief-${stamp()}.md`, briefMd, "text/markdown")}
              >
                ↓ .md
              </button>
              <button
                className={btnClass}
                title="dismiss brief"
                onClick={() => { setBriefMd(null); setBriefErr(null); }}
              >
                ✕
              </button>
            </div>
          </div>
          <pre className="whitespace-pre-wrap font-mono text-xs text-slate-200">{briefMd}</pre>
        </div>
      )}
    </Panel>
  );
}
