'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { CSSProperties } from 'react';

// ── Types ─────────────────────────────────────────────────────────────────────

type FinalVerdict = 'APPROVE' | 'BLOCK' | 'ESCALATE';

interface AuditRecord {
  id: string;
  timestamp: string;
  chainId: number;
  fromAddress: string;
  toAddress: string;
  txType: string;
  valueWei: string;
  riskScore: number | null;
  riskCategory: string | null;
  finalVerdict: FinalVerdict;
  decodedTxJson: string;
  simulationResultJson: string;
  ruleFlagsJson: string;
  classifierOutputJson: string;
  policyDecisionJson: string;
  humanVerdict: string | null;
  humanTimestamp: string | null;
  humanNote: string | null;
}

interface DecodedTx {
  txType: string;
  from: string;
  to: string;
  recipient?: string;
  tokenAddress?: string;
  isUnlimitedApproval?: boolean;
  value: string;
}

interface SimResult {
  success: boolean;
  gasUsed: string;
  errorMessage: string | null;
  logs: Array<{ address: string; topics: string[] }>;
  stateChanges: Array<{ address: string; balanceBefore: string; balanceAfter: string }>;
}

interface RuleFlag {
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
}

interface ClassifierOutput {
  riskScore: number;
  category: string;
  reasoning: string;
  classifierSignals: string[];
}

interface PolicyDecision {
  verdict: string;
  reason: string;
  triggeredPolicyRules: string[];
}

// ── Demo calldatas (pre-encoded, no viem dependency in dashboard) ─────────────

const USDC   = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

// approve(0xdeadbeef…, uint256.max)
const APPROVAL_DATA = '0x095ea7b3'
  + '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
  + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

// transfer(0x70997970…, 10_000_000 units = 10 USDC)
const TRANSFER_DATA = '0xa9059cbb'
  + '00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8'
  + '0000000000000000000000000000000000000000000000000000000000989680';

const DEMO_OPTIONS = {
  block:   { label: 'Unlimited Approval → BLOCK',  tx: { to: USDC, from: SENDER, value: '0', data: APPROVAL_DATA, chainId: 84532 } },
  approve: { label: 'Safe Transfer → APPROVE', tx: { to: USDC, from: SENDER, value: '0', data: TRANSFER_DATA, chainId: 84532 } },
} as const;

type DemoKey = keyof typeof DEMO_OPTIONS;

// ── Helpers ───────────────────────────────────────────────────────────────────

function trunc(s: string | undefined | null, chars = 6): string {
  if (!s || s.length < 14) return s ?? '—';
  return `${s.slice(0, chars + 2)}…${s.slice(-4)}`;
}

function safeJson<T>(s: string | null | undefined): T | null {
  if (!s) return null;
  try { const v = JSON.parse(s); return v === null ? null : (v as T); }
  catch { return null; }
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ── Design tokens ─────────────────────────────────────────────────────────────

const C = {
  bg:       '#0f1117',
  surface:  '#1a1d27',
  border:   '#2d3144',
  border2:  '#1e293b',
  text:     '#e2e8f0',
  muted:    '#64748b',
  dimmed:   '#334155',
  green:    '#22c55e',
  red:      '#ef4444',
  yellow:   '#f59e0b',
  orange:   '#fb923c',
  indigo:   '#818cf8',
  indigoLt: '#a5b4fc',
  blueDark: '#1d4ed8',
} as const;

const VERDICT_COLOR: Record<FinalVerdict, string> = {
  APPROVE:  C.green,
  BLOCK:    C.red,
  ESCALATE: C.yellow,
};

const SEV_COLOR: Record<string, string> = {
  CRITICAL: C.red,
  HIGH:     '#f97316',
  MEDIUM:   C.yellow,
  LOW:      C.muted,
};

// ── Shared components ─────────────────────────────────────────────────────────

function VerdictBadge({ verdict }: { verdict: string }) {
  const color = VERDICT_COLOR[verdict as FinalVerdict] ?? C.muted;
  return (
    <span style={{ color, border: `1px solid ${color}`, borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
      {verdict}
    </span>
  );
}

function SevBadge({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity] ?? C.muted;
  return (
    <span style={{ color, border: `1px solid ${color}`, borderRadius: 3, padding: '1px 5px', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em' }}>
      {severity}
    </span>
  );
}

// ── PipelineDetail ────────────────────────────────────────────────────────────
// Expanded view showing every pipeline stage.
//
// Visual distinction enforced here:
//   Rule Flags        — from the deterministic rules engine, severity-colored badges
//   Classifier Signals — from Claude AI, indigo palette
//   Triggered Policy Rules — from policy.evaluate(), orange palette

function PipelineDetail({ record }: { record: AuditRecord }) {
  const decoded = safeJson<DecodedTx>(record.decodedTxJson);
  const sim     = safeJson<SimResult>(record.simulationResultJson);
  const flags   = safeJson<RuleFlag[]>(record.ruleFlagsJson) ?? [];
  const cls     = safeJson<ClassifierOutput>(record.classifierOutputJson);
  const policy  = safeJson<PolicyDecision>(record.policyDecisionJson);

  const wrap: CSSProperties = { padding: '16px 16px 20px 40px', borderTop: `1px solid ${C.border2}`, background: '#0d0f18' };
  const sec:  CSSProperties = { marginTop: 18 };
  const lbl:  CSSProperties = { color: C.muted, fontSize: 10, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 8 };
  const row:  CSSProperties = { display: 'flex', gap: 8, marginBottom: 5, flexWrap: 'wrap' };
  const kSt:  CSSProperties = { color: C.muted, minWidth: 140, fontSize: 12 };
  const vSt:  CSSProperties = { color: C.text, fontFamily: 'ui-monospace, monospace', fontSize: 12 };

  return (
    <div style={wrap}>

      {/* 1 — Decoded transaction */}
      <div style={sec}>
        <p style={lbl}>Decoded Transaction</p>
        {decoded ? (
          <>
            <div style={row}><span style={kSt}>txType</span><span style={vSt}>{decoded.txType}</span></div>
            <div style={row}><span style={kSt}>from</span><span style={vSt}>{decoded.from}</span></div>
            <div style={row}><span style={kSt}>to (contract)</span><span style={vSt}>{decoded.to}</span></div>
            {decoded.recipient    && <div style={row}><span style={kSt}>recipient</span><span style={vSt}>{decoded.recipient}</span></div>}
            {decoded.tokenAddress && <div style={row}><span style={kSt}>tokenAddress</span><span style={vSt}>{decoded.tokenAddress}</span></div>}
            <div style={row}><span style={kSt}>value (wei)</span><span style={vSt}>{decoded.value}</span></div>
            {decoded.isUnlimitedApproval != null && (
              <div style={row}>
                <span style={kSt}>unlimitedApproval</span>
                <span style={{ ...vSt, color: decoded.isUnlimitedApproval ? C.red : C.green }}>
                  {String(decoded.isUnlimitedApproval)}
                </span>
              </div>
            )}
          </>
        ) : <p style={{ color: C.muted, fontSize: 12 }}>unavailable</p>}
      </div>

      {/* 2 — Simulation */}
      <div style={sec}>
        <p style={lbl}>Simulation</p>
        {sim ? (
          <>
            <div style={row}>
              <span style={kSt}>success</span>
              <span style={{ ...vSt, color: sim.success ? C.green : C.red }}>{String(sim.success)}</span>
            </div>
            <div style={row}><span style={kSt}>gasUsed</span><span style={vSt}>{Number(sim.gasUsed).toLocaleString()}</span></div>
            {sim.errorMessage && (
              <div style={row}><span style={kSt}>error</span><span style={{ ...vSt, color: C.red }}>{sim.errorMessage}</span></div>
            )}
            <div style={row}><span style={kSt}>logs</span><span style={vSt}>{sim.logs.length} event(s)</span></div>
            {sim.stateChanges.length > 0 && (
              <div style={{ marginTop: 6 }}>
                <p style={{ ...kSt, marginBottom: 6 }}>State changes</p>
                {sim.stateChanges.map((sc, i) => {
                  const diff = BigInt(sc.balanceAfter) - BigInt(sc.balanceBefore);
                  return (
                    <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 3, paddingLeft: 8, fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>
                      <span style={{ color: C.muted }}>{trunc(sc.address, 8)}</span>
                      <span style={{ color: diff >= 0n ? C.green : C.red }}>
                        {diff >= 0n ? '+' : ''}{diff.toString()}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        ) : <p style={{ color: C.muted, fontSize: 12 }}>unavailable — simulator was not reachable</p>}
      </div>

      {/* 3 — Rule flags (deterministic engine) */}
      <div style={sec}>
        <p style={lbl}>Rule Flags — Deterministic Engine</p>
        {flags.length === 0
          ? <p style={{ color: C.muted, fontSize: 12 }}>none — all checks passed</p>
          : flags.map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6 }}>
              <SevBadge severity={f.severity} />
              <span style={{ ...vSt, color: '#cbd5e1' }}>{f.ruleId}</span>
              <span style={{ color: C.muted, fontSize: 12 }}>— {f.message}</span>
            </div>
          ))}
      </div>

      {/* 4 — Classifier (Claude AI) */}
      <div style={sec}>
        <p style={lbl}>Classifier — Claude AI</p>
        {cls ? (
          <>
            <div style={row}>
              <span style={kSt}>riskScore</span>
              <span style={{ ...vSt, fontWeight: 700, color: cls.riskScore >= 80 ? C.red : cls.riskScore >= 50 ? C.yellow : C.green }}>
                {cls.riskScore}
              </span>
            </div>
            <div style={row}><span style={kSt}>category</span><span style={vSt}>{cls.category}</span></div>
            <div style={{ marginTop: 8, marginBottom: 10 }}>
              <p style={{ ...kSt, marginBottom: 6 }}>reasoning</p>
              <p style={{ color: '#cbd5e1', fontSize: 12, lineHeight: 1.65, paddingLeft: 8, borderLeft: `2px solid ${C.border}` }}>
                {cls.reasoning}
              </p>
            </div>
            {/* Classifier signals — indigo, visually distinct from rule flags */}
            <div>
              <p style={{ ...kSt, marginBottom: 6, color: C.indigo }}>Classifier Signals</p>
              {cls.classifierSignals.length === 0
                ? <p style={{ color: C.dimmed, fontSize: 12, paddingLeft: 8 }}>none</p>
                : <ul style={{ paddingLeft: 20, listStyle: 'disc' }}>
                    {cls.classifierSignals.map((s, i) => (
                      <li key={i} style={{ color: C.indigoLt, fontSize: 12, marginBottom: 3 }}>{s}</li>
                    ))}
                  </ul>}
            </div>
          </>
        ) : (
          <p style={{ color: C.muted, fontSize: 12 }}>
            null — CRITICAL short-circuit skipped classifier, or classifier was unavailable
          </p>
        )}
      </div>

      {/* 5 — Policy decision */}
      <div style={sec}>
        <p style={lbl}>Policy Decision</p>
        {policy ? (
          <>
            <div style={row}><span style={kSt}>verdict</span><VerdictBadge verdict={policy.verdict} /></div>
            <div style={row}><span style={kSt}>reason</span><span style={{ ...vSt, color: '#cbd5e1' }}>{policy.reason}</span></div>
            {/* Triggered policy rules — orange, visually distinct from classifier signals */}
            <div style={{ marginTop: 8 }}>
              <p style={{ ...kSt, marginBottom: 6, color: C.orange }}>Triggered Policy Rules</p>
              {policy.triggeredPolicyRules.length === 0
                ? <p style={{ color: C.dimmed, fontSize: 12, paddingLeft: 8 }}>none — default APPROVE path</p>
                : <ul style={{ paddingLeft: 20, listStyle: 'disc' }}>
                    {policy.triggeredPolicyRules.map((r, i) => (
                      <li key={i} style={{ color: '#fdba74', fontSize: 12, fontFamily: 'ui-monospace, monospace', marginBottom: 3 }}>{r}</li>
                    ))}
                  </ul>}
            </div>
          </>
        ) : <p style={{ color: C.muted, fontSize: 12 }}>unavailable</p>}
      </div>
    </div>
  );
}

// ── Decision row ──────────────────────────────────────────────────────────────

const tdS: CSSProperties = { padding: '10px 12px', fontSize: 12 };

function DecisionRow({ record }: { record: AuditRecord }) {
  const [open, setOpen] = useState(false);
  const decoded   = safeJson<DecodedTx>(record.decodedTxJson);
  const recipient = decoded?.recipient ?? record.toAddress;

  return (
    <>
      <tr onClick={() => setOpen(o => !o)} style={{ cursor: 'pointer', borderBottom: `1px solid ${C.border2}` }} className="decision-row">
        <td style={tdS}>{fmtTime(record.timestamp)}</td>
        <td style={tdS}><span style={{ fontFamily: 'ui-monospace, monospace', fontSize: 11 }}>{record.txType}</span></td>
        <td style={tdS}><span style={{ fontFamily: 'ui-monospace, monospace', fontSize: 11 }}>{trunc(record.fromAddress)}</span></td>
        <td style={tdS}><span style={{ fontFamily: 'ui-monospace, monospace', fontSize: 11 }}>{trunc(recipient)}</span></td>
        <td style={{ ...tdS, textAlign: 'center' }}>
          {record.riskScore != null
            ? <span style={{ fontWeight: 600, color: record.riskScore >= 80 ? C.red : record.riskScore >= 50 ? C.yellow : C.green }}>{record.riskScore}</span>
            : <span style={{ color: C.dimmed }}>—</span>}
        </td>
        <td style={{ ...tdS, textAlign: 'center' }}><VerdictBadge verdict={record.finalVerdict} /></td>
        <td style={{ ...tdS, color: C.dimmed, fontSize: 12, width: 24 }}>{open ? '▼' : '▶'}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} style={{ padding: 0 }}>
            <PipelineDetail record={record} />
          </td>
        </tr>
      )}
    </>
  );
}

// ── Decision feed ─────────────────────────────────────────────────────────────

function DecisionFeed({ records }: { records: AuditRecord[] }) {
  const thS: CSSProperties = {
    padding: '8px 12px', textAlign: 'left', color: C.muted,
    fontSize: 10, fontWeight: 700, letterSpacing: '0.1em',
    textTransform: 'uppercase', borderBottom: `1px solid ${C.border2}`,
    whiteSpace: 'nowrap',
  };

  if (records.length === 0) {
    return <p style={{ color: C.muted, padding: '40px 0', textAlign: 'center' }}>No decisions yet — run a demo transaction below.</p>;
  }

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr>
          <th style={thS}>Time</th>
          <th style={thS}>Type</th>
          <th style={thS}>From</th>
          <th style={thS}>Recipient</th>
          <th style={{ ...thS, textAlign: 'center' }}>Risk</th>
          <th style={{ ...thS, textAlign: 'center' }}>Verdict</th>
          <th style={thS}></th>
        </tr>
      </thead>
      <tbody>
        {records.map(r => <DecisionRow key={r.id} record={r} />)}
      </tbody>
    </table>
  );
}

// ── Escalation card ───────────────────────────────────────────────────────────

const btnS: CSSProperties = { border: '1px solid', borderRadius: 4, padding: '6px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer' };

function EscalationCard({ record, onResolved }: { record: AuditRecord; onResolved: () => void }) {
  const [note, setNote]   = useState('');
  const [busy, setBusy]   = useState<'APPROVE' | 'REJECT' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const decoded = safeJson<DecodedTx>(record.decodedTxJson);
  const policy  = safeJson<PolicyDecision>(record.policyDecisionJson);

  async function resolve(verdict: 'APPROVE' | 'REJECT') {
    setBusy(verdict);
    setError(null);
    try {
      const resp = await fetch(`/api/decisions/${record.id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict, note: note.trim() || undefined }),
      });
      if (!resp.ok) throw new Error(await resp.text());
      onResolved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed');
      setBusy(null);
    }
  }

  return (
    <div style={{ border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.yellow}`, borderRadius: 6, marginBottom: 12, background: C.surface, overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <p style={{ fontFamily: 'ui-monospace, monospace', fontSize: 11, color: C.muted }}>{record.id.slice(0, 18)}…</p>
          <p style={{ marginTop: 4, fontSize: 12 }}>
            <span style={{ color: C.muted }}>{record.txType}</span>
            {' from '}
            <span style={{ fontFamily: 'ui-monospace, monospace' }}>{trunc(record.fromAddress)}</span>
            {decoded?.recipient && <> → <span style={{ fontFamily: 'ui-monospace, monospace' }}>{trunc(decoded.recipient)}</span></>}
          </p>
          {policy && <p style={{ marginTop: 4, fontSize: 12, color: '#94a3b8' }}>{policy.reason}</p>}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-end', flexShrink: 0 }}>
          <input
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Review note (optional)"
            style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, padding: '6px 10px', fontSize: 12, width: 220 }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => void resolve('APPROVE')} disabled={busy !== null}
              style={{ ...btnS, background: '#166534', color: '#bbf7d0', borderColor: '#166534', opacity: busy !== null ? 0.6 : 1 }}>
              {busy === 'APPROVE' ? '…' : '✓ Approve'}
            </button>
            <button onClick={() => void resolve('REJECT')} disabled={busy !== null}
              style={{ ...btnS, background: '#7f1d1d', color: '#fecaca', borderColor: '#7f1d1d', opacity: busy !== null ? 0.6 : 1 }}>
              {busy === 'REJECT' ? '…' : '✗ Reject'}
            </button>
          </div>
          {error && <p style={{ color: C.red, fontSize: 11 }}>{error}</p>}
        </div>
      </div>
      <PipelineDetail record={record} />
    </div>
  );
}

// ── EvaluateDemo with PipelineStageIndicator ──────────────────────────────────
//
// Stage progression (client-side timer for decode/simulate/rules, real fetch
// completion for the classifying→done transition):
//
//   0 ms  — decode ⟳
//   200ms — simulate ⟳
//  1800ms — rules ⟳
//  1850ms — classifying ⟳   ← spinner; NO timer after this
//  fetch resolves → clearTimeout on all pending timers, then immediately done
//
// Guarantee: "classifying ⟳" NEVER persists after the response arrives.
// clearTimeout fires synchronously before setStage('done') is called.

const PIPELINE_STAGES = ['decode', 'simulate', 'rules', 'classifying'] as const;
type ActiveStage = typeof PIPELINE_STAGES[number];
type Stage = 'idle' | ActiveStage | 'done';

function EvaluateDemo({ onNewDecision }: { onNewDecision: () => void }) {
  const [selected, setSelected]   = useState<DemoKey>('block');
  const [stage, setStage]         = useState<Stage>('idle');
  const [elapsedMs, setElapsedMs] = useState<number | null>(null);
  const [verdict, setVerdict]     = useState<string | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  function clearTimers() {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  }

  async function runDemo() {
    if (stage !== 'idle' && stage !== 'done') return;
    clearTimers();
    setStage('decode');
    setElapsedMs(null);
    setVerdict(null);
    setEvalError(null);

    const t0 = performance.now();
    timers.current.push(setTimeout(() => setStage('simulate'),    200));
    timers.current.push(setTimeout(() => setStage('rules'),       1800));
    timers.current.push(setTimeout(() => setStage('classifying'), 1850));

    try {
      const resp = await fetch('/api/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(DEMO_OPTIONS[selected].tx),
      });
      const data = await resp.json() as { policy?: { verdict?: string } };
      // Clear timers BEFORE setting done — no pending timer can race past this point.
      clearTimers();
      setElapsedMs(performance.now() - t0);
      setVerdict(data.policy?.verdict ?? 'UNKNOWN');
      setStage('done');
      onNewDecision();
    } catch (e) {
      clearTimers();
      setEvalError(e instanceof Error ? e.message : 'Request failed');
      setStage('idle');
    }
  }

  const stageIdx = stage === 'idle' ? -1
    : stage === 'done' ? PIPELINE_STAGES.length
    : PIPELINE_STAGES.indexOf(stage as ActiveStage);

  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20, marginTop: 24 }}>
      <p style={{ fontSize: 10, fontWeight: 700, color: C.muted, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 14 }}>
        Demo — Evaluate Transaction
      </p>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        {(Object.keys(DEMO_OPTIONS) as DemoKey[]).map(k => (
          <button key={k} onClick={() => setSelected(k)} style={{
            ...btnS,
            background: selected === k ? C.border2 : 'transparent',
            color: selected === k ? C.text : C.muted,
            borderColor: selected === k ? '#475569' : C.border2,
          }}>
            {DEMO_OPTIONS[k].label}
          </button>
        ))}
        <button
          onClick={() => void runDemo()}
          disabled={stage !== 'idle' && stage !== 'done'}
          style={{ ...btnS, background: C.blueDark, color: '#dbeafe', borderColor: C.blueDark, marginLeft: 8, opacity: stage !== 'idle' && stage !== 'done' ? 0.6 : 1 }}
        >
          {stage === 'idle' || stage === 'done' ? 'Evaluate ▶' : 'Running…'}
        </button>
      </div>

      {stage !== 'idle' && (
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', marginBottom: 12, gap: 0 }}>
          {PIPELINE_STAGES.map((s, i) => {
            const isDone   = stageIdx > i;
            const isActive = stageIdx === i;
            return (
              <span key={s} style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{
                  fontFamily: 'ui-monospace, monospace', fontSize: 12,
                  color: isDone ? C.green : isActive ? C.text : C.dimmed,
                  fontWeight: isActive ? 600 : 400,
                }}>
                  {isDone ? `${s} ✓` : isActive ? `${s} ⟳` : s}
                </span>
                {i < PIPELINE_STAGES.length - 1 && (
                  <span style={{ color: C.dimmed, margin: '0 8px' }}>→</span>
                )}
              </span>
            );
          })}
        </div>
      )}

      {stage === 'done' && verdict && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <VerdictBadge verdict={verdict} />
          {elapsedMs != null && (
            <span style={{ color: C.muted, fontSize: 12 }}>
              Evaluated in {(elapsedMs / 1000).toFixed(1)}s
            </span>
          )}
        </div>
      )}

      {evalError && <p style={{ color: C.red, fontSize: 12, marginTop: 8 }}>{evalError}</p>}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [tab, setTab]             = useState<'feed' | 'escalation'>('feed');
  const [records, setRecords]     = useState<AuditRecord[]>([]);
  const [loading, setLoading]     = useState(true);
  const [verdict, setVerdict]     = useState('');
  const [pendingOnly, setPending] = useState(false);

  const fetchRecords = useCallback(async () => {
    const p = new URLSearchParams();
    if (verdict) p.set('verdict', verdict);
    if (tab === 'escalation' || pendingOnly) p.set('pendingHumanReview', 'true');
    try {
      const resp = await fetch(`/api/decisions?${p.toString()}`);
      if (resp.ok) setRecords(await resp.json() as AuditRecord[]);
    } finally {
      setLoading(false);
    }
  }, [tab, verdict, pendingOnly]);

  useEffect(() => {
    setLoading(true);
    void fetchRecords();
    const id = setInterval(() => void fetchRecords(), 5000);
    return () => clearInterval(id);
  }, [fetchRecords]);

  const pendingEscalations = records.filter(r => r.finalVerdict === 'ESCALATE' && r.humanVerdict === null);

  return (
    <div style={{ minHeight: '100vh', background: C.bg, color: C.text }}>

      <div style={{ borderBottom: `1px solid ${C.border2}`, padding: '12px 24px', display: 'flex', gap: 24, alignItems: 'center' }}>
        <h1 style={{ fontSize: 14, fontWeight: 700, letterSpacing: '0.03em', whiteSpace: 'nowrap' }}>
          Agent TX Firewall
        </h1>
        <nav style={{ display: 'flex', gap: 4 }}>
          {(['feed', 'escalation'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? C.border2 : 'transparent',
              border: 'none', borderRadius: 4, cursor: 'pointer',
              color: tab === t ? C.text : C.muted,
              fontSize: 13, padding: '5px 12px',
              fontWeight: tab === t ? 600 : 400,
            }}>
              {t === 'feed' ? 'Decision Feed' : (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  Escalation Queue
                  {pendingEscalations.length > 0 && (
                    <span style={{ background: C.yellow, color: C.bg, borderRadius: 10, padding: '0 6px', fontSize: 10, fontWeight: 700 }}>
                      {pendingEscalations.length}
                    </span>
                  )}
                </span>
              )}
            </button>
          ))}
        </nav>
        {loading && <span style={{ color: C.dimmed, fontSize: 11, marginLeft: 'auto' }}>refreshing…</span>}
      </div>

      <div style={{ maxWidth: 1200, margin: '0 auto', padding: 24 }}>

        {tab === 'feed' && (
          <>
            <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <select value={verdict} onChange={e => setVerdict(e.target.value)} style={{
                background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4,
                color: C.text, padding: '6px 10px', fontSize: 12,
              }}>
                <option value="">All verdicts</option>
                <option value="APPROVE">APPROVE</option>
                <option value="BLOCK">BLOCK</option>
                <option value="ESCALATE">ESCALATE</option>
              </select>
              <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, color: '#94a3b8', cursor: 'pointer' }}>
                <input type="checkbox" checked={pendingOnly} onChange={e => setPending(e.target.checked)} style={{ accentColor: C.yellow }} />
                Pending human review only
              </label>
              <span style={{ marginLeft: 'auto', color: C.dimmed, fontSize: 11 }}>
                {records.length} record{records.length !== 1 ? 's' : ''} · auto-refreshes every 5s
              </span>
            </div>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <DecisionFeed records={records} />
            </div>
          </>
        )}

        {tab === 'escalation' && (
          <>
            <p style={{ color: C.muted, fontSize: 12, marginBottom: 16 }}>
              Transactions requiring human review — awaiting APPROVE or REJECT.
            </p>
            {pendingEscalations.length === 0
              ? <p style={{ color: C.dimmed, textAlign: 'center', padding: '48px 0' }}>No pending escalations.</p>
              : pendingEscalations.map(r => (
                  <EscalationCard key={r.id} record={r} onResolved={() => void fetchRecords()} />
                ))}
          </>
        )}

        <EvaluateDemo onNewDecision={() => void fetchRecords()} />
      </div>
    </div>
  );
}
