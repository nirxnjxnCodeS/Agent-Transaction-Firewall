// service/eval/runner.ts
//
// Eval harness for the Agent TX Firewall.
// Run via:  npm run eval  (from service/ directory)
//
// Dataset:  service/src/eval/dataset.ts  (imported as ../src/eval/dataset.js)
// Results:  service/eval/results.json
//
// Starts anvil on :18546 and the firewall service on :3002 as child processes,
// runs all 100 labeled cases sequentially, writes a metrics report, and exits
// with code 0 (pass rate ≥ 80%) or 1.

import { spawn, type ChildProcess } from 'child_process';
import { writeFileSync, existsSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { keccak256, encodeAbiParameters, parseAbiParameters } from 'viem';
import { EVAL_DATASET, type EvalCase } from '../src/eval/dataset.js';

// ── Paths ─────────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const SVC_ROOT  = resolve(__dirname, '..');
const ANVIL_BIN = resolve(process.env.HOME!, '.foundry/bin/anvil');

function findBin(name: string): string {
  for (const dir of [
    resolve(SVC_ROOT, 'node_modules/.bin'),
    resolve(SVC_ROOT, '..', 'node_modules/.bin'),
  ]) {
    const p = resolve(dir, name);
    if (existsSync(p)) return p;
  }
  return name; // fall back to $PATH
}

const TSX_BIN = findBin('tsx');

// ── Constants ─────────────────────────────────────────────────────────────────

const ANVIL_PORT      = 18546;
const SERVICE_PORT    = 3002;
const ANVIL_URL       = `http://localhost:${ANVIL_PORT}`;
const SERVICE_URL     = `http://localhost:${SERVICE_PORT}`;
const CASE_TIMEOUT_MS = 45_000;   // 45s: classifier ≤ ~11s + simulator ≤ ~2s + overhead
const STARTUP_TIMEOUT = 60_000;
const PASS_RATE_GATE  = 0.80;

// Addresses used for pre-funding (WETH for Pattern I, USDC for Pattern F)
const AGENT_ADDR = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const WETH_ADDR  = '0x4200000000000000000000000000000000000006'; // Base Sepolia WETH
const USDC_ADDR  = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'; // Base Sepolia USDC

// Fork block pinned for reproducibility — agent has ~25 USDC here; pre-fund brings it to 10,000
const FORK_BLOCK = 44060967;

// ── Types ─────────────────────────────────────────────────────────────────────

interface PipelineResponse {
  policy?: {
    verdict?: string;
    triggeredPolicyRules?: string[];
    reason?: string;
  };
  classification?: { riskScore?: number } | null;
  simulation?: unknown | null;
}

type CaseStatus = 'pass' | 'fail' | 'error';

interface CaseResult {
  status: CaseStatus;
  caseId: string;
  description: string;
  attackPattern: string;
  groundTruthLabel: 'MALICIOUS' | 'BENIGN';
  expectedVerdict: string;
  actualVerdict: string | null;    // null on error
  riskScore: number | null;
  primaryRuleFired: string | null;
  pipelineStage: 'simulator' | 'classifier' | 'policy' | 'unknown';
  durationMs: number;
  errorMessage?: string;
}

interface FailureRecord {
  id: string;
  description: string;
  attackPattern: string;
  expected: string;
  actual: string;
  riskScore: number | null;
  primaryRuleFired: string | null;
  pipelineStage: 'simulator' | 'classifier' | 'policy' | 'unknown';
}

interface VerdictMetrics { precision: number; recall: number; fpr: number }

interface EvalReport {
  runAt: string;
  totalCases: number;
  passed: number;
  failed: number;
  errored: number;
  passRate: number;
  metrics: {
    byVerdict: Record<'BLOCK' | 'ESCALATE' | 'APPROVE', VerdictMetrics>;
    byPattern: Record<string, { total: number; passed: number; passRate: number }>;
    classifierScoreDistribution: {
      benignApprove: { min: number; max: number; mean: number; above50Count: number; sampleSize: number };
    };
  };
  failures: FailureRecord[];
  durationMs: number;
  meanCaseDurationMs: number;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

function elapsed(t0: number): number {
  return Math.round(performance.now() - t0);
}

function r2(n: number): number {
  return Math.round(n * 100) / 100;
}

// ── RPC helper ────────────────────────────────────────────────────────────────

async function rpc(method: string, params: unknown[] = []): Promise<unknown> {
  const resp = await fetch(ANVIL_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
  });
  const json = await resp.json() as { result?: unknown; error?: { message: string } };
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

// ── Process management ────────────────────────────────────────────────────────

async function startAnvil(): Promise<{ proc: ChildProcess; genesisBlock: number }> {
  const rpcUrl = process.env.BASE_SEPOLIA_RPC_URL;
  if (!rpcUrl) throw new Error('BASE_SEPOLIA_RPC_URL not set — add it to service/.env');

  const proc = spawn(ANVIL_BIN, [
    '--fork-url',          rpcUrl,
    '--fork-block-number', String(FORK_BLOCK), // pinned for reproducibility — same USDC/WETH state every run
    '--port',              String(ANVIL_PORT),
    '--chain-id',          '84532',
    '--silent',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  proc.stderr?.on('data', (d: Buffer) => {
    const msg = d.toString().trim();
    if (msg) process.stderr.write(`[anvil] ${msg}\n`);
  });
  proc.on('exit', code => {
    if (code !== null && code !== 0) process.stderr.write(`[anvil] exited with code ${code}\n`);
  });

  const deadline = Date.now() + STARTUP_TIMEOUT;
  while (Date.now() < deadline) {
    try {
      const hex = await rpc('eth_blockNumber') as string;
      const genesisBlock = parseInt(hex, 16);
      console.log(`[startup] anvil ready  :${ANVIL_PORT}  fork block ${genesisBlock}`);
      return { proc, genesisBlock };
    } catch {
      await sleep(500);
    }
  }
  proc.kill();
  throw new Error('Anvil did not become ready within 60s');
}

async function startService(): Promise<ChildProcess> {
  const proc = spawn(TSX_BIN, ['src/server.ts'], {
    cwd: SVC_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      PORT:            String(SERVICE_PORT),
      ANVIL_FORK_PORT: String(ANVIL_PORT),
    },
  });

  // Suppress routine stdout (request logs); surface only stderr errors
  proc.stdout?.resume();
  proc.stderr?.on('data', (d: Buffer) => {
    const msg = d.toString().trim();
    if (/error|Error|fatal|Fatal/.test(msg)) process.stderr.write(`[service] ${msg}\n`);
  });
  proc.on('exit', code => {
    if (code !== null && code !== 0) process.stderr.write(`[service] exited with code ${code}\n`);
  });

  const deadline = Date.now() + STARTUP_TIMEOUT;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${SERVICE_URL}/health`);
      if (resp.ok) {
        console.log(`[startup] service ready :${SERVICE_PORT}`);
        return proc;
      }
    } catch { /* not yet */ }
    await sleep(500);
  }
  proc.kill();
  throw new Error('Firewall service did not become ready within 60s');
}

function cleanup(anvil: ChildProcess | undefined, service: ChildProcess | undefined): void {
  for (const [name, proc] of [['service', service], ['anvil', anvil]] as const) {
    if (!proc || proc.exitCode !== null) continue;
    proc.kill('SIGTERM');
    setTimeout(() => {
      if (proc.exitCode === null) {
        proc.kill('SIGKILL');
        process.stderr.write(`[cleanup] force-killed ${name}\n`);
      }
    }, 3000).unref();
  }
}

// ── WETH pre-funding ──────────────────────────────────────────────────────────
// Pattern I cases use WETH transfer() which requires the agent to hold WETH.
// The fork agent starts with 0 WETH, so we deposit 10 ETH via WETH.deposit()
// before taking the initial snapshot — every test case inherits the balance.

async function prefundWeth(): Promise<void> {
  await rpc('anvil_setBalance', [AGENT_ADDR, `0x${(10n ** 20n).toString(16)}`]);
  await rpc('anvil_impersonateAccount', [AGENT_ADDR]);
  const txHash = await rpc('eth_sendTransaction', [{
    from:  AGENT_ADDR,
    to:    WETH_ADDR,
    data:  '0xd0e30db0', // WETH deposit()
    value: `0x${(10n ** 19n).toString(16)}`, // 10 ETH → 10 WETH
    gas:   '0x30000',
  }]) as string;
  // Poll for receipt — anvil fork mode mines async
  for (let i = 0; i < 20; i++) {
    const receipt = await rpc('eth_getTransactionReceipt', [txHash]);
    if (receipt) break;
    await sleep(250);
  }
  await rpc('anvil_stopImpersonatingAccount', [AGENT_ADDR]);
  console.log('[startup] agent pre-funded with 10 WETH via deposit()');
}

// ── USDC pre-funding ──────────────────────────────────────────────────────────
// Pattern F cases need the agent to hold USDC. At the pinned fork block the agent
// has ~25 USDC — not enough for F-005 (50) through F-007 (75).
// We probe ERC-20 mapping slots 0–30, verify with balanceOf, and set 10,000 USDC.
// Trying slots is more robust than hardcoding Circle USDC's internal slot index.

async function prefundUsdc(): Promise<void> {
  const target = 10_000n * 1_000_000n; // 10,000 USDC (6 decimals)
  const balanceOfData = '0x70a08231' + AGENT_ADDR.slice(2).padStart(64, '0');

  for (let i = 0n; i <= 30n; i++) {
    const storageSlot = keccak256(encodeAbiParameters(
      parseAbiParameters('address, uint256'),
      [AGENT_ADDR as `0x${string}`, i],
    ));
    await rpc('anvil_setStorageAt', [
      USDC_ADDR,
      storageSlot,
      `0x${target.toString(16).padStart(64, '0')}`,
    ]);
    const raw = await rpc('eth_call', [{ to: USDC_ADDR, data: balanceOfData }, 'latest']) as string;
    if (BigInt(raw) === target) {
      console.log(`[startup] agent pre-funded with 10,000 USDC (mapping slot ${i})`);
      return;
    }
    // Wrong slot — zero it out and try next
    await rpc('anvil_setStorageAt', [USDC_ADDR, storageSlot, `0x${'0'.repeat(64)}`]);
  }
  process.stderr.write('[startup] WARNING: could not find USDC balance slot — F-series USDC cases may revert\n');
}

// ── Fork state management ─────────────────────────────────────────────────────
//
// evm_snapshot / evm_revert pattern:
//   - Take initial snapshot after anvil is ready (before first case).
//   - Before each case: evm_revert to that snapshot (restores fork to genesis
//     state), then immediately evm_snapshot to get a fresh ID for the next case.
//   - Why re-snapshot after revert: evm_revert CONSUMES the snapshot ID; it
//     becomes invalid. A new snapshot must be taken for the next iteration.
//   - Cost: ~5ms per case vs ~500ms for anvil_reset with remote RPC.
//
// Fallback: if evm_revert throws (snapshot ID expired, fork corrupted),
// call anvil_reset (which re-forks from the pinned genesis block) then
// take a fresh snapshot. This logs a warning so you know it fired.

let snapshotId = '';

async function takeSnapshot(): Promise<void> {
  snapshotId = (await rpc('evm_snapshot')) as string;
}

async function resetToSnapshot(genesisBlock: number): Promise<void> {
  try {
    await rpc('evm_revert', [snapshotId]);
    // Consumed — take a fresh snapshot for the next case
    await takeSnapshot();
  } catch (err) {
    process.stderr.write(
      `[warn] evm_revert failed (${(err as Error).message}) — falling back to anvil_reset\n`,
    );
    await resetFork(genesisBlock);
    await takeSnapshot();
  }
}

async function resetFork(genesisBlock: number): Promise<void> {
  await rpc('anvil_reset', [{
    forking: {
      jsonRpcUrl:  process.env.BASE_SEPOLIA_RPC_URL!,
      blockNumber: genesisBlock,
    },
  }]);
}

// ── Pipeline stage inference ──────────────────────────────────────────────────

function inferStage(resp: PipelineResponse): 'simulator' | 'classifier' | 'policy' | 'unknown' {
  const rules = resp.policy?.triggeredPolicyRules ?? [];
  if (rules.includes('SIMULATOR_UNAVAILABLE')) return 'simulator';
  if (rules.includes('CLASSIFIER_UNAVAILABLE')) return 'classifier';
  if (resp.policy) return 'policy';
  return 'unknown';
}

// ── Per-case evaluation ───────────────────────────────────────────────────────

async function runCase(c: EvalCase): Promise<CaseResult> {
  const t0 = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CASE_TIMEOUT_MS);

  const base: Pick<CaseResult, 'caseId' | 'description' | 'attackPattern' | 'groundTruthLabel' | 'expectedVerdict'> = {
    caseId:           c.id,
    description:      c.description,
    attackPattern:    c.attackPattern,
    groundTruthLabel: c.groundTruthLabel,
    expectedVerdict:  c.expectedVerdict,
  };

  try {
    const body = {
      to:      c.tx.to,
      from:    c.tx.from,
      value:   c.tx.value.toString(),   // bigint → decimal string; server does BigInt(str)
      data:    c.tx.data,
      chainId: c.tx.chainId,
      ...(c.tx.nonce    != null ? { nonce:    c.tx.nonce }               : {}),
      ...(c.tx.gasLimit != null ? { gasLimit: c.tx.gasLimit.toString() } : {}),
    };

    const resp = await fetch(`${SERVICE_URL}/api/evaluate`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  controller.signal,
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      return {
        ...base, status: 'error', actualVerdict: null, riskScore: null,
        primaryRuleFired: null, pipelineStage: 'unknown',
        durationMs: elapsed(t0), errorMessage: `HTTP ${resp.status}: ${text}`,
      };
    }

    const response = await resp.json() as PipelineResponse;
    const actual           = response?.policy?.verdict ?? 'UNKNOWN';
    const riskScore        = response?.classification?.riskScore ?? null;
    const primaryRuleFired = response?.policy?.triggeredPolicyRules?.[0] ?? null;
    const pipelineStage    = inferStage(response);
    const pass             = actual === c.expectedVerdict;

    return {
      ...base,
      status:         pass ? 'pass' : 'fail',
      actualVerdict:  actual,
      riskScore,
      primaryRuleFired,
      pipelineStage,
      durationMs:     elapsed(t0),
    };

  } catch (err) {
    const msg = controller.signal.aborted
      ? `Timed out after ${CASE_TIMEOUT_MS}ms`
      : (err instanceof Error ? err.message : String(err));
    return {
      ...base, status: 'error', actualVerdict: null, riskScore: null,
      primaryRuleFired: null, pipelineStage: 'unknown',
      durationMs: elapsed(t0), errorMessage: msg,
    };
  } finally {
    clearTimeout(timer);
  }
}

// ── Progress ──────────────────────────────────────────────────────────────────

function printProgress(n: number, total: number, c: EvalCase, r: CaseResult): void {
  const icon   = r.status === 'pass' ? '✓' : r.status === 'fail' ? '✗' : '!';
  const pct    = ((n / total) * 100).toFixed(0).padStart(3);
  const ms     = String(r.durationMs).padStart(5);
  const suffix = r.status === 'fail'
    ? `  expected=${r.expectedVerdict} actual=${r.actualVerdict} rule=${r.primaryRuleFired ?? '—'}`
    : r.status === 'error'
    ? `  ERROR: ${r.errorMessage}`
    : '';
  console.log(`${icon} [${String(n).padStart(3)}/${total}] ${pct}%  ${c.id.padEnd(6)} ${ms}ms${suffix}`);
}

// ── Metrics ───────────────────────────────────────────────────────────────────

function buildReport(results: CaseResult[], durationMs: number): EvalReport {
  const passed  = results.filter(r => r.status === 'pass').length;
  const failed  = results.filter(r => r.status === 'fail').length;
  const errored = results.filter(r => r.status === 'error').length;

  // Precision/recall/fpr — only pass+fail cases have a known actual verdict
  const evaluated = results.filter(r => r.status !== 'error');
  const VERDICTS = ['BLOCK', 'ESCALATE', 'APPROVE'] as const;
  const byVerdict = {} as Record<'BLOCK' | 'ESCALATE' | 'APPROVE', VerdictMetrics>;

  for (const v of VERDICTS) {
    const tp = evaluated.filter(r => r.expectedVerdict === v && r.actualVerdict === v).length;
    const fp = evaluated.filter(r => r.expectedVerdict !== v && r.actualVerdict === v).length;
    const fn = evaluated.filter(r => r.expectedVerdict === v && r.actualVerdict !== v).length;
    const tn = evaluated.filter(r => r.expectedVerdict !== v && r.actualVerdict !== v).length;
    byVerdict[v] = {
      precision: (tp + fp) > 0 ? r2(tp / (tp + fp)) : 1,
      recall:    (tp + fn) > 0 ? r2(tp / (tp + fn)) : 1,
      fpr:       (fp + tn) > 0 ? r2(fp / (fp + tn)) : 0,
    };
  }

  // Per-pattern pass rate (key = first char of case ID: A–J)
  const byPattern: Record<string, { total: number; passed: number; passRate: number }> = {};
  for (const r of results) {
    const p = r.caseId[0];
    if (!byPattern[p]) byPattern[p] = { total: 0, passed: 0, passRate: 0 };
    byPattern[p].total++;
    if (r.status === 'pass') byPattern[p].passed++;
  }
  for (const p of Object.keys(byPattern)) {
    byPattern[p].passRate = r2(byPattern[p].passed / byPattern[p].total);
  }

  // Classifier score distribution for BENIGN cases that got APPROVE
  // (BLOCK/ESCALATE cases have classification=null due to CRITICAL short-circuit,
  // so we only have scores for cases that reached the classifier — all BENIGN ones)
  const benignApproveScores = results
    .filter(r => r.groundTruthLabel === 'BENIGN' && r.actualVerdict === 'APPROVE' && r.riskScore !== null)
    .map(r => r.riskScore as number);

  const benignApprove = benignApproveScores.length === 0
    ? { min: 0, max: 0, mean: 0, above50Count: 0, sampleSize: 0 }
    : {
        min:          Math.min(...benignApproveScores),
        max:          Math.max(...benignApproveScores),
        mean:         r2(benignApproveScores.reduce((a, b) => a + b, 0) / benignApproveScores.length),
        above50Count: benignApproveScores.filter(s => s > 50).length,
        sampleSize:   benignApproveScores.length,
      };

  // Failures — trimmed; full pipeline data is in the SQLite audit log
  const failures: FailureRecord[] = results
    .filter(r => r.status === 'fail')
    .map(r => ({
      id:              r.caseId,
      description:     r.description,
      attackPattern:   r.attackPattern,
      expected:        r.expectedVerdict,
      actual:          r.actualVerdict!,
      riskScore:       r.riskScore,
      primaryRuleFired: r.primaryRuleFired,
      pipelineStage:   r.pipelineStage,
    }));

  return {
    runAt:          new Date().toISOString(),
    totalCases:     results.length,
    passed, failed, errored,
    passRate:       r2(passed / results.length),
    metrics:        { byVerdict, byPattern, classifierScoreDistribution: { benignApprove } },
    failures,
    durationMs,
    meanCaseDurationMs: r2(durationMs / results.length),
  };
}

// ── Summary ───────────────────────────────────────────────────────────────────

function printSummary(report: EvalReport): void {
  const { passed, failed, errored, passRate, totalCases, durationMs, meanCaseDurationMs } = report;
  const gate = passRate >= PASS_RATE_GATE ? '✓ PASS' : '✗ FAIL';

  console.log('\n═══════════════════════════════════════════════════════');
  console.log(' EVAL RESULTS');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`  Overall   ${gate}  ${(passRate * 100).toFixed(1)}% pass rate`);
  console.log(`  Cases     ${totalCases} total  /  ${passed} pass  /  ${failed} fail  /  ${errored} error`);
  console.log(`  Time      ${(durationMs / 1000).toFixed(1)}s total  /  ${meanCaseDurationMs.toFixed(0)}ms mean`);

  console.log('\n  Per-verdict metrics (evaluated cases only, errors excluded):');
  console.log('  Verdict     Precision  Recall  FPR');
  for (const v of ['BLOCK', 'ESCALATE', 'APPROVE'] as const) {
    const m = report.metrics.byVerdict[v];
    console.log(`  ${v.padEnd(11)} ${pct(m.precision)}      ${pct(m.recall)}  ${pct(m.fpr)}`);
  }

  console.log('\n  Per-pattern pass rate:');
  const patterns = Object.entries(report.metrics.byPattern).sort(([a], [b]) => a.localeCompare(b));
  for (const [p, stat] of patterns) {
    const bar = '█'.repeat(Math.round(stat.passRate * 10)) + '░'.repeat(10 - Math.round(stat.passRate * 10));
    console.log(`  ${p}  ${bar}  ${stat.passed}/${stat.total}  ${(stat.passRate * 100).toFixed(0)}%`);
  }

  const dist = report.metrics.classifierScoreDistribution.benignApprove;
  console.log('\n  Classifier score distribution — BENIGN APPROVE cases:');
  console.log(`  n=${dist.sampleSize}  min=${dist.min}  max=${dist.max}  mean=${dist.mean}  above50=${dist.above50Count}`);
  if (dist.above50Count > 0) {
    console.log(`  ⚠ ${dist.above50Count} BENIGN case(s) scored >50 — calibration concern (threshold: escalate=50)`);
  }

  if (report.failures.length > 0) {
    console.log(`\n  Failures (${report.failures.length}):`);
    for (const f of report.failures) {
      console.log(`  ✗ ${f.id.padEnd(6)} expected=${f.expected} actual=${f.actual} score=${f.riskScore ?? 'n/a'} rule=${f.primaryRuleFired ?? '—'} stage=${f.pipelineStage}`);
    }
  }

  console.log('\n  Results written to service/eval/results.json');
  console.log('═══════════════════════════════════════════════════════\n');
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`.padStart(6);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`\nAgent TX Firewall — Eval Harness`);
  console.log(`${EVAL_DATASET.length} cases  |  anvil :${ANVIL_PORT}  |  service :${SERVICE_PORT}`);
  console.log(`BENIGN APPROVE cases will hit Claude (~9s each) — ~7-9 min total\n`);

  let anvil:   ChildProcess | undefined;
  let service: ChildProcess | undefined;

  try {
    const started = await startAnvil();
    anvil = started.proc;
    const { genesisBlock } = started;

    service = await startService();

    // Pre-fund balances before snapshotting — all cases inherit these
    await prefundWeth();   // 10 WETH for Pattern I
    await prefundUsdc();   // 10,000 USDC for Pattern F

    // Take initial snapshot — before any case runs
    await takeSnapshot();
    console.log(`[startup] initial snapshot taken (${snapshotId})\n`);

    const results: CaseResult[] = [];
    const runStart = performance.now();

    for (let i = 0; i < EVAL_DATASET.length; i++) {
      const c = EVAL_DATASET[i];

      // Reset to clean state before every case (not after — so a mid-case
      // error can't contaminate state AND be swallowed silently)
      await resetToSnapshot(genesisBlock);

      const result = await runCase(c);
      results.push(result);
      printProgress(i + 1, EVAL_DATASET.length, c, result);
    }

    const durationMs = Math.round(performance.now() - runStart);
    const report = buildReport(results, durationMs);

    writeFileSync(resolve(__dirname, 'results.json'), JSON.stringify(report, null, 2));
    printSummary(report);

    process.exit(report.passRate >= PASS_RATE_GATE ? 0 : 1);

  } finally {
    cleanup(anvil, service);
  }
}

main().catch(err => {
  console.error('\nFatal error:', err);
  process.exit(1);
});
