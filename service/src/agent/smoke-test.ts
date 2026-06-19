/**
 * End-to-end smoke test — runs two scenarios against the live firewall service.
 *
 * Requires:
 *   - anvil fork running:  npm run anvil:fork
 *   - service running:     npm run dev
 *   - ANTHROPIC_API_KEY set in .env (for Scenario 2 APPROVE verdict)
 *
 * Run: tsx src/agent/smoke-test.ts
 */

import 'dotenv/config';
import { encodeFunctionData, maxUint256, parseAbi } from 'viem';

const FIREWALL = process.env.FIREWALL_URL ?? 'http://localhost:3001';

// Well-known test addresses — Hardhat/anvil defaults.
const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // account #0
const ALLOWLISTED_RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'; // account #1, in policy.yaml allowlist
const DUMMY_SPENDER = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

const bigintReplacer = (_k: string, v: unknown) =>
  typeof v === 'bigint' ? v.toString() : v;

interface FirewallDecision {
  id: string;
  policy: { verdict: string; reason: string; triggeredPolicyRules: string[] };
  ruleFlags: Array<{ ruleId: string; severity: string }>;
  classification: { riskScore: number; category: string } | null;
}

async function evaluate(tx: object): Promise<FirewallDecision> {
  const resp = await fetch(`${FIREWALL}/api/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tx, bigintReplacer),
  });
  if (!resp.ok) throw new Error(`/api/evaluate returned ${resp.status}: ${await resp.text()}`);
  return resp.json() as Promise<FirewallDecision>;
}

function pass(label: string) {
  console.log(`  ✓ ${label}`);
}

function fail(label: string, got: string, expected: string): never {
  console.error(`  ✗ ${label}`);
  console.error(`    expected: ${expected}`);
  console.error(`    got:      ${got}`);
  process.exit(1);
}

async function main() {
  console.log(`\nFirewall smoke test — ${FIREWALL}\n`);
  console.log('══════════════════════════════════════════════════════');

  // ── Scenario 1: Unlimited ERC-20 approval → BLOCK ─────────────────────────
  // UNLIMITED_APPROVAL is CRITICAL. Rules fire, classifier is skipped,
  // policy maps CRITICAL → BLOCK. No ANTHROPIC_API_KEY required.

  console.log('\nScenario 1: Unlimited ERC-20 approval');

  const unlimitedCalldata = encodeFunctionData({
    abi: parseAbi(['function approve(address spender, uint256 amount) returns (bool)']),
    functionName: 'approve',
    args: [DUMMY_SPENDER as `0x${string}`, maxUint256],
  });

  const d1 = await evaluate({
    to: USDC_BASE_SEPOLIA,
    from: SENDER,
    value: '0',
    data: unlimitedCalldata,
    chainId: 84532,
  });

  console.log(`  Verdict:         ${d1.policy.verdict}`);
  console.log(`  Reason:          ${d1.policy.reason}`);
  console.log(`  Triggered rules: ${JSON.stringify(d1.policy.triggeredPolicyRules)}`);
  console.log(`  Rule flags:      ${d1.ruleFlags.map(f => `${f.severity}:${f.ruleId}`).join(', ')}`);
  console.log(`  Classification:  ${d1.classification ? `score=${d1.classification.riskScore}` : 'null (skipped — CRITICAL short-circuit)'}`);
  console.log(`  Decision ID:     ${d1.id}`);

  if (d1.policy.verdict !== 'BLOCK')
    fail('verdict', d1.policy.verdict, 'BLOCK');
  if (!d1.policy.triggeredPolicyRules.includes('UNLIMITED_APPROVAL'))
    fail('triggeredPolicyRules contains UNLIMITED_APPROVAL', JSON.stringify(d1.policy.triggeredPolicyRules), '["UNLIMITED_APPROVAL"]');
  if (d1.classification !== null)
    fail('classification skipped on CRITICAL path', 'non-null', 'null');

  pass('verdict = BLOCK');
  pass('triggered rule = UNLIMITED_APPROVAL');
  pass('classification = null (classifier not called)');

  // ── Scenario 2: Allowlisted small native transfer → APPROVE ───────────────
  // 0.001 ETH to an address in the allowlist:
  //   - No CRITICAL flags
  //   - No HIGH flags (small value, known txType, allowlisted recipient)
  //   - No MEDIUM flags (allowlisted → no UNKNOWN_RECIPIENT; simulation succeeds)
  //   - Classifier runs → expects low risk score → APPROVE
  //
  // Requires ANTHROPIC_API_KEY. Without it, verdict will be ESCALATE
  // with triggeredPolicyRules: ["CLASSIFIER_UNAVAILABLE"].

  console.log('\nScenario 2: Small native ETH transfer to allowlisted recipient');

  const d2 = await evaluate({
    to: ALLOWLISTED_RECIPIENT,
    from: SENDER,
    value: String(10n ** 15n), // 0.001 ETH — well under 0.1 ETH ceiling
    data: '0x',
    chainId: 84532,
  });

  console.log(`  Verdict:         ${d2.policy.verdict}`);
  console.log(`  Reason:          ${d2.policy.reason}`);
  console.log(`  Triggered rules: ${JSON.stringify(d2.policy.triggeredPolicyRules)}`);
  console.log(`  Rule flags:      ${d2.ruleFlags.length === 0 ? 'none' : d2.ruleFlags.map(f => `${f.severity}:${f.ruleId}`).join(', ')}`);
  console.log(`  Classification:  ${d2.classification ? `score=${d2.classification.riskScore} category=${d2.classification.category}` : 'null'}`);
  console.log(`  Decision ID:     ${d2.id}`);

  if (d2.policy.verdict === 'ESCALATE' && d2.policy.triggeredPolicyRules.includes('CLASSIFIER_UNAVAILABLE')) {
    console.error('\n  ✗ APPROVE blocked: classifier unavailable (ANTHROPIC_API_KEY not set in .env)');
    console.error('    Add ANTHROPIC_API_KEY=sk-ant-... to service/.env and rerun.');
    process.exit(1);
  }

  if (d2.policy.verdict !== 'APPROVE')
    fail('verdict', d2.policy.verdict, 'APPROVE');
  if (d2.ruleFlags.length !== 0)
    fail('no rule flags expected', d2.ruleFlags.map(f => f.ruleId).join(', '), 'none');
  if (!d2.classification || d2.classification.riskScore >= 50)
    fail('riskScore < 50', String(d2.classification?.riskScore), '< 50');

  pass('verdict = APPROVE');
  pass('zero rule flags');
  pass(`riskScore = ${d2.classification.riskScore} (< 50)`);

  // ── Audit log verification ────────────────────────────────────────────────

  console.log('\nAudit log (GET /api/decisions)');

  const listResp = await fetch(`${FIREWALL}/api/decisions`);
  const records = await listResp.json() as Array<{ id: string; finalVerdict: string }>;

  const r1 = records.find(r => r.id === d1.id);
  const r2 = records.find(r => r.id === d2.id);

  if (!r1) fail('BLOCK record in audit log', 'missing', d1.id);
  if (!r2) fail('APPROVE record in audit log', 'missing', d2.id);

  pass(`BLOCK record persisted  (id=${d1.id})`);
  pass(`APPROVE record persisted (id=${d2.id})`);
  console.log(`  Total decisions logged: ${records.length}`);

  console.log('\n══════════════════════════════════════════════════════');
  console.log('Smoke test PASSED ✓\n');
}

main().catch(err => {
  console.error('\nSmoke test error:', err.message ?? err);
  process.exit(1);
});
