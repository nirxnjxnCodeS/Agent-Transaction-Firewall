import { v4 as uuidv4 } from 'uuid';
import { decode } from './decoder/index.js';
import { simulate } from './simulator/index.js';
import { applyRules } from './rules/index.js';
import { classify, ClassifierError } from './classifier/index.js';
import { evaluate, loadPolicy } from './policy/index.js';
import { logDecision } from './audit/index.js';
import type { Decision, PolicyDecision, RawTransaction } from './types/index.js';

const policy = loadPolicy();

/**
 * Main pipeline entry point — called by AgentKit's action-provider hook
 * before any transaction reaches the wallet provider for signing.
 *
 * Returns the completed Decision. Callers inspect `decision.policy.verdict`:
 *   - APPROVE  → pass tx to wallet provider for signing
 *   - BLOCK    → throw/reject — transaction never reaches signer
 *   - ESCALATE → suspend tx, surface via API for human review
 */
export async function evaluateTransaction(tx: RawTransaction): Promise<Decision> {
  const id = uuidv4();
  const timestamp = new Date().toISOString();

  // ── Step 1: Decode ──────────────────────────────────────────────────────────
  //
  // Pure synchronous logic (no I/O); never throws in practice.
  // If it does throw (malformed calldata), propagate — it's a programming error,
  // not a recoverable pipeline state. The server's top-level handler catches
  // untyped errors and returns 500.
  const decoded = await decode(tx);

  // ── Step 2: Simulate ────────────────────────────────────────────────────────
  //
  // Calls the local anvil fork via JSON-RPC. CAN throw (fork not running, ECONNREFUSED).
  // On throw: immediate ESCALATE. Rules/classifier/policy.evaluate() are all skipped.
  // Rationale: rules require a SimulationResult; continuing with null would silently
  // skip SIMULATION_REVERTED checks. ESCALATE (not BLOCK) because a simulator failure
  // does not mean the transaction is malicious.
  let simulation;
  try {
    simulation = await simulate(decoded);
  } catch (_err) {
    const simulatorFailPolicy: PolicyDecision = {
      verdict: 'ESCALATE',
      reason: 'Simulator unavailable — human review required',
      triggeredPolicyRules: ['SIMULATOR_UNAVAILABLE'],
    };
    const decision: Decision = {
      id, timestamp, raw: tx, decoded,
      simulation: null,
      ruleFlags: [],
      classification: null,
      policy: simulatorFailPolicy,
      humanVerdict: null, humanTimestamp: null, humanNote: null,
    };
    await safeLog(decision);
    return decision;
  }

  // ── Step 3: Rules ───────────────────────────────────────────────────────────
  //
  // Deterministic; returns flags sorted CRITICAL → HIGH → MEDIUM → LOW.
  const ruleFlags = await applyRules(decoded, simulation, policy);

  // ── Step 4: CRITICAL short-circuit check ────────────────────────────────────
  //
  // If any flag has severity === 'CRITICAL':
  //   - Do NOT call classify(). Their verdict must not depend on Claude API availability.
  //   - Note: simulator already ran — simulation IS populated.
  //   - classification = null; proceed directly to Step 6.
  const hasCritical = ruleFlags.some(f => f.severity === 'CRITICAL');

  let classification = null;

  if (!hasCritical) {
    // ── Step 5: Classify ───────────────────────────────────────────────────────
    //
    // Only reached when no CRITICAL flags are present.
    // On ClassifierError: immediate ESCALATE. Do NOT call evaluate().
    // reason embeds err.type so the audit log distinguishes the failure mode
    // from a risk-score-triggered escalation.
    try {
      classification = await classify(decoded, simulation, ruleFlags);
    } catch (err) {
      if (err instanceof ClassifierError) {
        const classifierFailPolicy: PolicyDecision = {
          verdict: 'ESCALATE',
          reason: `Classifier unavailable (${err.type}) — human review required`,
          triggeredPolicyRules: ['CLASSIFIER_UNAVAILABLE'],
        };
        const decision: Decision = {
          id, timestamp, raw: tx, decoded,
          simulation,
          ruleFlags,
          classification: null,
          policy: classifierFailPolicy,
          humanVerdict: null, humanTimestamp: null, humanNote: null,
        };
        await safeLog(decision);
        return decision;
      }
      throw err;
    }
  }

  // ── Step 6: Policy ──────────────────────────────────────────────────────────
  //
  // Deterministic. classification is null only when CRITICAL flags were present.
  // evaluate() handles null correctly (skips risk score steps 2 and 4).
  const policyDecision = evaluate(ruleFlags, classification, policy);

  const decision: Decision = {
    id, timestamp, raw: tx, decoded,
    simulation,
    ruleFlags,
    classification,
    policy: policyDecision,
    humanVerdict: null, humanTimestamp: null, humanNote: null,
  };

  // ── Step 7: Audit ───────────────────────────────────────────────────────────
  //
  // Always runs, including for early-exit paths (handled above with safeLog).
  // A logging failure must not affect the verdict returned to the caller.
  await safeLog(decision);
  return decision;
}

async function safeLog(decision: Decision): Promise<void> {
  try {
    await logDecision(decision);
  } catch (err) {
    console.error('[audit] logDecision failed:', err);
  }
}
