import type { Decision, RawTransaction } from './types/index.js';

/**
 * Main pipeline entry point — called by AgentKit's action-provider hook
 * before any transaction reaches the wallet provider for signing.
 *
 * Pipeline order:
 *   1. decoder  — normalize calldata → DecodedTransaction
 *   2. simulator — Tenderly API → SimulationResult
 *   3. rules    — deterministic checks → RuleFlag[]
 *   4. classifier — Claude structured output → ClassifierOutput
 *   5. policy   — YAML thresholds → PolicyDecision
 *   6. audit    — persist full decision to DB
 *
 * Returns the completed Decision. Callers inspect `decision.policy.verdict`:
 *   - APPROVE  → pass tx to wallet provider for signing
 *   - BLOCK    → throw/reject — transaction never reaches signer
 *   - ESCALATE → suspend tx, surface via API for human review
 */
export async function evaluateTransaction(tx: RawTransaction): Promise<Decision> {
  throw new Error('Not implemented');
}
