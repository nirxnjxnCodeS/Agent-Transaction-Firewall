import type { DecodedTransaction, RuleFlag, SimulationResult } from '../types/index.js';
import type { PolicyConfig } from '../policy/index.js';

/**
 * Run deterministic rule checks against the decoded transaction and
 * simulation result. Returns all triggered flags in severity order.
 *
 * Rules checked:
 *  - UNLIMITED_APPROVAL: approvalAmount === uint256.max
 *  - EXCESSIVE_APPROVAL: approvalAmount > policy threshold
 *  - UNKNOWN_RECIPIENT: `to` / `recipient` not in policy allowlist
 *  - VALUE_EXCEEDS_CEILING: native value > policy spendCeilingWei
 *  - SIMULATION_REVERTED: simulation.success === false
 *  - DENYLIST_ADDRESS: `to` or `recipient` in policy denylist
 */
export async function applyRules(
  decoded: DecodedTransaction,
  simulation: SimulationResult,
  policy: PolicyConfig,
): Promise<RuleFlag[]> {
  throw new Error('Not implemented');
}
