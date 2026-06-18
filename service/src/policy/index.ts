import type { ClassifierOutput, PolicyDecision, PolicyVerdict, RuleFlag } from '../types/index.js';

export interface PolicyConfig {
  /** Maximum native ETH value allowed without escalation, in wei (as string). */
  spendCeilingWei: string;
  riskScoreThresholds: {
    /** riskScore >= block  → BLOCK immediately. */
    block: number;
    /** riskScore >= escalate → ESCALATE for human review. */
    escalate: number;
  };
  /** Checksummed addresses that are always allowed as recipients. */
  allowlist: string[];
  /** Checksummed addresses that always result in BLOCK. */
  denylist: string[];
  rules: {
    unlimitedApproval: { action: PolicyVerdict };
    excessiveApproval: { thresholdWei: string; action: PolicyVerdict };
    unknownRecipient: { action: PolicyVerdict };
    valueExceedsCeiling: { action: PolicyVerdict };
  };
}

/**
 * Load and validate the YAML policy config from disk.
 * Defaults to `config/policy.yaml` relative to the service root.
 */
export function loadPolicy(configPath?: string): PolicyConfig {
  throw new Error('Not implemented');
}

/**
 * Apply the loaded policy to the rule flags and classifier output.
 * Deterministic — no I/O. Returns the verdict and which rule triggered it.
 *
 * Precedence (highest to lowest):
 *  1. Denylist address  → BLOCK
 *  2. CRITICAL rule flag (e.g., UNLIMITED_APPROVAL) → per-rule action
 *  3. riskScore >= block threshold → BLOCK
 *  4. HIGH rule flags → per-rule action
 *  5. riskScore >= escalate threshold → ESCALATE
 *  6. MEDIUM/LOW flags → per-rule action
 *  7. Default → APPROVE
 */
export function evaluate(
  ruleFlags: RuleFlag[],
  classification: ClassifierOutput,
  policy: PolicyConfig,
): PolicyDecision {
  throw new Error('Not implemented');
}
