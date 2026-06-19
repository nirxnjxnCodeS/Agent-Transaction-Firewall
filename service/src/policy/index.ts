import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import type { ClassifierOutput, PolicyDecision, PolicyVerdict, RuleFlag, RuleFlagSeverity } from '../types/index.js';

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
    /** Fires when txType === 'UNKNOWN'; catches unrecognized swap selectors too. */
    unknownTxType: { action: PolicyVerdict };
    unknownRecipient: { action: PolicyVerdict };
    valueExceedsCeiling: { action: PolicyVerdict };
    simulationReverted: { action: PolicyVerdict };
  };
}

/**
 * Load and validate the YAML policy config from disk.
 * Defaults to `config/policy.yaml` relative to the service root.
 */
export function loadPolicy(configPath?: string): PolicyConfig {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const resolvedPath = configPath ?? resolve(__dirname, '../../config/policy.yaml');
  const raw = readFileSync(resolvedPath, 'utf8');
  return yaml.load(raw) as PolicyConfig;
}

/**
 * Apply the loaded policy to the rule flags and classifier output.
 * Deterministic — no I/O. Returns the verdict and which rule triggered it.
 *
 * `classification` is null when the orchestrator short-circuited before
 * calling the classifier (CRITICAL rule flag present). In that case steps
 * 3 and 5 below are skipped — the verdict is determined by rule flags alone.
 *
 * Precedence (highest to lowest):
 *  1. CRITICAL rule flag (DENYLIST_ADDRESS, UNLIMITED_APPROVAL) → per-rule action
 *     Note: orchestrator already short-circuited here — this is a safety net
 *     in case evaluate() is called directly without going through orchestrator.
 *  2. riskScore >= block threshold     → BLOCK   (skipped if classification null)
 *  3. HIGH rule flags                  → per-rule action
 *  4. riskScore >= escalate threshold  → ESCALATE (skipped if classification null)
 *  5. MEDIUM/LOW rule flags            → per-rule action
 *  6. Default                          → APPROVE
 */
export function evaluate(
  ruleFlags: RuleFlag[],
  classification: ClassifierOutput | null,
  policy: PolicyConfig,
): PolicyDecision {
  const bySeverity = (s: RuleFlagSeverity) => ruleFlags.filter(f => f.severity === s);

  // Step 1 — CRITICAL flags: verdict is determined by rule alone, no classifier vote.
  // DENYLIST_ADDRESS always BLOCKs; other CRITICAL rules use their configured action.
  const critical = bySeverity('CRITICAL');
  if (critical.length > 0) {
    const winner = pickHighestAction(critical, policy);
    return {
      verdict: winner.action,
      reason: winner.flag.description,
      triggeredPolicyRules: critical.map(f => f.ruleId),
    };
  }

  // Step 2 — risk score >= block threshold (skipped when classification is null).
  if (classification !== null && classification.riskScore >= policy.riskScoreThresholds.block) {
    return {
      verdict: 'BLOCK',
      reason: `Classifier risk score ${classification.riskScore} ≥ block threshold ${policy.riskScoreThresholds.block}`,
      triggeredPolicyRules: ['RISK_SCORE_BLOCK'],
    };
  }

  // Step 3 — HIGH flags.
  const high = bySeverity('HIGH');
  if (high.length > 0) {
    const winner = pickHighestAction(high, policy);
    return {
      verdict: winner.action,
      reason: high.map(f => f.description).join('; '),
      triggeredPolicyRules: high.map(f => f.ruleId),
    };
  }

  // Step 4 — risk score >= escalate threshold (skipped when classification is null).
  if (classification !== null && classification.riskScore >= policy.riskScoreThresholds.escalate) {
    return {
      verdict: 'ESCALATE',
      reason: `Classifier risk score ${classification.riskScore} ≥ escalate threshold ${policy.riskScoreThresholds.escalate}`,
      triggeredPolicyRules: ['RISK_SCORE_ESCALATE'],
    };
  }

  // Step 5 — MEDIUM / LOW flags.
  const mediumLow = [...bySeverity('MEDIUM'), ...bySeverity('LOW')];
  if (mediumLow.length > 0) {
    const winner = pickHighestAction(mediumLow, policy);
    if (winner.action !== 'APPROVE') {
      return {
        verdict: winner.action,
        reason: mediumLow.map(f => f.description).join('; '),
        triggeredPolicyRules: mediumLow.map(f => f.ruleId),
      };
    }
  }

  // Step 6 — default.
  return {
    verdict: 'APPROVE',
    reason: 'No risk signals detected',
    triggeredPolicyRules: [],
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** BLOCK > ESCALATE > APPROVE. Returns the flag with the highest-severity action. */
function pickHighestAction(
  flags: RuleFlag[],
  policy: PolicyConfig,
): { flag: RuleFlag; action: PolicyVerdict } {
  const SEVERITY: Record<PolicyVerdict, number> = { BLOCK: 2, ESCALATE: 1, APPROVE: 0 };
  let best = { flag: flags[0]!, action: actionForRule(flags[0]!, policy) };
  for (const flag of flags.slice(1)) {
    const action = actionForRule(flag, policy);
    if (SEVERITY[action] > SEVERITY[best.action]) {
      best = { flag, action };
    }
  }
  return best;
}

/**
 * Map a rule flag's ruleId to its configured policy action.
 * Unknown ruleIds default to ESCALATE (conservative fail-safe).
 */
function actionForRule(flag: RuleFlag, policy: PolicyConfig): PolicyVerdict {
  switch (flag.ruleId) {
    case 'DENYLIST_ADDRESS':    return 'BLOCK'; // denylist always blocks, no config entry
    case 'UNLIMITED_APPROVAL':  return policy.rules.unlimitedApproval.action;
    case 'EXCESSIVE_APPROVAL':  return policy.rules.excessiveApproval.action;
    case 'UNKNOWN_TX_TYPE':     return policy.rules.unknownTxType.action;
    case 'UNKNOWN_RECIPIENT':   return policy.rules.unknownRecipient.action;
    case 'VALUE_EXCEEDS_CEILING': return policy.rules.valueExceedsCeiling.action;
    case 'SIMULATION_REVERTED': return policy.rules.simulationReverted.action;
    default:                    return 'ESCALATE';
  }
}
