import type { DecodedTransaction, RuleFlag, RuleFlagSeverity, SimulationResult } from '../types/index.js';
import type { PolicyConfig } from '../policy/index.js';

const SEVERITY_ORDER: Record<RuleFlagSeverity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3,
};

/**
 * Run deterministic rule checks against the decoded transaction and
 * simulation result. Returns all triggered flags sorted by severity.
 *
 * Rules checked:
 *  - DENYLIST_ADDRESS:      `to` or `recipient` in policy denylist            [CRITICAL]
 *  - UNLIMITED_APPROVAL:    isUnlimitedApproval === true (exact uint256.max)  [CRITICAL]
 *                           Near-max values (UINT256_MAX-1, 2^255, etc.) are
 *                           NOT flagged here — EXCESSIVE_APPROVAL handles them.
 *  - UNKNOWN_TX_TYPE:       txType === 'UNKNOWN' — unrecognized calldata.     [HIGH]
 *                           Covers swap selectors not in the known set.
 *                           Absence of this rule = fail-open for arbitrary calls.
 *  - EXCESSIVE_APPROVAL:    approvalAmount > threshold && !isUnlimitedApproval [HIGH]
 *                           Catches near-max phishing values.
 *                           Mutually exclusive with UNLIMITED_APPROVAL.
 *  - VALUE_EXCEEDS_CEILING: decoded.value > policy.spendCeilingWei            [HIGH]
 *  - UNKNOWN_RECIPIENT:     effective recipient not in allowlist               [MEDIUM]
 *  - SIMULATION_REVERTED:   simulation.success === false                       [MEDIUM]
 */
export async function applyRules(
  decoded: DecodedTransaction,
  simulation: SimulationResult,
  policy: PolicyConfig,
): Promise<RuleFlag[]> {
  const flags: RuleFlag[] = [];
  const denylist = new Set(policy.denylist.map(a => a.toLowerCase()));
  const allowlist = new Set(policy.allowlist.map(a => a.toLowerCase()));

  // ── DENYLIST_ADDRESS [CRITICAL] ────────────────────────────────────────────
  // Check both the contract target and the effective recipient — a denylisted
  // spender on an ERC-20 approve is just as dangerous as a denylisted `to`.
  const candidates = new Set([decoded.to.toLowerCase()]);
  if (decoded.recipient) candidates.add(decoded.recipient.toLowerCase());
  for (const addr of candidates) {
    if (denylist.has(addr)) {
      flags.push({
        ruleId: 'DENYLIST_ADDRESS',
        ruleName: 'Denylist Address',
        severity: 'CRITICAL',
        description: `Address ${addr} is in the configured denylist`,
        metadata: { address: addr },
      });
      break; // one flag per tx; verdict is BLOCK regardless of how many match
    }
  }

  // ── UNLIMITED_APPROVAL [CRITICAL] ─────────────────────────────────────────
  // Exact uint256.max only (derived from decoder.isUnlimitedApproval).
  // Near-max values intentionally fall through to EXCESSIVE_APPROVAL [HIGH].
  if (decoded.isUnlimitedApproval) {
    flags.push({
      ruleId: 'UNLIMITED_APPROVAL',
      ruleName: 'Unlimited Token Approval',
      severity: 'CRITICAL',
      description: `uint256.max approval to spender ${decoded.recipient}`,
      metadata: {
        spender: decoded.recipient,
        approvalAmount: decoded.approvalAmount?.toString(),
      },
    });
  }

  // ── UNKNOWN_TX_TYPE [HIGH] ────────────────────────────────────────────────
  // txType === 'UNKNOWN' means the decoder could not recognize the calldata —
  // this includes any swap selector not in selectors.SWAP_SELECTORS.
  // Severity HIGH → policy maps this to ESCALATE (never silent APPROVE).
  if (decoded.txType === 'UNKNOWN') {
    flags.push({
      ruleId: 'UNKNOWN_TX_TYPE',
      ruleName: 'Unknown Transaction Type',
      severity: 'HIGH',
      description: `Unrecognized calldata (selector: ${decoded.functionSelector ?? 'none'})`,
      metadata: { functionSelector: decoded.functionSelector },
    });
  }

  // ── EXCESSIVE_APPROVAL [HIGH] ─────────────────────────────────────────────
  // Fires when approvalAmount exceeds the configured threshold but is not
  // exactly uint256.max (which is CRITICAL above). This is the rule that
  // catches phishing patterns like UINT256_MAX-1 or 2^255.
  if (
    decoded.txType === 'ERC20_APPROVAL' &&
    decoded.approvalAmount !== null &&
    !decoded.isUnlimitedApproval
  ) {
    const threshold = BigInt(policy.rules.excessiveApproval.thresholdWei);
    if (decoded.approvalAmount > threshold) {
      flags.push({
        ruleId: 'EXCESSIVE_APPROVAL',
        ruleName: 'Excessive Token Approval',
        severity: 'HIGH',
        description: `Approval amount ${decoded.approvalAmount} exceeds threshold ${threshold}`,
        metadata: {
          approvalAmount: decoded.approvalAmount.toString(),
          thresholdWei: threshold.toString(),
          spender: decoded.recipient,
        },
      });
    }
  }

  // ── VALUE_EXCEEDS_CEILING [HIGH] ──────────────────────────────────────────
  const ceiling = BigInt(policy.spendCeilingWei);
  if (decoded.value > ceiling) {
    flags.push({
      ruleId: 'VALUE_EXCEEDS_CEILING',
      ruleName: 'Value Exceeds Spend Ceiling',
      severity: 'HIGH',
      description: `Native value ${decoded.value} wei exceeds ceiling ${ceiling} wei`,
      metadata: {
        value: decoded.value.toString(),
        ceilingWei: ceiling.toString(),
      },
    });
  }

  // ── UNKNOWN_RECIPIENT [MEDIUM] ────────────────────────────────────────────
  // Effective recipient: decoded.recipient for ERC-20 cases (actual spender /
  // token recipient), decoded.to as fallback for SWAP routers and UNKNOWN calls.
  const effectiveRecipient = (decoded.recipient ?? decoded.to).toLowerCase();
  if (!allowlist.has(effectiveRecipient)) {
    flags.push({
      ruleId: 'UNKNOWN_RECIPIENT',
      ruleName: 'Unknown Recipient',
      severity: 'MEDIUM',
      description: `Recipient ${effectiveRecipient} is not in the allowlist`,
      metadata: { recipient: effectiveRecipient },
    });
  }

  // ── SIMULATION_REVERTED [MEDIUM] ─────────────────────────────────────────
  if (!simulation.success) {
    flags.push({
      ruleId: 'SIMULATION_REVERTED',
      ruleName: 'Simulation Reverted',
      severity: 'MEDIUM',
      description: `Simulation reverted: ${simulation.errorMessage ?? 'unknown reason'}`,
      metadata: {
        errorMessage: simulation.errorMessage,
        simulationId: simulation.simulationId,
      },
    });
  }

  return flags.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
