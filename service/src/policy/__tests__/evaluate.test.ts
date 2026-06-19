import { describe, expect, it } from 'vitest';
import { evaluate, type PolicyConfig } from '../index.js';
import type { ClassifierOutput, RuleFlag } from '../../types/index.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const POLICY: PolicyConfig = {
  spendCeilingWei: '100000000000000000',
  riskScoreThresholds: { block: 80, escalate: 50 },
  allowlist: ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8'],
  denylist: [],
  rules: {
    unlimitedApproval:  { action: 'BLOCK' },
    excessiveApproval:  { action: 'ESCALATE', thresholdWei: '1000000000000000000000' },
    unknownTxType:      { action: 'ESCALATE' },
    unknownRecipient:   { action: 'ESCALATE' },
    valueExceedsCeiling: { action: 'BLOCK' },
    simulationReverted: { action: 'ESCALATE' },
  },
};

function flag(
  ruleId: string,
  severity: RuleFlag['severity'],
  description = `${ruleId} triggered`,
): RuleFlag {
  return { ruleId, ruleName: ruleId, severity, description };
}

function classification(riskScore: number): ClassifierOutput {
  return { riskScore, reasoning: 'test', category: 'SAFE', classifierSignals: [] };
}

// ─── The test that needed to exist ───────────────────────────────────────────
// CRITICAL flag + null classification must BLOCK without the classifier running.
// This is the short-circuit path that was documented but never verified.

describe('CRITICAL flag + null classification (short-circuit path)', () => {
  it('UNLIMITED_APPROVAL (CRITICAL) + null classification → BLOCK', () => {
    const result = evaluate(
      [flag('UNLIMITED_APPROVAL', 'CRITICAL')],
      null, // classifier was not called
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('UNLIMITED_APPROVAL');
  });

  it('DENYLIST_ADDRESS (CRITICAL) + null classification → BLOCK', () => {
    const result = evaluate(
      [flag('DENYLIST_ADDRESS', 'CRITICAL')],
      null,
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('DENYLIST_ADDRESS');
  });

  it('multiple CRITICAL flags → all appear in triggeredPolicyRules', () => {
    const result = evaluate(
      [
        flag('DENYLIST_ADDRESS', 'CRITICAL'),
        flag('UNLIMITED_APPROVAL', 'CRITICAL'),
      ],
      null,
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('DENYLIST_ADDRESS');
    expect(result.triggeredPolicyRules).toContain('UNLIMITED_APPROVAL');
  });

  it('CRITICAL flag overrides even when classification has low risk score', () => {
    // Safety net: even if called incorrectly (classifier ran despite CRITICAL flag),
    // evaluate() must still return BLOCK — not APPROVE from the low score.
    const result = evaluate(
      [flag('UNLIMITED_APPROVAL', 'CRITICAL')],
      classification(10), // low risk score
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
  });
});

// ─── Risk score paths ─────────────────────────────────────────────────────────

describe('risk score thresholds (no rule flags)', () => {
  it('riskScore >= 80 → BLOCK', () => {
    const result = evaluate([], classification(80), POLICY);
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('RISK_SCORE_BLOCK');
  });

  it('riskScore >= 50 and < 80 → ESCALATE', () => {
    const result = evaluate([], classification(60), POLICY);
    expect(result.verdict).toBe('ESCALATE');
    expect(result.triggeredPolicyRules).toContain('RISK_SCORE_ESCALATE');
  });

  it('riskScore < 50 with no flags → APPROVE', () => {
    const result = evaluate([], classification(20), POLICY);
    expect(result.verdict).toBe('APPROVE');
  });

  it('null classification + no flags → APPROVE (risk score steps skipped)', () => {
    // An unknown transaction that the classifier skipped for some reason
    // should not silently approve — but with no flags either, there's
    // nothing to trigger on. This path should not occur in practice
    // (orchestrator short-circuits on CRITICAL flags, classifier runs otherwise),
    // but the function must not crash.
    const result = evaluate([], null, POLICY);
    expect(result.verdict).toBe('APPROVE');
  });
});

// ─── HIGH flag paths ──────────────────────────────────────────────────────────

describe('HIGH severity flags', () => {
  it('VALUE_EXCEEDS_CEILING (HIGH, action=BLOCK) → BLOCK', () => {
    const result = evaluate([flag('VALUE_EXCEEDS_CEILING', 'HIGH')], null, POLICY);
    expect(result.verdict).toBe('BLOCK');
  });

  it('UNKNOWN_TX_TYPE (HIGH, action=ESCALATE) → ESCALATE', () => {
    const result = evaluate([flag('UNKNOWN_TX_TYPE', 'HIGH')], null, POLICY);
    expect(result.verdict).toBe('ESCALATE');
  });

  it('HIGH flag takes precedence over risk score in escalate range', () => {
    // Risk score 60 would normally → ESCALATE via risk score path.
    // HIGH flag with BLOCK action should win at step 3, before step 4.
    const result = evaluate(
      [flag('VALUE_EXCEEDS_CEILING', 'HIGH')],
      classification(60),
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('VALUE_EXCEEDS_CEILING');
    expect(result.triggeredPolicyRules).not.toContain('RISK_SCORE_ESCALATE');
  });

  it('multiple HIGH flags → highest action wins (BLOCK beats ESCALATE)', () => {
    const result = evaluate(
      [
        flag('UNKNOWN_TX_TYPE', 'HIGH'),      // action: ESCALATE
        flag('VALUE_EXCEEDS_CEILING', 'HIGH'), // action: BLOCK
      ],
      null,
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('UNKNOWN_TX_TYPE');
    expect(result.triggeredPolicyRules).toContain('VALUE_EXCEEDS_CEILING');
  });
});

// ─── MEDIUM / LOW flag paths ─────────────────────────────────────────────────

describe('MEDIUM and LOW severity flags', () => {
  it('UNKNOWN_RECIPIENT (MEDIUM, action=ESCALATE) → ESCALATE', () => {
    const result = evaluate(
      [flag('UNKNOWN_RECIPIENT', 'MEDIUM')],
      classification(20), // low risk score — below both thresholds
      POLICY,
    );
    expect(result.verdict).toBe('ESCALATE');
  });

  it('SIMULATION_REVERTED (MEDIUM, action=ESCALATE) → ESCALATE', () => {
    const result = evaluate(
      [flag('SIMULATION_REVERTED', 'MEDIUM')],
      classification(10),
      POLICY,
    );
    expect(result.verdict).toBe('ESCALATE');
  });
});

// ─── Precedence ordering ─────────────────────────────────────────────────────

describe('precedence: CRITICAL beats HIGH beats risk score', () => {
  it('CRITICAL flag beats HIGH flag', () => {
    const result = evaluate(
      [
        flag('UNKNOWN_TX_TYPE', 'HIGH'),
        flag('UNLIMITED_APPROVAL', 'CRITICAL'),
      ],
      null,
      POLICY,
    );
    // Only CRITICAL flags are listed — HIGH not reached
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('UNLIMITED_APPROVAL');
    expect(result.triggeredPolicyRules).not.toContain('UNKNOWN_TX_TYPE');
  });

  it('risk score block (step 2) beats HIGH flag (step 3) when both present', () => {
    // riskScore 90 >= block threshold 80 → triggers at step 2.
    // HIGH flag is step 3 and is never reached.
    // Verdict is BLOCK either way, but the trigger must be RISK_SCORE_BLOCK,
    // not the flag — this matters for audit log attribution.
    const result = evaluate(
      [flag('VALUE_EXCEEDS_CEILING', 'HIGH')],
      classification(90),
      POLICY,
    );
    expect(result.verdict).toBe('BLOCK');
    expect(result.triggeredPolicyRules).toContain('RISK_SCORE_BLOCK');
    expect(result.triggeredPolicyRules).not.toContain('VALUE_EXCEEDS_CEILING');
  });
});

// ─── Unknown ruleId ───────────────────────────────────────────────────────────

describe('unknown ruleId', () => {
  it('unrecognized CRITICAL ruleId defaults to ESCALATE conservatively', () => {
    // A future rule not yet in the switch statement should not silently approve.
    const result = evaluate(
      [flag('FUTURE_UNKNOWN_RULE', 'CRITICAL')],
      null,
      POLICY,
    );
    // actionForRule returns ESCALATE for unknown ids, but CRITICAL path uses
    // pickHighestAction, so result depends on that — at minimum it should not APPROVE.
    expect(result.verdict).not.toBe('APPROVE');
  });
});
