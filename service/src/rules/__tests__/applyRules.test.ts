import { describe, expect, it } from 'vitest';
import { applyRules } from '../index.js';
import { UINT256_MAX } from '../../decoder/selectors.js';
import type { DecodedTransaction, RawTransaction, SimulationResult } from '../../types/index.js';
import type { PolicyConfig } from '../../policy/index.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const ADDR = {
  agent:   '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  alice:   '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  bob:     '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
  token:   '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  spender: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  bad:     '0xBaD0000000000000000000000000000000000000',
  // Base Sepolia DEX routers — verified from docs.uniswap.org
  uniswapSwapRouter02:   '0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4',
  uniswapUniversalRouter: '0x492E6456D9528771018DeB9E87ef7750EF184104',
  unknownRouter:          '0xDEAD000000000000000000000000000000000001',
} as const;

const RULES = {
  unlimitedApproval:   { action: 'BLOCK' as const },
  excessiveApproval:   { action: 'ESCALATE' as const, thresholdWei: '1000000000000000000000' },
  unknownTxType:       { action: 'ESCALATE' as const },
  unknownRecipient:    { action: 'ESCALATE' as const },
  valueExceedsCeiling: { action: 'BLOCK' as const },
  simulationReverted:  { action: 'ESCALATE' as const },
};

const POLICY: PolicyConfig = {
  spendCeilingWei: '100000000000000000',
  riskScoreThresholds: { block: 80, escalate: 50 },
  allowlist: [ADDR.alice.toLowerCase()],
  denylist:  [ADDR.bad.toLowerCase()],
  rules: RULES,
};

// Policy that mirrors policy.yaml: Base Sepolia routers in allowlist,
// unknownRecipient.action stays ESCALATE for everything else.
const POLICY_WITH_ROUTERS: PolicyConfig = {
  ...POLICY,
  allowlist: [
    ADDR.alice.toLowerCase(),
    ADDR.uniswapSwapRouter02.toLowerCase(),
    ADDR.uniswapUniversalRouter.toLowerCase(),
  ],
};

const RAW: RawTransaction = {
  to: ADDR.alice, from: ADDR.agent, value: 0n, data: '0x', chainId: 84532,
};

function decoded(overrides: Partial<DecodedTransaction> = {}): DecodedTransaction {
  return {
    raw: RAW,
    txType: 'NATIVE_TRANSFER',
    functionSelector: null,
    functionName: null,
    to: ADDR.alice,
    from: ADDR.agent,
    value: 0n,
    tokenAddress: null,
    recipient: ADDR.alice,   // alice is in allowlist → no UNKNOWN_RECIPIENT by default
    amount: null,
    approvalAmount: null,
    isUnlimitedApproval: false,
    ...overrides,
  };
}

function sim(overrides: Partial<SimulationResult> = {}): SimulationResult {
  return {
    success: true,
    gasUsed: 21000n,
    stateChanges: [],
    logs: [],
    errorMessage: null,
    simulationId: 'sim-test',
    ...overrides,
  };
}

function flagIds(flags: Awaited<ReturnType<typeof applyRules>>) {
  return flags.map(f => f.ruleId);
}

// ─── Question 1: near-max approvals ──────────────────────────────────────────
// decoder explicitly punted threshold detection to rules/.
// Verify UNLIMITED_APPROVAL fires only on exact max, and EXCESSIVE_APPROVAL
// catches the phishing values the decoder tests pinned.

describe('near-max approval handling (the decoder hand-off)', () => {
  const approvalBase = {
    txType: 'ERC20_APPROVAL' as const,
    to: ADDR.token,
    tokenAddress: ADDR.token,
    recipient: ADDR.alice, // in allowlist so no UNKNOWN_RECIPIENT noise
  };

  it('exact uint256.max → UNLIMITED_APPROVAL [CRITICAL], NOT EXCESSIVE_APPROVAL', async () => {
    const flags = await applyRules(
      decoded({ ...approvalBase, approvalAmount: UINT256_MAX, isUnlimitedApproval: true }),
      sim(),
      POLICY,
    );
    const ids = flagIds(flags);
    expect(ids).toContain('UNLIMITED_APPROVAL');
    expect(ids).not.toContain('EXCESSIVE_APPROVAL');
    expect(flags.find(f => f.ruleId === 'UNLIMITED_APPROVAL')?.severity).toBe('CRITICAL');
  });

  it('UINT256_MAX - 1 → EXCESSIVE_APPROVAL [HIGH], NOT UNLIMITED_APPROVAL', async () => {
    const flags = await applyRules(
      decoded({ ...approvalBase, approvalAmount: UINT256_MAX - 1n, isUnlimitedApproval: false }),
      sim(),
      POLICY,
    );
    const ids = flagIds(flags);
    expect(ids).toContain('EXCESSIVE_APPROVAL');
    expect(ids).not.toContain('UNLIMITED_APPROVAL');
    expect(flags.find(f => f.ruleId === 'EXCESSIVE_APPROVAL')?.severity).toBe('HIGH');
  });

  it('2^255 → EXCESSIVE_APPROVAL [HIGH], NOT UNLIMITED_APPROVAL', async () => {
    const flags = await applyRules(
      decoded({ ...approvalBase, approvalAmount: 2n ** 255n, isUnlimitedApproval: false }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).toContain('EXCESSIVE_APPROVAL');
    expect(flagIds(flags)).not.toContain('UNLIMITED_APPROVAL');
  });

  it('2^254 → EXCESSIVE_APPROVAL [HIGH]', async () => {
    const flags = await applyRules(
      decoded({ ...approvalBase, approvalAmount: 2n ** 254n, isUnlimitedApproval: false }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).toContain('EXCESSIVE_APPROVAL');
  });

  it('approval below threshold → no approval flag', async () => {
    const smallAmount = 100n * 10n ** 18n; // 100 tokens, well below 1000-token threshold
    const flags = await applyRules(
      decoded({ ...approvalBase, approvalAmount: smallAmount, isUnlimitedApproval: false }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).not.toContain('UNLIMITED_APPROVAL');
    expect(flagIds(flags)).not.toContain('EXCESSIVE_APPROVAL');
  });
});

// ─── Question 2: UNKNOWN_TX_TYPE severity and action ─────────────────────────
// Verify the unrecognized-swap-selector case is real code, not just a comment.

describe('UNKNOWN_TX_TYPE — unrecognized calldata (including unknown swap selectors)', () => {
  it('txType UNKNOWN → UNKNOWN_TX_TYPE flag with severity HIGH', async () => {
    const flags = await applyRules(
      decoded({
        txType: 'UNKNOWN',
        functionSelector: '0xdeadbeef',
        recipient: null,
        to: ADDR.alice,
      }),
      sim(),
      POLICY,
    );
    const flag = flags.find(f => f.ruleId === 'UNKNOWN_TX_TYPE');
    expect(flag).toBeDefined();
    expect(flag?.severity).toBe('HIGH');
    expect(flag?.metadata?.functionSelector).toBe('0xdeadbeef');
  });

  it('unrecognized swap selector reaches rules/ as UNKNOWN — same HIGH flag fires', async () => {
    // In decoder, any selector not in SWAP_SELECTORS set falls to txType UNKNOWN.
    // This test verifies the chain is complete: unrecognized selector → UNKNOWN
    // txType → UNKNOWN_TX_TYPE flag → policy maps HIGH + action:ESCALATE → ESCALATE.
    // Here we just verify rules/ fires the flag; policy mapping is verified in policy tests.
    const flags = await applyRules(
      decoded({
        txType: 'UNKNOWN',
        functionSelector: '0xcafebabe', // not in SWAP_SELECTORS
        recipient: null,
        to: ADDR.alice,
      }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).toContain('UNKNOWN_TX_TYPE');
    expect(flags.find(f => f.ruleId === 'UNKNOWN_TX_TYPE')?.severity).toBe('HIGH');
  });

  it('known swap selector (SWAP txType) → no UNKNOWN_TX_TYPE flag', async () => {
    const flags = await applyRules(
      decoded({ txType: 'SWAP', to: ADDR.token, recipient: null }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).not.toContain('UNKNOWN_TX_TYPE');
  });
});

// ─── DENYLIST_ADDRESS ─────────────────────────────────────────────────────────

describe('DENYLIST_ADDRESS', () => {
  it('denylisted `to` address → CRITICAL flag', async () => {
    const flags = await applyRules(
      decoded({ to: ADDR.bad, recipient: ADDR.bad }),
      sim(),
      POLICY,
    );
    const flag = flags.find(f => f.ruleId === 'DENYLIST_ADDRESS');
    expect(flag?.severity).toBe('CRITICAL');
  });

  it('denylisted spender in ERC-20 approve → CRITICAL flag', async () => {
    const flags = await applyRules(
      decoded({
        txType: 'ERC20_APPROVAL',
        to: ADDR.token,        // token contract — not denylisted
        recipient: ADDR.bad,   // spender — denylisted
        approvalAmount: 1n,
        isUnlimitedApproval: false,
      }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).toContain('DENYLIST_ADDRESS');
    expect(flags.find(f => f.ruleId === 'DENYLIST_ADDRESS')?.severity).toBe('CRITICAL');
  });

  it('clean address → no DENYLIST_ADDRESS flag', async () => {
    const flags = await applyRules(decoded(), sim(), POLICY);
    expect(flagIds(flags)).not.toContain('DENYLIST_ADDRESS');
  });
});

// ─── VALUE_EXCEEDS_CEILING ────────────────────────────────────────────────────

describe('VALUE_EXCEEDS_CEILING', () => {
  it('value above ceiling → HIGH flag', async () => {
    const flags = await applyRules(
      decoded({ value: 200000000000000000n }), // 0.2 ETH > 0.1 ETH ceiling
      sim(),
      POLICY,
    );
    const flag = flags.find(f => f.ruleId === 'VALUE_EXCEEDS_CEILING');
    expect(flag?.severity).toBe('HIGH');
  });

  it('value exactly at ceiling → no flag', async () => {
    const flags = await applyRules(
      decoded({ value: 100000000000000000n }), // exactly 0.1 ETH
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).not.toContain('VALUE_EXCEEDS_CEILING');
  });

  it('value below ceiling → no flag', async () => {
    const flags = await applyRules(decoded({ value: 1000n }), sim(), POLICY);
    expect(flagIds(flags)).not.toContain('VALUE_EXCEEDS_CEILING');
  });
});

// ─── UNKNOWN_RECIPIENT ────────────────────────────────────────────────────────

describe('UNKNOWN_RECIPIENT', () => {
  it('recipient not in allowlist → MEDIUM flag', async () => {
    const flags = await applyRules(
      decoded({ recipient: ADDR.bob }), // bob is not in allowlist
      sim(),
      POLICY,
    );
    const flag = flags.find(f => f.ruleId === 'UNKNOWN_RECIPIENT');
    expect(flag?.severity).toBe('MEDIUM');
  });

  it('recipient in allowlist → no flag', async () => {
    const flags = await applyRules(
      decoded({ recipient: ADDR.alice }), // alice is in allowlist
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).not.toContain('UNKNOWN_RECIPIENT');
  });

  it('null recipient falls back to `to` address for allowlist check', async () => {
    // SWAP and UNKNOWN have null recipient; decoded.to is the fallback
    const flags = await applyRules(
      decoded({ txType: 'SWAP', recipient: null, to: ADDR.bob }),
      sim(),
      POLICY,
    );
    expect(flagIds(flags)).toContain('UNKNOWN_RECIPIENT');
  });
});

// ─── SIMULATION_REVERTED ──────────────────────────────────────────────────────

describe('SIMULATION_REVERTED', () => {
  it('simulation failure → MEDIUM flag with error message', async () => {
    const flags = await applyRules(
      decoded(),
      sim({ success: false, errorMessage: 'ERC20: transfer amount exceeds balance' }),
      POLICY,
    );
    const flag = flags.find(f => f.ruleId === 'SIMULATION_REVERTED');
    expect(flag?.severity).toBe('MEDIUM');
    expect(flag?.metadata?.errorMessage).toBe('ERC20: transfer amount exceeds balance');
  });

  it('successful simulation → no flag', async () => {
    const flags = await applyRules(decoded(), sim({ success: true }), POLICY);
    expect(flagIds(flags)).not.toContain('SIMULATION_REVERTED');
  });
});

// ─── Clean transaction ────────────────────────────────────────────────────────

describe('clean transaction', () => {
  it('small native transfer to allowlisted address → no flags', async () => {
    const flags = await applyRules(
      decoded({ to: ADDR.alice, recipient: ADDR.alice, value: 1000n }),
      sim(),
      POLICY,
    );
    expect(flags).toHaveLength(0);
  });
});

// ─── Base Sepolia DEX router allowlist ───────────────────────────────────────

describe('Base Sepolia DEX router allowlist', () => {
  it('SWAP to allowlisted Uniswap SwapRouter02 → no UNKNOWN_RECIPIENT flag', async () => {
    const flags = await applyRules(
      decoded({
        txType: 'SWAP',
        to: ADDR.uniswapSwapRouter02,
        recipient: null, // swaps have no decoded recipient; fallback is decoded.to
      }),
      sim(),
      POLICY_WITH_ROUTERS,
    );
    expect(flagIds(flags)).not.toContain('UNKNOWN_RECIPIENT');
  });

  it('SWAP to allowlisted Uniswap UniversalRouter → no UNKNOWN_RECIPIENT flag', async () => {
    const flags = await applyRules(
      decoded({
        txType: 'SWAP',
        to: ADDR.uniswapUniversalRouter,
        recipient: null,
      }),
      sim(),
      POLICY_WITH_ROUTERS,
    );
    expect(flagIds(flags)).not.toContain('UNKNOWN_RECIPIENT');
  });

  it('SWAP to unlisted router → UNKNOWN_RECIPIENT fires, unknownRecipient.action stays ESCALATE', async () => {
    // unknownRecipient.action is ESCALATE in POLICY_WITH_ROUTERS — not flipped to APPROVE.
    const flags = await applyRules(
      decoded({
        txType: 'SWAP',
        to: ADDR.unknownRouter,
        recipient: null,
      }),
      sim(),
      POLICY_WITH_ROUTERS,
    );
    const flag = flags.find(f => f.ruleId === 'UNKNOWN_RECIPIENT');
    expect(flag).toBeDefined();
    expect(flag?.severity).toBe('MEDIUM');
    // Confirm the action the flag maps to in policy (not evaluate()'s job here,
    // but assert the rule config hasn't been changed to APPROVE as a workaround)
    expect(POLICY_WITH_ROUTERS.rules.unknownRecipient.action).toBe('ESCALATE');
  });
});

// ─── Severity ordering ────────────────────────────────────────────────────────

describe('output ordering', () => {
  it('flags are returned CRITICAL → HIGH → MEDIUM regardless of detection order', async () => {
    // Trigger CRITICAL (unlimited approval), HIGH (value ceiling), MEDIUM (sim revert)
    const flags = await applyRules(
      decoded({
        txType: 'ERC20_APPROVAL',
        to: ADDR.token,
        recipient: ADDR.alice,
        approvalAmount: UINT256_MAX,
        isUnlimitedApproval: true,
        value: 200000000000000000n, // > ceiling
      }),
      sim({ success: false, errorMessage: 'reverted' }),
      POLICY,
    );
    const severities = flags.map(f => f.severity);
    // Verify each element is >= the previous in severity order
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    for (let i = 1; i < severities.length; i++) {
      expect(order[severities[i]!]).toBeGreaterThanOrEqual(order[severities[i - 1]!]);
    }
  });
});
