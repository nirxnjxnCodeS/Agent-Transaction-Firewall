import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ClassifierError, buildUserMessage, classify } from '../index.js';
import type { DecodedTransaction, RawTransaction, SimulationResult } from '../../types/index.js';
import type { RuleFlag } from '../../types/index.js';

// ─── SDK mock ─────────────────────────────────────────────────────────────────
// Hoisted so it exists before vi.mock() runs the factory.

const mockCreate = vi.hoisted(() => vi.fn());

vi.mock('@anthropic-ai/sdk', () => ({
  default: vi.fn().mockImplementation(() => ({
    messages: { create: mockCreate },
  })),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const RAW: RawTransaction = {
  to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  value: 0n,
  data: '0x',
  chainId: 84532,
};

const DECODED: DecodedTransaction = {
  raw: RAW,
  txType: 'ERC20_TRANSFER',
  functionSelector: '0xa9059cbb',
  functionName: 'transfer',
  to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  value: 0n,
  tokenAddress: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  recipient: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  amount: 500n * 10n ** 6n,
  approvalAmount: null,
  isUnlimitedApproval: false,
};

const SIM: SimulationResult = {
  success: true,
  gasUsed: 45000n,
  stateChanges: [],
  logs: [],
  errorMessage: null,
  simulationId: 'sim-test-1',
};

const FLAGS: RuleFlag[] = [];

function toolUseResponse(input: Record<string, unknown>) {
  return {
    id: 'msg_test',
    type: 'message',
    role: 'assistant',
    content: [
      { type: 'tool_use', id: 'toolu_test', name: 'submit_risk_assessment', input },
    ],
    model: 'claude-sonnet-4-6',
    stop_reason: 'tool_use',
    usage: { input_tokens: 200, output_tokens: 80 },
  };
}

// ─── Happy path ───────────────────────────────────────────────────────────────

describe('classify — successful response', () => {
  it('returns ClassifierOutput when response is well-formed', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({
        riskScore: 15,
        reasoning: 'Small transfer to a known address with no rule flags. Low risk.',
        category: 'SAFE',
        classifierSignals: [],
      }),
    );

    const result = await classify(DECODED, SIM, FLAGS);

    expect(result.riskScore).toBe(15);
    expect(result.category).toBe('SAFE');
    expect(result.reasoning).toBeTruthy();
    expect(Array.isArray(result.classifierSignals)).toBe(true);
  });

  it('passes rule flags to Claude in the user message', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({
        riskScore: 72,
        reasoning: 'UNKNOWN_RECIPIENT flag present.',
        category: 'SUSPICIOUS_RECIPIENT',
        classifierSignals: ['recipient not in known address set'],
      }),
    );

    const flags: RuleFlag[] = [
      {
        ruleId: 'UNKNOWN_RECIPIENT',
        ruleName: 'Unknown Recipient',
        severity: 'MEDIUM',
        description: 'Recipient is not in the allowlist',
      },
    ];

    await classify(DECODED, SIM, flags);

    const callArgs = mockCreate.mock.lastCall![0];
    const userMessage = callArgs.messages[0].content as string;
    expect(userMessage).toContain('[MEDIUM] Unknown Recipient');
    expect(userMessage).toContain('Recipient is not in the allowlist');
  });

  it('uses forced tool-use in every API call', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({ riskScore: 5, reasoning: 'ok', category: 'SAFE', classifierSignals: [] }),
    );

    await classify(DECODED, SIM, FLAGS);

    const callArgs = mockCreate.mock.lastCall![0];
    expect(callArgs.tool_choice).toEqual({ type: 'tool', name: 'submit_risk_assessment' });
    expect(callArgs.tools[0].name).toBe('submit_risk_assessment');
  });
});

// ─── API_ERROR ────────────────────────────────────────────────────────────────

describe('classify — API_ERROR', () => {
  it('SDK network failure → ClassifierError API_ERROR', async () => {
    mockCreate.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      name: 'ClassifierError',
      type: 'API_ERROR',
    });
  });

  it('API_ERROR cause is preserved', async () => {
    const originalError = new Error('rate limited');
    mockCreate.mockRejectedValueOnce(originalError);

    const err = await classify(DECODED, SIM, FLAGS).catch(e => e);
    expect(err.cause).toBe(originalError);
  });
});

// ─── TOOL_NOT_CALLED ──────────────────────────────────────────────────────────

describe('classify — TOOL_NOT_CALLED', () => {
  it('response with no tool_use block → ClassifierError TOOL_NOT_CALLED', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: 'text', text: 'I cannot assess this transaction.' }],
    });

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      name: 'ClassifierError',
      type: 'TOOL_NOT_CALLED',
    });
  });

  it('empty content array → ClassifierError TOOL_NOT_CALLED', async () => {
    mockCreate.mockResolvedValueOnce({ content: [] });

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'TOOL_NOT_CALLED',
    });
  });
});

// ─── MALFORMED_RESPONSE ───────────────────────────────────────────────────────

describe('classify — MALFORMED_RESPONSE', () => {
  it('riskScore out of range (> 100) → ClassifierError MALFORMED_RESPONSE', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({ riskScore: 150, reasoning: 'ok', category: 'SAFE', classifierSignals: [] }),
    );

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'MALFORMED_RESPONSE',
    });
  });

  it('riskScore is a float → ClassifierError MALFORMED_RESPONSE', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({ riskScore: 45.7, reasoning: 'ok', category: 'SAFE', classifierSignals: [] }),
    );

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'MALFORMED_RESPONSE',
    });
  });

  it('category not in enum → ClassifierError MALFORMED_RESPONSE', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({
        riskScore: 50,
        reasoning: 'ok',
        category: 'BLOCK_THIS', // invented category — policy decision sneaked in
        classifierSignals: [],
      }),
    );

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'MALFORMED_RESPONSE',
    });
  });

  it('missing required field (reasoning absent) → ClassifierError MALFORMED_RESPONSE', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({ riskScore: 30, category: 'SAFE', classifierSignals: [] }),
    );

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'MALFORMED_RESPONSE',
    });
  });

  it('classifierSignals is not an array → ClassifierError MALFORMED_RESPONSE', async () => {
    mockCreate.mockResolvedValueOnce(
      toolUseResponse({
        riskScore: 30,
        reasoning: 'ok',
        category: 'SAFE',
        classifierSignals: 'should be array', // wrong type
      }),
    );

    await expect(classify(DECODED, SIM, FLAGS)).rejects.toMatchObject({
      type: 'MALFORMED_RESPONSE',
    });
  });
});

// ─── buildUserMessage ─────────────────────────────────────────────────────────

describe('buildUserMessage', () => {
  it('includes key decoded fields', () => {
    const msg = buildUserMessage(DECODED, SIM, FLAGS);
    expect(msg).toContain('ERC20_TRANSFER');
    expect(msg).toContain(DECODED.from);
    expect(msg).toContain(DECODED.to);
    expect(msg).toContain('transfer');
  });

  it('shows "None" when no rule flags fired', () => {
    const msg = buildUserMessage(DECODED, SIM, []);
    expect(msg).toContain('None');
  });

  it('formats rule flags with severity prefix', () => {
    const flags: RuleFlag[] = [
      { ruleId: 'EXCESSIVE_APPROVAL', ruleName: 'Excessive Token Approval', severity: 'HIGH', description: 'Amount exceeds threshold' },
    ];
    const msg = buildUserMessage(DECODED, SIM, flags);
    expect(msg).toContain('[HIGH] Excessive Token Approval');
  });

  it('formats simulation revert reason', () => {
    const failedSim: SimulationResult = {
      ...SIM,
      success: false,
      errorMessage: 'ERC20: insufficient balance',
    };
    const msg = buildUserMessage(DECODED, failedSim, []);
    expect(msg).toContain('ERC20: insufficient balance');
    expect(msg).toContain('Success: false');
  });

  it('formats state changes when present', () => {
    const simWithChanges: SimulationResult = {
      ...SIM,
      stateChanges: [
        {
          address: '0xTokenContract',
          balanceBefore: '1000',
          balanceAfter: '500',
          storageDiffs: [{ slot: '0x0', before: '0x1', after: '0x2' }],
        },
      ],
    };
    const msg = buildUserMessage(DECODED, simWithChanges, []);
    expect(msg).toContain('0xTokenContract');
    expect(msg).toContain('1000 → 500');
    expect(msg).toContain('1 storage slot(s) modified');
  });
});
