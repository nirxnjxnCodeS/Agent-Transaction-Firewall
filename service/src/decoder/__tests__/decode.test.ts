import { encodeFunctionData, parseAbi } from 'viem';
import { describe, expect, it } from 'vitest';
import { decode } from '../index.js';
import { SELECTOR, UINT256_MAX } from '../selectors.js';
import type { RawTransaction } from '../../types/index.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function transferFrom(address from, address to, uint256 amount) returns (bool)',
]);

const ADDR = {
  token:    '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC (illustrative)
  alice:    '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  bob:      '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
  spender:  '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  agent:    '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
} as const;

function base(overrides: Partial<RawTransaction> = {}): RawTransaction {
  return {
    to:      ADDR.token,
    from:    ADDR.agent,
    value:   0n,
    data:    '0x',
    chainId: 84532, // Base Sepolia
    ...overrides,
  };
}

// ─── Native transfer ──────────────────────────────────────────────────────────

describe('native ETH transfer', () => {
  it('empty data string → NATIVE_TRANSFER', async () => {
    const tx = base({ to: ADDR.bob, value: 10n ** 17n, data: '' });
    const decoded = await decode(tx);

    expect(decoded.txType).toBe('NATIVE_TRANSFER');
    expect(decoded.functionSelector).toBeNull();
    expect(decoded.functionName).toBeNull();
    expect(decoded.recipient).toBe(ADDR.bob);
    expect(decoded.value).toBe(10n ** 17n);
    expect(decoded.tokenAddress).toBeNull();
    expect(decoded.amount).toBeNull();
    expect(decoded.approvalAmount).toBeNull();
    expect(decoded.isUnlimitedApproval).toBe(false);
  });

  it('"0x" data → NATIVE_TRANSFER', async () => {
    const decoded = await decode(base({ to: ADDR.bob, value: 1n, data: '0x' }));
    expect(decoded.txType).toBe('NATIVE_TRANSFER');
    expect(decoded.recipient).toBe(ADDR.bob);
  });
});

// ─── ERC-20 transfer ──────────────────────────────────────────────────────────

describe('ERC-20 transfer', () => {
  const amount = 500n * 10n ** 6n; // 500 USDC

  it('decodes transfer(address,uint256)', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [ADDR.bob, amount],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('ERC20_TRANSFER');
    expect(decoded.functionSelector).toBe(SELECTOR.ERC20_TRANSFER);
    expect(decoded.functionName).toBe('transfer');
    expect(decoded.tokenAddress).toBe(ADDR.token);
    expect(decoded.recipient).toBe(ADDR.bob);
    expect(decoded.amount).toBe(amount);
    expect(decoded.approvalAmount).toBeNull();
    expect(decoded.isUnlimitedApproval).toBe(false);
  });

  it('decodes transferFrom(address,address,uint256)', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'transferFrom',
      args: [ADDR.alice, ADDR.bob, amount],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('ERC20_TRANSFER');
    expect(decoded.functionSelector).toBe(SELECTOR.ERC20_TRANSFER_FROM);
    expect(decoded.functionName).toBe('transferFrom');
    expect(decoded.recipient).toBe(ADDR.bob); // destination, not source
    expect(decoded.amount).toBe(amount);
  });
});

// ─── ERC-20 approval ─────────────────────────────────────────────────────────

describe('ERC-20 approval', () => {
  it('finite approval amount', async () => {
    const allowance = 100n * 10n ** 18n;
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [ADDR.spender, allowance],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('ERC20_APPROVAL');
    expect(decoded.functionSelector).toBe(SELECTOR.ERC20_APPROVE);
    expect(decoded.functionName).toBe('approve');
    expect(decoded.tokenAddress).toBe(ADDR.token);
    expect(decoded.recipient).toBe(ADDR.spender);
    expect(decoded.approvalAmount).toBe(allowance);
    expect(decoded.amount).toBeNull();
    expect(decoded.isUnlimitedApproval).toBe(false);
  });

  it('uint256.max → isUnlimitedApproval = true', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [ADDR.spender, UINT256_MAX],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('ERC20_APPROVAL');
    expect(decoded.isUnlimitedApproval).toBe(true);
    expect(decoded.approvalAmount).toBe(UINT256_MAX);
  });

  it('zero approval (revoke) → isUnlimitedApproval = false', async () => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [ADDR.spender, 0n],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('ERC20_APPROVAL');
    expect(decoded.isUnlimitedApproval).toBe(false);
    expect(decoded.approvalAmount).toBe(0n);
  });

  // Real-world phishing pattern: approvalAmount slightly less than uint256.max
  // to evade naive exact-match checks. decoder does NOT flag these —
  // rules/ must independently threshold-check approvalAmount.
  it.each([
    ['UINT256_MAX - 1', UINT256_MAX - 1n],
    ['2^255 (half of max)', 2n ** 255n],
    ['2^254', 2n ** 254n],
  ])('near-max approval (%s) → isUnlimitedApproval = false, approvalAmount exposed', async (_label, nearMax) => {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: 'approve',
      args: [ADDR.spender, nearMax],
    });
    const decoded = await decode(base({ data }));

    expect(decoded.isUnlimitedApproval).toBe(false);
    // approvalAmount is preserved so rules/ can apply its own threshold
    expect(decoded.approvalAmount).toBe(nearMax);
  });
});

// ─── Swap ────────────────────────────────────────────────────────────────────

describe('swap detection', () => {
  it('Uniswap V2 swapExactTokensForTokens selector → SWAP', async () => {
    // Just selector + zero-padded bytes — we don't parse swap args
    const data = '0x38ed173900000000000000000000000000000000000000000000000000000000';
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('SWAP');
    expect(decoded.functionSelector).toBe('0x38ed1739');
    expect(decoded.tokenAddress).toBe(ADDR.token);
  });

  it('Uniswap V3 exactInputSingle selector → SWAP', async () => {
    const data = '0x414bf38900000000000000000000000000000000000000000000000000000000';
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('SWAP');
    expect(decoded.functionSelector).toBe('0x414bf389');
  });
});

// ─── Unknown calldata ────────────────────────────────────────────────────────

describe('unknown calldata', () => {
  it('unrecognized 4-byte selector → UNKNOWN, no throw', async () => {
    const data = '0xdeadbeef0000000000000000000000000000000000000000000000000000';
    const decoded = await decode(base({ data }));

    expect(decoded.txType).toBe('UNKNOWN');
    expect(decoded.functionSelector).toBe('0xdeadbeef');
    expect(decoded.functionName).toBeNull();
    expect(decoded.recipient).toBeNull();
    expect(decoded.amount).toBeNull();
  });
});

// ─── Raw fields preserved ────────────────────────────────────────────────────

describe('raw field passthrough', () => {
  it('always preserves raw transaction on decoded.raw', async () => {
    const tx = base({ to: ADDR.bob, value: 42n, data: '0x' });
    const decoded = await decode(tx);
    expect(decoded.raw).toBe(tx);
    expect(decoded.from).toBe(ADDR.agent);
    expect(decoded.to).toBe(ADDR.bob);
    expect(decoded.value).toBe(42n);
  });
});
