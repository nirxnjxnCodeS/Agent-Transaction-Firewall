import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { encodeFunctionData, maxUint256, parseAbi } from 'viem';
import { decode } from '../../decoder/index.js';
import { simulate } from '../index.js';
import type { RawTransaction } from '../../types/index.js';

// ── Constants ─────────────────────────────────────────────────────────────────

// Use a dedicated test port so this doesn't collide with a running dev fork.
const TEST_PORT = '18545';

// USDC on Base Sepolia — exists when forking from the live chain.
const USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

// Anvil default accounts (deterministic, always funded on a fresh --no-fork instance).
const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // account #0
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'; // account #1

const FORK_URL = process.env.BASE_SEPOLIA_RPC_URL;

// ── Anvil lifecycle ───────────────────────────────────────────────────────────

let anvilProcess: ChildProcess;

async function waitForAnvil(port: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`http://localhost:${port}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'eth_blockNumber', params: [] }),
      });
      if (resp.ok) return;
    } catch {
      await new Promise(r => setTimeout(r, 300));
    }
  }
  throw new Error(`Anvil did not start within ${timeoutMs}ms on port ${port}`);
}

beforeAll(async () => {
  // Override the port the simulator reads so tests use the test instance.
  process.env.ANVIL_FORK_PORT = TEST_PORT;

  const args = ['--port', TEST_PORT, '--chain-id', '84532', '--silent'];
  if (FORK_URL) {
    args.push('--fork-url', FORK_URL);
  }

  // Foundry installs to ~/.foundry/bin which may not be in vitest's worker PATH.
  const anvilBin = process.env.ANVIL_BIN ??
    `${process.env.HOME ?? '/Users/niranjansbinu'}/.foundry/bin/anvil`;

  anvilProcess = spawn(anvilBin, args, { stdio: 'pipe' });

  anvilProcess.on('error', err => {
    throw new Error(`Failed to start anvil: ${err.message}`);
  });

  await waitForAnvil(TEST_PORT);
}, 30_000);

afterAll(() => {
  anvilProcess?.kill('SIGTERM');
});

// ── Snapshot isolation ────────────────────────────────────────────────────────
// Each test gets a clean fork state. simulate() takes its own inner snapshot;
// this outer snapshot cleans up any side effects (e.g. anvil_setBalance).

let testSnapshot: string;

async function testRpc(method: string, params: unknown[] = []): Promise<unknown> {
  const resp = await fetch(`http://localhost:${TEST_PORT}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
  });
  const { result } = (await resp.json()) as { result: unknown };
  return result;
}

beforeEach(async () => {
  testSnapshot = (await testRpc('evm_snapshot')) as string;
});

afterEach(async () => {
  await testRpc('evm_revert', [testSnapshot]);
});

// ── Helper ────────────────────────────────────────────────────────────────────

async function makeDecoded(raw: RawTransaction) {
  return decode(raw);
}

// ── Connectivity test (always runs — no fork needed) ─────────────────────────

describe('simulate — connectivity failure', () => {
  it('throws "not reachable" when anvil is not running on the configured port', async () => {
    // Stub fetch globally to simulate ECONNREFUSED on port 19999.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' })),
    );

    const decoded = await makeDecoded({
      to: RECIPIENT, from: SENDER, value: 0n, data: '0x', chainId: 84532,
    });

    await expect(simulate(decoded)).rejects.toThrow('not reachable');

    vi.unstubAllGlobals();
  });
});

// ── Native ETH transfer (no fork needed — anvil default accounts have ETH) ───

describe('simulate — native ETH transfer', () => {
  it('succeeds: 0.1 ETH transfer between anvil accounts', async () => {
    const raw: RawTransaction = {
      to: RECIPIENT,
      from: SENDER,
      value: 10n ** 17n, // 0.1 ETH
      data: '0x',
      chainId: 84532,
    };
    const decoded = await makeDecoded(raw);
    const result = await simulate(decoded);

    expect(result.success).toBe(true);
    expect(result.gasUsed).toBeGreaterThan(0n);
    expect(result.errorMessage).toBeNull();
    expect(result.simulationId).toBeTruthy();
    expect(result.logs).toHaveLength(0); // native transfer emits no EVM logs

    // Sender ETH balance decreases (gas + value sent).
    const senderChange = result.stateChanges.find(
      s => s.address.toLowerCase() === SENDER.toLowerCase(),
    );
    expect(senderChange).toBeDefined();
    expect(BigInt(senderChange!.balanceBefore!)).toBeGreaterThan(
      BigInt(senderChange!.balanceAfter!),
    );
  });

  it('fork state is restored after simulation — sender balance unchanged on next call', async () => {
    const raw: RawTransaction = {
      to: RECIPIENT, from: SENDER, value: 10n ** 18n, data: '0x', chainId: 84532,
    };
    const decoded = await makeDecoded(raw);

    // Run twice; the second call should see the same pre-tx state as the first.
    const first = await simulate(decoded);
    const second = await simulate(decoded);

    const firstBefore = first.stateChanges.find(
      s => s.address.toLowerCase() === SENDER.toLowerCase(),
    )?.balanceBefore;
    const secondBefore = second.stateChanges.find(
      s => s.address.toLowerCase() === SENDER.toLowerCase(),
    )?.balanceBefore;

    // The "before" balance each simulation sees is whatever anvil_setBalance set
    // (10 ETH), because evm_revert restores to the post-setBalance snapshot.
    // The key invariant: both simulations see the same starting balance.
    expect(firstBefore).toBe(secondBefore);
  });
});

// ── ERC-20 tests (require Base Sepolia fork) ──────────────────────────────────

describe.skipIf(!FORK_URL)('simulate — ERC-20 on Base Sepolia fork', () => {
  it('success: approve(spender, 1000 USDC) — tx succeeds, Approval log emitted', async () => {
    const calldata = encodeFunctionData({
      abi: parseAbi(['function approve(address spender, uint256 amount) returns (bool)']),
      functionName: 'approve',
      args: [RECIPIENT as `0x${string}`, 1_000n * 10n ** 6n],
    });
    const raw: RawTransaction = {
      to: USDC, from: SENDER, value: 0n, data: calldata, chainId: 84532,
    };
    const decoded = await makeDecoded(raw);
    const result = await simulate(decoded);

    expect(result.success).toBe(true);
    expect(result.gasUsed).toBeGreaterThan(0n);
    expect(result.errorMessage).toBeNull();

    // Approval(address indexed owner, address indexed spender, uint256 value)
    const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
    const approvalLog = result.logs.find(l => l.topics[0] === APPROVAL_TOPIC);
    expect(approvalLog).toBeDefined();
    expect(approvalLog?.address.toLowerCase()).toBe(USDC.toLowerCase());
  }, 30_000);

  it('success: approve(spender, uint256.max) — unlimited approval, Approval log emitted', async () => {
    const calldata = encodeFunctionData({
      abi: parseAbi(['function approve(address spender, uint256 amount) returns (bool)']),
      functionName: 'approve',
      args: [RECIPIENT as `0x${string}`, maxUint256],
    });
    const raw: RawTransaction = {
      to: USDC, from: SENDER, value: 0n, data: calldata, chainId: 84532,
    };
    const decoded = await makeDecoded(raw);

    // Decoder flags it correctly — this is what the rules engine checks.
    expect(decoded.isUnlimitedApproval).toBe(true);
    expect(decoded.txType).toBe('ERC20_APPROVAL');

    const result = await simulate(decoded);

    expect(result.success).toBe(true);
    expect(result.gasUsed).toBeGreaterThan(0n);

    const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
    expect(result.logs.some(l => l.topics[0] === APPROVAL_TOPIC)).toBe(true);
  }, 30_000);

  it('revert: transfer USDC with zero balance — success=false, errorMessage populated', async () => {
    // SENDER has 0 USDC on Base Sepolia fork → transfer reverts.
    const calldata = encodeFunctionData({
      abi: parseAbi(['function transfer(address to, uint256 amount) returns (bool)']),
      functionName: 'transfer',
      args: [RECIPIENT as `0x${string}`, 999_999_999n * 10n ** 6n],
    });
    const raw: RawTransaction = {
      to: USDC, from: SENDER, value: 0n, data: calldata, chainId: 84532,
    };
    const decoded = await makeDecoded(raw);
    const result = await simulate(decoded);

    expect(result.success).toBe(false);
    expect(result.errorMessage).toBeTruthy();
    // Gas is consumed up to the revert point.
    expect(result.gasUsed).toBeGreaterThan(0n);
    // No logs emitted on revert.
    expect(result.logs).toHaveLength(0);
  }, 30_000);
});
