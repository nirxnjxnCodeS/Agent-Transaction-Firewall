/**
 * Agent Transaction Firewall — AgentKit integration demo
 *
 * Demonstrates the pre-signing hook pattern:
 *   1. Agent builds a transaction (unlimited ERC-20 approval on Base Sepolia)
 *   2. Before signing, the transaction is submitted to the firewall
 *   3. The firewall returns a verdict (APPROVE / BLOCK / ESCALATE)
 *   4. Agent respects the verdict — blocked transactions never reach the signer
 *
 * Run: FIREWALL_URL=http://localhost:3001 tsx src/agent/index.ts
 */

import 'dotenv/config';
import { createWalletClient, encodeFunctionData, http, parseAbi, maxUint256 } from 'viem';
import { baseSepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { ViemWalletProvider } from '@coinbase/agentkit';
import type { Decision, RawTransaction } from '../types/index.js';

// ── Config ────────────────────────────────────────────────────────────────────

const FIREWALL_URL = process.env.FIREWALL_URL ?? 'http://localhost:3001';

// Demo private key — replace with AGENT_PRIVATE_KEY env var in production.
// This is a well-known test key; never hold real funds on it.
const PRIVATE_KEY =
  (process.env.AGENT_PRIVATE_KEY as `0x${string}` | undefined) ??
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

// USDC contract on Base Sepolia (for the demo approval transaction).
const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const;

// Dummy spender address — the approval target. In a real scenario this would be
// a protocol contract (e.g. a DEX router). Using a random address here so the
// smoke test doesn't depend on a real deployment.
const DUMMY_SPENDER = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' as const;

// ── Firewall client ───────────────────────────────────────────────────────────

/**
 * Pre-signing hook: submit the transaction to the firewall service before
 * passing it to the wallet provider.
 *
 * Returns the full Decision so callers can log/inspect the verdict.
 * Throws FirewallBlockError if verdict is BLOCK.
 * Returns verdict ESCALATE without throwing — callers must suspend the tx.
 */
async function checkWithFirewall(tx: RawTransaction): Promise<Decision> {
  const body = JSON.stringify(tx, (_k, v) =>
    typeof v === 'bigint' ? v.toString() : v,
  );

  const resp = await fetch(`${FIREWALL_URL}/api/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });

  if (!resp.ok) {
    throw new Error(`Firewall service returned ${resp.status}: ${await resp.text()}`);
  }

  return resp.json() as Promise<Decision>;
}

class FirewallBlockError extends Error {
  constructor(
    public readonly decision: Decision,
  ) {
    super(`Transaction BLOCKED by firewall: ${decision.policy.reason}`);
    this.name = 'FirewallBlockError';
  }
}

// ── Agent ─────────────────────────────────────────────────────────────────────

async function runAgent() {
  const account = privateKeyToAccount(PRIVATE_KEY);

  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(),
  });

  // ViemWalletProvider wraps the viem client for AgentKit action providers.
  const walletProvider = new ViemWalletProvider(walletClient);

  console.log(`Agent wallet: ${walletProvider.getAddress()}`);
  console.log(`Network: ${walletProvider.getNetwork().networkId}`);
  console.log('');

  // Build an unlimited ERC-20 approval — the most dangerous transaction type.
  // This is the transaction the firewall must intercept and BLOCK.
  const calldata = encodeFunctionData({
    abi: parseAbi(['function approve(address spender, uint256 amount) returns (bool)']),
    functionName: 'approve',
    args: [DUMMY_SPENDER, maxUint256],
  });

  const tx: RawTransaction = {
    to: USDC_BASE_SEPOLIA,
    from: walletProvider.getAddress(),
    value: 0n,
    data: calldata,
    chainId: baseSepolia.id,
  };

  console.log('Attempting unlimited approval:');
  console.log(`  token:   ${tx.to}`);
  console.log(`  spender: ${DUMMY_SPENDER}`);
  console.log(`  amount:  uint256.max (${maxUint256})`);
  console.log('');

  // ── Pre-signing hook ───────────────────────────────────────────────────────
  console.log('Submitting to firewall...');
  const decision = await checkWithFirewall(tx);

  console.log(`Firewall verdict: ${decision.policy.verdict}`);
  console.log(`Reason:          ${decision.policy.reason}`);
  console.log(`Triggered rules: ${JSON.stringify(decision.policy.triggeredPolicyRules)}`);
  console.log(`Decision ID:     ${decision.id}`);
  console.log('');

  if (decision.policy.verdict === 'BLOCK') {
    throw new FirewallBlockError(decision);
  }

  if (decision.policy.verdict === 'ESCALATE') {
    console.log('Transaction suspended — awaiting human review.');
    console.log(`Review at: GET /api/decisions?pendingHumanReview=true`);
    return;
  }

  // APPROVE — pass to the wallet provider for signing.
  console.log('Sending transaction...');
  const hash = await walletProvider.sendTransaction({
    to: tx.to as `0x${string}`,
    value: tx.value,
    data: tx.data as `0x${string}`,
  });
  console.log(`Transaction hash: ${hash}`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

runAgent().catch(err => {
  if (err instanceof FirewallBlockError) {
    console.error(`BLOCKED: ${err.message}`);
    process.exit(1);
  }
  console.error('Agent error:', err);
  process.exit(1);
});
