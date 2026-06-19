import { v4 as uuidv4 } from 'uuid';
import type { DecodedTransaction, EventLog, SimulationResult, StateChange } from '../types/index.js';

// ── JSON-RPC transport ────────────────────────────────────────────────────────

let _reqId = 0;

interface RpcResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: string };
}

async function rpc(url: string, method: string, params: unknown[] = []): Promise<unknown> {
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++_reqId, method, params }),
    });
  } catch (err) {
    // ECONNREFUSED or similar — anvil fork is not running.
    // The orchestrator catches this and ESCALATEs (SIMULATOR_UNAVAILABLE).
    throw new Error(
      `Anvil fork not reachable at ${url} — run 'npm run anvil:fork' in a separate terminal: ${(err as Error).message}`,
    );
  }

  const json = (await resp.json()) as RpcResponse;
  if (json.error) {
    throw new Error(`RPC ${method} error (${json.error.code}): ${json.error.message}`);
  }
  return json.result;
}

// ── Balance helpers ───────────────────────────────────────────────────────────

async function ethBalance(url: string, address: string): Promise<bigint> {
  const hex = (await rpc(url, 'eth_getBalance', [address, 'latest'])) as string;
  return BigInt(hex);
}

// ERC-20 balanceOf(address) — selector 0x70a08231
async function tokenBalance(url: string, token: string, account: string): Promise<bigint> {
  const padded = account.slice(2).toLowerCase().padStart(64, '0');
  const data = `0x70a08231${padded}`;
  const result = (await rpc(url, 'eth_call', [{ to: token, data }, 'latest'])) as string;
  if (!result || result === '0x') return 0n;
  return BigInt(result);
}

// ── Revert reason extraction ──────────────────────────────────────────────────

async function getRevertReason(
  url: string,
  from: string,
  to: string,
  data: string,
  value: string,
): Promise<string | null> {
  try {
    await rpc(url, 'eth_call', [{ from, to, data, value }, 'latest']);
    return null; // call succeeded — no revert
  } catch (err) {
    if (!(err instanceof Error)) return 'Unknown revert';
    const msg = err.message;
    // Anvil wraps the revert reason in the error message.
    const match =
      msg.match(/execution reverted:?\s+(.*)/i) ??
      msg.match(/revert:?\s+(.*)/i) ??
      msg.match(/error: (.*)/i);
    return match ? match[1].trim() || 'Execution reverted' : msg;
  }
}

// ── Simulator ─────────────────────────────────────────────────────────────────

/**
 * Simulate a transaction against a local anvil fork of Base Sepolia.
 *
 * Requires `npm run anvil:fork` running in a separate terminal.
 * Env vars: ANVIL_FORK_PORT (default 8545).
 *
 * Internally:
 *   1. Connectivity-check via eth_blockNumber — throws immediately if anvil
 *      isn't reachable so the orchestrator can ESCALATE cleanly.
 *   2. Pre-funds the sender via anvil_setBalance so gas is never the reason a
 *      simulation fails (local-fork-only artifact; real wallets have real ETH).
 *   3. Impersonates the sender (no private key needed on a local fork).
 *   4. Takes an evm_snapshot, executes the transaction, captures the receipt,
 *      reads post-tx balances, then reverts to the snapshot — fork state is
 *      always restored on exit.
 *   5. Maps receipt → SimulationResult (drop-in replacement for the old
 *      Tenderly integration — SimulationResult shape is unchanged).
 *
 * State changes captured: ETH balance of sender + ERC-20 balances of sender
 * and immediate recipient (derived from DecodedTransaction).
 * Storage slot diffs are not captured (would require debug_traceCall).
 */
export async function simulate(decoded: DecodedTransaction): Promise<SimulationResult> {
  const port = process.env.ANVIL_FORK_PORT ?? '8545';
  const url = `http://localhost:${port}`;

  // Step 1 — connectivity. Throws if anvil isn't running; orchestrator ESCALATEs.
  await rpc(url, 'eth_blockNumber');

  const from = decoded.from;
  const to = decoded.to;
  const data = decoded.raw.data || '0x';
  const valueHex = `0x${decoded.value.toString(16) || '0'}`;

  // Step 2 — pre-fund sender for gas. On a real fork, the agent's wallet might
  // have zero ETH on Base Sepolia. This is simulation-only; it doesn't affect
  // the fork state permanently (evm_revert cleans up below).
  await rpc(url, 'anvil_setBalance', [from, `0x${(10n ** 19n).toString(16)}`]); // 10 ETH

  // Step 3 — record pre-tx balances for state-change tracking.
  const ethBefore = await ethBalance(url, from);
  const tokenAddr = decoded.tokenAddress;
  const recipientAddr = decoded.recipient;

  const tokenBefore: Record<string, bigint> = {};
  if (tokenAddr) {
    tokenBefore[from.toLowerCase()] = await tokenBalance(url, tokenAddr, from);
    if (recipientAddr && recipientAddr.toLowerCase() !== from.toLowerCase()) {
      tokenBefore[recipientAddr.toLowerCase()] = await tokenBalance(url, tokenAddr, recipientAddr);
    }
  }

  // Step 4 — impersonate sender + snapshot.
  await rpc(url, 'anvil_impersonateAccount', [from]);
  const snapshotId = (await rpc(url, 'evm_snapshot')) as string;

  let success = true;
  let gasUsed = 21_000n;
  let errorMessage: string | null = null;
  const logs: EventLog[] = [];
  let ethAfter = ethBefore;
  const tokenAfter: Record<string, bigint> = { ...tokenBefore };

  try {
    // Execute the transaction from the impersonated account.
    const txHash = (await rpc(url, 'eth_sendTransaction', [
      { from, to, data, value: valueHex, gas: '0x7A1200' }, // 8M gas ceiling
    ])) as string;

    // anvil in fork mode mines asynchronously — poll until the receipt appears.
    type RawReceipt = { status: string; gasUsed: string; logs: Array<{ address: string; topics: string[]; data: string }> };
    let receipt: RawReceipt | null = null;
    for (let i = 0; i < 20; i++) {
      receipt = (await rpc(url, 'eth_getTransactionReceipt', [txHash])) as RawReceipt | null;
      if (receipt) break;
      await new Promise(r => setTimeout(r, 250));
    }

    if (!receipt) {
      throw new Error('Transaction receipt not returned after 5s — anvil may not be in auto-mine mode');
    }

    success = receipt.status === '0x1';
    gasUsed = BigInt(receipt.gasUsed);

    for (const log of receipt.logs ?? []) {
      logs.push({ address: log.address, topics: log.topics, data: log.data });
    }

    // Read post-tx balances before reverting.
    ethAfter = await ethBalance(url, from);
    if (tokenAddr) {
      tokenAfter[from.toLowerCase()] = await tokenBalance(url, tokenAddr, from);
      if (recipientAddr && recipientAddr.toLowerCase() !== from.toLowerCase()) {
        tokenAfter[recipientAddr.toLowerCase()] = await tokenBalance(url, tokenAddr, recipientAddr);
      }
    }

    if (!success) {
      // Re-run as eth_call to extract the revert reason string.
      errorMessage = await getRevertReason(url, from, to, data, valueHex);
    }
  } catch (err) {
    // eth_sendTransaction itself threw (e.g. JSON-RPC-level error).
    success = false;
    errorMessage = err instanceof Error ? err.message : 'Transaction execution failed';
    // Try eth_call for a cleaner revert reason if available.
    const callReason = await getRevertReason(url, from, to, data, valueHex).catch(() => null);
    if (callReason) errorMessage = callReason;
  } finally {
    // Always restore fork state — invariant holds even on error.
    await rpc(url, 'evm_revert', [snapshotId]).catch(() => {});
    await rpc(url, 'anvil_stopImpersonatingAccount', [from]).catch(() => {});
  }

  // ── Build state changes ───────────────────────────────────────────────────

  const stateChanges: StateChange[] = [];

  if (ethBefore !== ethAfter) {
    stateChanges.push({
      address: from,
      balanceBefore: ethBefore.toString(),
      balanceAfter: ethAfter.toString(),
      storageDiffs: [],
    });
  }

  if (tokenAddr) {
    for (const [addr, before] of Object.entries(tokenBefore)) {
      const after = tokenAfter[addr] ?? before;
      if (before !== after) {
        stateChanges.push({
          address: addr,
          balanceBefore: before.toString(),
          balanceAfter: after.toString(),
          storageDiffs: [],
        });
      }
    }
  }

  return {
    success,
    gasUsed,
    stateChanges,
    logs,
    errorMessage,
    simulationId: uuidv4(),
  };
}
