import { decodeFunctionData, type Hex } from 'viem';
import type { DecodedTransaction, RawTransaction } from '../types/index.js';
import { ERC20_ABI, SELECTOR, SWAP_SELECTORS, UINT256_MAX } from './selectors.js';

/**
 * Decode raw calldata into a normalized DecodedTransaction.
 *
 * Resolution order:
 *  1. Empty calldata          → NATIVE_TRANSFER
 *  2. Known swap selector     → SWAP
 *  3. ERC-20 transfer         → ERC20_TRANSFER
 *  4. ERC-20 transferFrom     → ERC20_TRANSFER
 *  5. ERC-20 approve          → ERC20_APPROVAL
 *  6. Anything else           → UNKNOWN
 *
 * Never throws — unknown calldata yields txType UNKNOWN rather than an error.
 */
export async function decode(tx: RawTransaction): Promise<DecodedTransaction> {
  const data = normalizeHex(tx.data);

  if (isEmptyCalldata(data)) {
    return nativeTransfer(tx);
  }

  const selector = extractSelector(data);

  if (SWAP_SELECTORS.has(selector)) {
    return swap(tx, selector);
  }

  if (selector === SELECTOR.ERC20_TRANSFER) {
    return decodeErc20Transfer(tx, data, selector);
  }

  if (selector === SELECTOR.ERC20_TRANSFER_FROM) {
    return decodeErc20TransferFrom(tx, data, selector);
  }

  if (selector === SELECTOR.ERC20_APPROVE) {
    return decodeErc20Approve(tx, data, selector);
  }

  return unknown(tx, selector);
}

// ─── Decoders ────────────────────────────────────────────────────────────────

function nativeTransfer(tx: RawTransaction): DecodedTransaction {
  return {
    raw: tx,
    txType: 'NATIVE_TRANSFER',
    functionSelector: null,
    functionName: null,
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: null,
    recipient: tx.to,
    amount: null,
    approvalAmount: null,
    isUnlimitedApproval: false,
  };
}

function swap(tx: RawTransaction, selector: string): DecodedTransaction {
  return {
    raw: tx,
    txType: 'SWAP',
    functionSelector: selector,
    functionName: null, // name lookup not needed by downstream modules
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: tx.to,
    recipient: null,
    amount: null,
    approvalAmount: null,
    isUnlimitedApproval: false,
  };
}

function decodeErc20Transfer(
  tx: RawTransaction,
  data: Hex,
  selector: string,
): DecodedTransaction {
  const { args } = decodeFunctionData({ abi: ERC20_ABI, data });
  // transfer(address to, uint256 amount)
  const [recipient, amount] = args as [string, bigint];
  return {
    raw: tx,
    txType: 'ERC20_TRANSFER',
    functionSelector: selector,
    functionName: 'transfer',
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: tx.to,
    recipient,
    amount,
    approvalAmount: null,
    isUnlimitedApproval: false,
  };
}

function decodeErc20TransferFrom(
  tx: RawTransaction,
  data: Hex,
  selector: string,
): DecodedTransaction {
  const { args } = decodeFunctionData({ abi: ERC20_ABI, data });
  // transferFrom(address from, address to, uint256 amount)
  const [, recipient, amount] = args as [string, string, bigint];
  return {
    raw: tx,
    txType: 'ERC20_TRANSFER',
    functionSelector: selector,
    functionName: 'transferFrom',
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: tx.to,
    recipient,
    amount,
    approvalAmount: null,
    isUnlimitedApproval: false,
  };
}

function decodeErc20Approve(
  tx: RawTransaction,
  data: Hex,
  selector: string,
): DecodedTransaction {
  const { args } = decodeFunctionData({ abi: ERC20_ABI, data });
  // approve(address spender, uint256 amount)
  const [spender, approvalAmount] = args as [string, bigint];
  return {
    raw: tx,
    txType: 'ERC20_APPROVAL',
    functionSelector: selector,
    functionName: 'approve',
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: tx.to,
    recipient: spender,
    amount: null,
    approvalAmount,
    // Strict equality to uint256.max only. Near-max values (e.g. UINT256_MAX-1,
    // 2^255) used in phishing approvals are NOT flagged here — rules/ is
    // responsible for threshold-based "suspiciously large" detection using the
    // raw approvalAmount field directly.
    isUnlimitedApproval: approvalAmount === UINT256_MAX,
  };
}

function unknown(tx: RawTransaction, selector: string): DecodedTransaction {
  return {
    raw: tx,
    txType: 'UNKNOWN',
    functionSelector: selector,
    functionName: null,
    to: tx.to,
    from: tx.from,
    value: tx.value,
    tokenAddress: null,
    recipient: null,
    amount: null,
    approvalAmount: null,
    isUnlimitedApproval: false,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeHex(data: string): Hex {
  if (!data || data === '0x') return '0x';
  return data.startsWith('0x') ? (data as Hex) : (`0x${data}` as Hex);
}

function isEmptyCalldata(data: Hex): boolean {
  return data === '0x' || data.length < 10; // less than selector + 1 byte
}

/** Returns the lowercase 4-byte selector including '0x' prefix. */
function extractSelector(data: Hex): string {
  return data.slice(0, 10).toLowerCase();
}
