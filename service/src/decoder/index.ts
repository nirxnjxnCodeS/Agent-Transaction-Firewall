import type { DecodedTransaction, RawTransaction } from '../types/index.js';

/**
 * Decode raw calldata into a normalized DecodedTransaction.
 *
 * Handles: native ETH transfer, ERC-20 transfer, ERC-20 approval, and
 * basic swap detection. Uses viem's ABI decoding under the hood.
 */
export async function decode(tx: RawTransaction): Promise<DecodedTransaction> {
  throw new Error('Not implemented');
}
