import type { DecodedTransaction, SimulationResult } from '../types/index.js';

/**
 * Submit the decoded transaction to the Tenderly Simulation API and
 * return predicted state changes, gas usage, and event logs.
 *
 * Requires env vars: TENDERLY_ACCOUNT, TENDERLY_PROJECT, TENDERLY_ACCESS_KEY
 */
export async function simulate(
  decoded: DecodedTransaction,
): Promise<SimulationResult> {
  throw new Error('Not implemented');
}
