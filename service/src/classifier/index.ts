import type {
  ClassifierOutput,
  DecodedTransaction,
  RuleFlag,
  SimulationResult,
} from '../types/index.js';

/**
 * Call Claude with the full pipeline context and get back a structured
 * risk assessment. Uses JSON-mode output (no free-text parsing).
 *
 * Prompt includes: decoded tx fields, simulation state changes, rule flags.
 * Expected response schema: { riskScore, reasoning, category, flags }
 *
 * Requires env var: ANTHROPIC_API_KEY
 */
export async function classify(
  decoded: DecodedTransaction,
  simulation: SimulationResult,
  ruleFlags: RuleFlag[],
): Promise<ClassifierOutput> {
  throw new Error('Not implemented');
}
