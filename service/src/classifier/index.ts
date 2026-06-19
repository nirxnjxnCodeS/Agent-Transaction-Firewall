import Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import type { ClassifierOutput, DecodedTransaction, RuleFlag, SimulationResult } from '../types/index.js';

// ─── Error type ───────────────────────────────────────────────────────────────

export type ClassifierErrorType =
  | 'API_ERROR'         // network failure, timeout, Anthropic 4xx/5xx
  | 'TOOL_NOT_CALLED'   // response contained no tool_use block (should not happen with forced tool-use)
  | 'MALFORMED_RESPONSE'; // tool input failed Zod schema validation

export class ClassifierError extends Error {
  constructor(
    public readonly type: ClassifierErrorType,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'ClassifierError';
  }
}

// ─── Output schema (Zod) ─────────────────────────────────────────────────────

const OutputSchema = z.object({
  riskScore: z.number().int().min(0).max(100),
  reasoning: z.string().min(1),
  category: z.enum([
    'SAFE',
    'SUSPICIOUS_APPROVAL',
    'SUSPICIOUS_RECIPIENT',
    'HIGH_VALUE_TRANSFER',
    'POTENTIAL_DRAIN',
    'KNOWN_SCAM_PATTERN',
    'UNKNOWN',
  ]),
  classifierSignals: z.array(z.string()),
});

// ─── Tool definition ──────────────────────────────────────────────────────────

const RISK_ASSESSMENT_TOOL: Anthropic.Tool = {
  name: 'submit_risk_assessment',
  description:
    'Submit the structured risk assessment for this transaction. ' +
    'Do not include any policy recommendation or action field.',
  input_schema: {
    type: 'object',
    properties: {
      riskScore: {
        type: 'integer',
        minimum: 0,
        maximum: 100,
        description: 'Integer risk score from 0 (no risk) to 100 (highest risk)',
      },
      reasoning: {
        type: 'string',
        description:
          'Explanation of the risk score: which signals were observed, ' +
          'why they contribute to the score, and what the transaction appears to be doing',
      },
      category: {
        type: 'string',
        enum: [
          'SAFE',
          'SUSPICIOUS_APPROVAL',
          'SUSPICIOUS_RECIPIENT',
          'HIGH_VALUE_TRANSFER',
          'POTENTIAL_DRAIN',
          'KNOWN_SCAM_PATTERN',
          'UNKNOWN',
        ],
        description: 'Primary risk category that best characterizes this transaction',
      },
      classifierSignals: {
        type: 'array',
        items: { type: 'string' },
        description:
          'Specific risk indicators identified beyond the deterministic rule checks, ' +
          'as short descriptive strings (e.g. "approval to unverified contract", ' +
          '"state change inconsistent with declared function")',
      },
    },
    required: ['riskScore', 'reasoning', 'category', 'classifierSignals'],
  },
};

// ─── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT =
  `You are a blockchain transaction risk analyst. You are one component in a ` +
  `multi-stage safety pipeline for AI-agent-initiated transactions on Base Sepolia testnet.\n\n` +
  `Your role is to assess risk. Another system — which you do not have access to — uses your ` +
  `output to make a policy decision. Do not include any policy recommendation in your response. ` +
  `Do not suggest whether the transaction should proceed, be blocked, or be reviewed. ` +
  `Reason and score only.\n\n` +
  `You will receive:\n` +
  `1. A decoded transaction describing what the transaction does\n` +
  `2. A simulation result showing the predicted on-chain state changes\n` +
  `3. A list of deterministic checks that fired — automated rule checks that detected ` +
  `specific conditions in the transaction\n\n` +
  `When rule checks are listed, treat them as observed signals: additional evidence to factor ` +
  `into your score and reasoning. They are not conclusions. A transaction with a HIGH-severity ` +
  `rule check may score low if the broader context is benign. A transaction with no rule checks ` +
  `may score high if the simulation reveals unusual state changes.\n\n` +
  `Scoring:\n` +
  `  0–20   No meaningful risk signals. Standard, recognizable transaction pattern.\n` +
  `  21–49  Minor or ambiguous signals. Unusual but not clearly dangerous.\n` +
  `  50–79  Meaningful risk signals present. Characteristics that warrant scrutiny.\n` +
  `  80–100 Strong, converging risk signals. Multiple indicators of a likely harmful transaction.\n\n` +
  `Risk categories:\n` +
  `  SAFE                  No risk signals detected\n` +
  `  SUSPICIOUS_APPROVAL   Approval pattern suggests excessive or abnormal token access\n` +
  `  SUSPICIOUS_RECIPIENT  Recipient exhibits characteristics of a drainer or scam contract\n` +
  `  HIGH_VALUE_TRANSFER   Transfer amount is large relative to the observed context\n` +
  `  POTENTIAL_DRAIN       Transaction pattern consistent with a wallet drain attempt\n` +
  `  KNOWN_SCAM_PATTERN    Matches a recognized on-chain attack or phishing pattern\n` +
  `  UNKNOWN               Insufficient information to categorize`;

// ─── User message builder ─────────────────────────────────────────────────────

export function buildUserMessage(
  decoded: DecodedTransaction,
  simulation: SimulationResult,
  ruleFlags: RuleFlag[],
): string {
  const stateChanges =
    simulation.stateChanges.length === 0
      ? '  None'
      : simulation.stateChanges
          .map(sc => {
            const balance =
              sc.balanceBefore !== null || sc.balanceAfter !== null
                ? `balance ${sc.balanceBefore ?? '?'} → ${sc.balanceAfter ?? '?'} wei`
                : null;
            const storage =
              sc.storageDiffs.length > 0
                ? `${sc.storageDiffs.length} storage slot(s) modified`
                : null;
            const detail = [balance, storage].filter(Boolean).join(', ') || 'no changes recorded';
            return `  ${sc.address}: ${detail}`;
          })
          .join('\n');

  const ruleFlagLines =
    ruleFlags.length === 0
      ? '  None'
      : ruleFlags.map(f => `  [${f.severity}] ${f.ruleName}: ${f.description}`).join('\n');

  return (
    `Assess the risk of the following transaction.\n\n` +
    `## Decoded Transaction\n` +
    `Type: ${decoded.txType}\n` +
    `From: ${decoded.from}\n` +
    `To (immediate contract target): ${decoded.to}\n` +
    `Native ETH value: ${decoded.value.toString()} wei\n` +
    `Function: ${decoded.functionName ?? 'N/A'} (selector: ${decoded.functionSelector ?? 'N/A'})\n` +
    `Token contract: ${decoded.tokenAddress ?? 'N/A'}\n` +
    `Recipient/spender: ${decoded.recipient ?? 'N/A'}\n` +
    `Token transfer amount: ${decoded.amount?.toString() ?? 'N/A'}\n` +
    `Approval amount: ${decoded.approvalAmount?.toString() ?? 'N/A'}\n` +
    `Is unlimited approval (uint256.max): ${decoded.isUnlimitedApproval}\n\n` +
    `## Simulation\n` +
    `Success: ${simulation.success}\n` +
    `Gas used: ${simulation.gasUsed.toString()} units\n` +
    `Revert reason: ${simulation.errorMessage ?? 'None'}\n` +
    `State changes:\n${stateChanges}\n` +
    `Event logs: ${simulation.logs.length} event(s) emitted\n\n` +
    `## Deterministic Rule Checks That Fired\n` +
    ruleFlagLines
  );
}

// ─── Classifier ───────────────────────────────────────────────────────────────

function makeClient(): Anthropic {
  return new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
}

/**
 * Call Claude with the full pipeline context and return a structured risk
 * assessment. Uses forced tool-use so the response is always structured JSON
 * — no free-text parsing.
 *
 * Throws ClassifierError on any failure. The orchestrator catches
 * ClassifierError and escalates the transaction for human review rather than
 * crashing the pipeline or silently approving.
 */
export async function classify(
  decoded: DecodedTransaction,
  simulation: SimulationResult,
  ruleFlags: RuleFlag[],
): Promise<ClassifierOutput> {
  let response: Anthropic.Message;

  try {
    response = await makeClient().messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      tools: [RISK_ASSESSMENT_TOOL],
      tool_choice: { type: 'tool', name: 'submit_risk_assessment' },
      messages: [{ role: 'user', content: buildUserMessage(decoded, simulation, ruleFlags) }],
    });
  } catch (err) {
    throw new ClassifierError('API_ERROR', 'Anthropic API call failed', { cause: err });
  }

  const toolUse = response.content.find(block => block.type === 'tool_use');
  if (!toolUse || toolUse.type !== 'tool_use') {
    throw new ClassifierError(
      'TOOL_NOT_CALLED',
      `Expected tool_use block; got: [${response.content.map(b => b.type).join(', ')}]`,
    );
  }

  const parsed = OutputSchema.safeParse(toolUse.input);
  if (!parsed.success) {
    throw new ClassifierError(
      'MALFORMED_RESPONSE',
      `Tool input failed schema validation: ${parsed.error.message}`,
    );
  }

  return parsed.data;
}
