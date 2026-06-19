// ─── Raw input ──────────────────────────────────────────────────────────────

/** Transaction as provided by AgentKit before signing. */
export interface RawTransaction {
  to: string;
  from: string;
  /** Native ETH value in wei. */
  value: bigint;
  /** Hex-encoded calldata (empty string for plain ETH transfers). */
  data: string;
  chainId: number;
  nonce?: number;
  gasLimit?: bigint;
}

// ─── Decoder output ─────────────────────────────────────────────────────────

export type TxType =
  | 'NATIVE_TRANSFER'
  | 'ERC20_TRANSFER'
  | 'ERC20_APPROVAL'
  | 'SWAP'
  | 'UNKNOWN';

/** Normalized, human-readable view of a transaction. */
export interface DecodedTransaction {
  raw: RawTransaction;
  txType: TxType;
  /** First 4 bytes of calldata as hex, null for native ETH transfers. */
  functionSelector: string | null;
  functionName: string | null;
  to: string;
  from: string;
  /** Native ETH value in wei. */
  value: bigint;
  /** ERC-20 contract address (null for native transfers). */
  tokenAddress: string | null;
  /** Transfer recipient from decoded calldata (may differ from `to`). */
  recipient: string | null;
  /** Token units transferred (null if not a transfer). */
  amount: bigint | null;
  /** Approval allowance; `null` unless txType === 'ERC20_APPROVAL'. */
  approvalAmount: bigint | null;
  /** Whether the approval amount equals `uint256.max` (unlimited). */
  isUnlimitedApproval: boolean;
}

// ─── Simulator output ────────────────────────────────────────────────────────

export interface SimulationResult {
  success: boolean;
  gasUsed: bigint;
  stateChanges: StateChange[];
  logs: EventLog[];
  /** Revert reason or other error, null on success. */
  errorMessage: string | null;
  /** Tenderly simulation ID for linking back to their UI. */
  simulationId: string;
}

export interface StateChange {
  address: string;
  balanceBefore: string | null; // stringified bigint — bigint not JSON-serializable
  balanceAfter: string | null;
  storageDiffs: StorageDiff[];
}

export interface StorageDiff {
  slot: string;
  before: string;
  after: string;
}

export interface EventLog {
  address: string;
  topics: string[];
  data: string;
}

// ─── Rules output ────────────────────────────────────────────────────────────

export type RuleFlagSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RuleFlag {
  ruleId: string;
  ruleName: string;
  severity: RuleFlagSeverity;
  description: string;
  metadata?: Record<string, unknown>;
}

// ─── Classifier output ───────────────────────────────────────────────────────

export type RiskCategory =
  | 'SAFE'
  | 'SUSPICIOUS_APPROVAL'
  | 'SUSPICIOUS_RECIPIENT'
  | 'HIGH_VALUE_TRANSFER'
  | 'POTENTIAL_DRAIN'
  | 'KNOWN_SCAM_PATTERN'
  | 'UNKNOWN';

/** Structured JSON output from Claude. */
export interface ClassifierOutput {
  /** 0 = no risk, 100 = certain malicious. */
  riskScore: number;
  reasoning: string;
  category: RiskCategory;
  /**
   * LLM-identified risk signals beyond the deterministic rule checks.
   * Named classifierSignals (not flags) to distinguish from RuleFlag[],
   * which has different provenance and structure in the audit log.
   */
  classifierSignals: string[];
}

// ─── Policy output ───────────────────────────────────────────────────────────

export type PolicyVerdict = 'APPROVE' | 'BLOCK' | 'ESCALATE';

export interface PolicyDecision {
  verdict: PolicyVerdict;
  reason: string;
  /** Which policy rule(s) triggered this verdict. */
  triggeredPolicyRules: string[];
}

// ─── Full pipeline decision ──────────────────────────────────────────────────

/** The complete output of `evaluateTransaction` — also what gets logged. */
export interface Decision {
  id: string; // UUID v4
  timestamp: string; // ISO 8601
  raw: RawTransaction;
  decoded: DecodedTransaction;
  /**
   * null when the Tenderly simulator threw before rules/ could run.
   * The pipeline ESCALATEs immediately in that case — rules, classifier,
   * and policy.evaluate() are all skipped.
   */
  simulation: SimulationResult | null;
  ruleFlags: RuleFlag[];
  /**
   * null when the orchestrator short-circuited before calling the classifier
   * due to a CRITICAL-severity rule flag (DENYLIST_ADDRESS, UNLIMITED_APPROVAL).
   * CRITICAL verdicts must not depend on Claude API availability.
   */
  classification: ClassifierOutput | null;
  policy: PolicyDecision;
  // Populated only after a human acts on an ESCALATE item:
  humanVerdict: 'APPROVE' | 'REJECT' | null;
  humanTimestamp: string | null;
  humanNote: string | null;
}

// ─── Audit / DB record ───────────────────────────────────────────────────────

/**
 * What is persisted per decision. Flat top-level columns for efficient
 * querying; full pipeline blobs as JSON for complete replay.
 * The `groundTruthLabel` / `evalNotes` columns are reserved for the
 * evaluation harness in the next phase — they default to null.
 */
export interface AuditRecord {
  id: string;
  timestamp: string;
  chainId: number;
  fromAddress: string;
  toAddress: string;
  txType: TxType;
  /** Native value in wei as string (bigint → DB-safe). */
  valueWei: string;
  /** null when classifier was skipped due to CRITICAL rule flag. */
  riskScore: number | null;
  riskCategory: RiskCategory | null;
  finalVerdict: PolicyVerdict;
  // Full JSON snapshots of each pipeline stage:
  decodedTxJson: string;
  simulationResultJson: string;
  ruleFlagsJson: string;
  classifierOutputJson: string;
  policyDecisionJson: string;
  // Human review (for ESCALATE):
  humanVerdict: 'APPROVE' | 'REJECT' | null;
  humanTimestamp: string | null;
  humanNote: string | null;
  // Eval harness (next phase):
  groundTruthLabel: 'BENIGN' | 'MALICIOUS' | null;
  evalNotes: string | null;
}

// ─── Human verdict request ───────────────────────────────────────────────────

export interface HumanVerdictRequest {
  verdict: 'APPROVE' | 'REJECT';
  note?: string;
}
