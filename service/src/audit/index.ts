import type { AuditRecord, Decision, PolicyVerdict } from '../types/index.js';

export interface ListRecordsOptions {
  limit?: number;
  offset?: number;
  /** Filter by final verdict. */
  verdict?: PolicyVerdict;
  /** If true, return only ESCALATE items with no human verdict yet. */
  pendingHumanReview?: boolean;
}

/**
 * Initialize the SQLite database and run migrations (creates tables if
 * they don't exist). Call once at startup before any other audit functions.
 */
export async function initDb(): Promise<void> {
  throw new Error('Not implemented');
}

/**
 * Persist a completed pipeline decision. Returns the stored record's ID.
 * Serializes bigint fields to strings before writing JSON blobs.
 */
export async function logDecision(decision: Decision): Promise<string> {
  throw new Error('Not implemented');
}

/** Retrieve a single audit record by its UUID. */
export async function getRecord(id: string): Promise<AuditRecord | null> {
  throw new Error('Not implemented');
}

/** List audit records with optional filtering and pagination. */
export async function listRecords(
  opts?: ListRecordsOptions,
): Promise<AuditRecord[]> {
  throw new Error('Not implemented');
}

/**
 * Record the outcome of a human review action on an ESCALATE decision.
 * Updates humanVerdict, humanTimestamp, and humanNote in place.
 */
export async function updateHumanVerdict(
  id: string,
  verdict: 'APPROVE' | 'REJECT',
  note?: string,
): Promise<void> {
  throw new Error('Not implemented');
}

/**
 * Set the ground-truth label on a record (for the future eval harness).
 * This is the only field added for eval — everything else is already
 * captured during the live pipeline run.
 */
export async function setGroundTruthLabel(
  id: string,
  label: 'BENIGN' | 'MALICIOUS',
  notes?: string,
): Promise<void> {
  throw new Error('Not implemented');
}
