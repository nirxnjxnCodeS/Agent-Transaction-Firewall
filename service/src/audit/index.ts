import Database from 'better-sqlite3';
import type { AuditRecord, Decision, PolicyVerdict } from '../types/index.js';

export interface ListRecordsOptions {
  limit?: number;
  offset?: number;
  /** Filter by final verdict. */
  verdict?: PolicyVerdict;
  /** If true, return only ESCALATE items with no human verdict yet. */
  pendingHumanReview?: boolean;
}

let db: Database.Database;

const CREATE_DECISIONS_TABLE = `
  CREATE TABLE IF NOT EXISTS decisions (
    id                  TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    chainId             INTEGER NOT NULL,
    fromAddress         TEXT NOT NULL,
    toAddress           TEXT NOT NULL,
    txType              TEXT NOT NULL,
    valueWei            TEXT NOT NULL,
    riskScore           INTEGER,
    riskCategory        TEXT,
    finalVerdict        TEXT NOT NULL,
    decodedTxJson       TEXT NOT NULL,
    simulationResultJson TEXT NOT NULL,
    ruleFlagsJson       TEXT NOT NULL,
    classifierOutputJson TEXT NOT NULL,
    policyDecisionJson  TEXT NOT NULL,
    humanVerdict        TEXT,
    humanTimestamp      TEXT,
    humanNote           TEXT,
    groundTruthLabel    TEXT,
    evalNotes           TEXT
  )
`;

const bigintReplacer = (_k: string, v: unknown) =>
  typeof v === 'bigint' ? v.toString() : v;

function toJson(val: unknown): string {
  return JSON.stringify(val, bigintReplacer);
}

function rowToRecord(row: Record<string, unknown>): AuditRecord {
  return row as unknown as AuditRecord;
}

/**
 * Initialize the SQLite database and run migrations (creates tables if
 * they don't exist). Call once at startup before any other audit functions.
 */
export async function initDb(dbPath?: string): Promise<void> {
  const resolved = dbPath ?? process.env.DB_PATH ?? './firewall.db';
  db = new Database(resolved);
  db.pragma('journal_mode = WAL');
  db.exec(CREATE_DECISIONS_TABLE);
}

/**
 * Persist a completed pipeline decision. Returns the stored record's ID.
 * Serializes bigint fields to strings before writing JSON blobs.
 */
export async function logDecision(decision: Decision): Promise<string> {
  const stmt = db.prepare(`
    INSERT INTO decisions (
      id, timestamp, chainId, fromAddress, toAddress, txType, valueWei,
      riskScore, riskCategory, finalVerdict,
      decodedTxJson, simulationResultJson, ruleFlagsJson,
      classifierOutputJson, policyDecisionJson,
      humanVerdict, humanTimestamp, humanNote,
      groundTruthLabel, evalNotes
    ) VALUES (
      @id, @timestamp, @chainId, @fromAddress, @toAddress, @txType, @valueWei,
      @riskScore, @riskCategory, @finalVerdict,
      @decodedTxJson, @simulationResultJson, @ruleFlagsJson,
      @classifierOutputJson, @policyDecisionJson,
      @humanVerdict, @humanTimestamp, @humanNote,
      @groundTruthLabel, @evalNotes
    )
  `);

  stmt.run({
    id: decision.id,
    timestamp: decision.timestamp,
    chainId: decision.raw.chainId,
    fromAddress: decision.raw.from,
    toAddress: decision.raw.to,
    txType: decision.decoded.txType,
    valueWei: decision.raw.value.toString(),
    riskScore: decision.classification?.riskScore ?? null,
    riskCategory: decision.classification?.category ?? null,
    finalVerdict: decision.policy.verdict,
    decodedTxJson: toJson(decision.decoded),
    simulationResultJson: toJson(decision.simulation),
    ruleFlagsJson: toJson(decision.ruleFlags),
    classifierOutputJson: toJson(decision.classification),
    policyDecisionJson: toJson(decision.policy),
    humanVerdict: null,
    humanTimestamp: null,
    humanNote: null,
    groundTruthLabel: null,
    evalNotes: null,
  });

  return decision.id;
}

/** Retrieve a single audit record by its UUID. */
export async function getRecord(id: string): Promise<AuditRecord | null> {
  const row = db.prepare('SELECT * FROM decisions WHERE id = ?').get(id) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToRecord(row) : null;
}

/** List audit records with optional filtering and pagination. */
export async function listRecords(opts?: ListRecordsOptions): Promise<AuditRecord[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (opts?.verdict) {
    conditions.push('finalVerdict = ?');
    params.push(opts.verdict);
  }

  if (opts?.pendingHumanReview) {
    conditions.push("finalVerdict = 'ESCALATE' AND humanVerdict IS NULL");
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = opts?.limit ?? 50;
  const offset = opts?.offset ?? 0;

  const rows = db
    .prepare(
      `SELECT * FROM decisions ${where} ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
    )
    .all([...params, limit, offset]) as Record<string, unknown>[];

  return rows.map(rowToRecord);
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
  db.prepare(`
    UPDATE decisions
    SET humanVerdict = ?, humanTimestamp = ?, humanNote = ?
    WHERE id = ?
  `).run(verdict, new Date().toISOString(), note ?? null, id);
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
  db.prepare(`
    UPDATE decisions SET groundTruthLabel = ?, evalNotes = ? WHERE id = ?
  `).run(label, notes ?? null, id);
}
