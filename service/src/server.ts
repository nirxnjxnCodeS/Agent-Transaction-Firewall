import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import { evaluateTransaction } from './orchestrator.js';
import { initDb, getRecord, listRecords, updateHumanVerdict } from './audit/index.js';
import type { HumanVerdictRequest, PolicyVerdict, RawTransaction } from './types/index.js';

const app = express();
app.use(express.json());

const bigintReplacer = (_k: string, v: unknown) =>
  typeof v === 'bigint' ? v.toString() : v;

// Safely extract a single string from Express query/param (which may be string|string[]|ParsedQs).
function qs(val: unknown): string | undefined {
  if (typeof val === 'string') return val;
  if (Array.isArray(val) && typeof val[0] === 'string') return val[0];
  return undefined;
}

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/health', (_req: Request, res: Response) => {
  res.json({ ok: true });
});

// ── POST /api/evaluate ────────────────────────────────────────────────────────
// Called by the AgentKit hook before signing. Accepts a RawTransaction with
// bigint fields serialized as decimal strings. Returns a Decision.

app.post('/api/evaluate', async (req: Request, res: Response) => {
  try {
    const b = req.body as Record<string, unknown>;
    const tx: RawTransaction = {
      to: String(b.to),
      from: String(b.from),
      value: BigInt((b.value as string | number | bigint | undefined) ?? '0'),
      data: String(b.data ?? '0x'),
      chainId: Number(b.chainId),
      nonce: b.nonce != null ? Number(b.nonce) : undefined,
      gasLimit: b.gasLimit != null ? BigInt(b.gasLimit as string) : undefined,
    };

    const decision = await evaluateTransaction(tx);
    // Serialize bigint fields as strings for JSON transport.
    res.json(JSON.parse(JSON.stringify(decision, bigintReplacer)));
  } catch (err) {
    console.error('[POST /api/evaluate]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/decisions ────────────────────────────────────────────────────────
// Paginated list of audit records.
// Query params: limit (default 50), offset (default 0), verdict, pendingHumanReview

app.get('/api/decisions', async (req: Request, res: Response) => {
  try {
    const limitStr = qs(req.query.limit);
    const offsetStr = qs(req.query.offset);
    const verdictStr = qs(req.query.verdict);

    const records = await listRecords({
      limit: limitStr != null ? Number(limitStr) : undefined,
      offset: offsetStr != null ? Number(offsetStr) : undefined,
      verdict: verdictStr != null ? (verdictStr as PolicyVerdict) : undefined,
      pendingHumanReview: req.query.pendingHumanReview === 'true' ? true : undefined,
    });
    res.json(records);
  } catch (err) {
    console.error('[GET /api/decisions]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/decisions/:id/resolve ──────────────────────────────────────────
// Human approve/reject for ESCALATE items. Body: { verdict, note? }

app.post('/api/decisions/:id/resolve', async (req: Request, res: Response) => {
  const id = qs(req.params['id']);
  if (!id) {
    res.status(400).json({ error: 'Missing id' });
    return;
  }

  const { verdict, note } = req.body as HumanVerdictRequest;
  if (verdict !== 'APPROVE' && verdict !== 'REJECT') {
    res.status(400).json({ error: 'verdict must be APPROVE or REJECT' });
    return;
  }

  try {
    await updateHumanVerdict(id, verdict, note);
    const record = await getRecord(id);
    if (!record) {
      res.status(404).json({ error: 'Decision not found' });
      return;
    }
    res.json(record);
  } catch (err) {
    console.error('[POST /api/decisions/:id/resolve]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Startup ───────────────────────────────────────────────────────────────────

async function main() {
  await initDb();

  const port = process.env.PORT ?? 3001;
  app.listen(port, () => {
    console.log(`Firewall service listening on :${port}`);
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
