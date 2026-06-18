import 'dotenv/config';
import express from 'express';
import { initDb } from './audit/index.js';

const app = express();
app.use(express.json());

// ─── Decision feed ────────────────────────────────────────────────────────────
// GET  /api/decisions          — paginated list of audit records
// GET  /api/decisions/:id      — single decision detail
// POST /api/decisions/:id/verdict — human approve/reject for ESCALATE items

// ─── Internal evaluation endpoint (called by AgentKit hook) ──────────────────
// POST /api/evaluate           — submit RawTransaction, returns Decision

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

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
