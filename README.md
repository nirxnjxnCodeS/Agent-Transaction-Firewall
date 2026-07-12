# Agent Transaction Firewall

A pre-signing safety checkpoint for AI agents that transact on-chain. Before any transaction reaches a wallet, it passes through a seven-stage pipeline that simulates, risk-scores, and either approves, blocks, or escalates it to a human reviewer.

Built to answer a real problem: autonomous agents increasingly hold on-chain wallets and execute transactions without human confirmation. Once a transaction is signed and broadcast, it is irreversible. This project is the pre-trade risk control layer that doesn't yet exist for agentic finance — the on-chain equivalent of what regulated markets require before any trade executes (SEC 15c3-5 / NYDFS pre-trade controls).

---

## Eval Results

Measured on a 100-case labeled dataset (50 malicious / 50 benign, 10 attack patterns):

| Metric | Value |
|---|---|
| BLOCK precision | 100% |
| BLOCK recall | 100% |
| APPROVE precision | 100% |
| APPROVE recall | 96% |
| False positive rate | 2% |
| Eval dataset | 100 cases · 10 attack patterns |
| Mean pipeline latency | ~10.5s (local: ~1.6s · Claude API: 6–11s) |

Every transaction that was blocked should have been blocked. No malicious transaction reached APPROVE. The two false positives (2%) are WETH transfers to the Permit2 contract that the classifier correctly identifies as unusual flows — they escalate to human review rather than auto-approving, which is the intended fail-safe behavior.

Score distribution for benign transactions: min=5, max=45, mean=18 — zero benign cases scored above the 50-point escalation threshold before the human-review gate.

---

## Architecture

```
Agent (Coinbase AgentKit)
    │
    │  RawTransaction
    ▼
┌─────────────────────────────────────────────────────┐
│                  Firewall Service                    │
│                                                     │
│  1. Decoder      — parse calldata into typed fields │
│  2. Simulator    — fork Base Sepolia via Foundry    │
│                    predict state changes            │
│  3. Rules        — deterministic checks:            │
│                    UNLIMITED_APPROVAL [CRITICAL]    │
│                    EXCESSIVE_APPROVAL [HIGH]        │
│                    DENYLIST_ADDRESS   [CRITICAL]    │
│                    VALUE_EXCEEDS_CEILING [HIGH]     │
│                    UNKNOWN_RECIPIENT  [MEDIUM]      │
│                    UNKNOWN_TX_TYPE   [HIGH]         │
│                                                     │
│  4. Short-circuit — CRITICAL flags skip classifier  │
│                     (cost/latency optimization)     │
│                                                     │
│  5. Classifier   — Claude API (forced tool-use)     │
│                    structured JSON output:          │
│                    riskScore · category · reasoning │
│                                                     │
│  6. Policy       — YAML-configured thresholds       │
│                    verdict precedence:              │
│                    denylist → CRITICAL → score≥80  │
│                    → HIGH flags → score≥50         │
│                    → MEDIUM/LOW → APPROVE           │
│                                                     │
│  7. Audit        — every decision logged to SQLite  │
│                    with groundTruthLabel field      │
│                    for eval harness reuse           │
└─────────────────────────────────────────────────────┘
    │
    ├── APPROVE  → wallet signs and broadcasts
    ├── BLOCK    → transaction rejected, reason logged
    └── ESCALATE → paused, surfaced in dashboard
                   for human approve/reject
```

### Key design decisions

**Fail-escalate, not fail-block.** When the classifier is unavailable (timeout, API error), the system escalates rather than blocking. BLOCK asserts "this is dangerous." A timeout asserts nothing — the correct response is human review.

**CRITICAL flags short-circuit the classifier.** An `UNLIMITED_APPROVAL` to an unknown address is definitionally a block. Calling Claude to get a second opinion on the obvious case costs latency and money without changing the outcome. The classifier only runs when it can actually affect the verdict.

**Classifier output is advisory, not authoritative.** The classifier returns `riskScore`, `reasoning`, and `category` — no `verdict`, no `action`. Policy applies the thresholds. This boundary prevents the LLM from overriding deterministic safety rules.

**Synthetic eval dataset, not replayed mainnet transactions.** The 100-case eval dataset is constructed from documented attack patterns (Inferno Drainer phishing flows, increaseAllowance drains, proxy upgrade exploits) rather than historical transaction hashes. This is more defensible: the eval measures whether the pipeline catches the *pattern*, not whether it can replay one specific historical event.

**Audit log doubles as eval dataset seed.** Every pipeline decision is stored with a `groundTruthLabel` field, making live production traffic directly usable for future eval dataset expansion without schema changes.

---

## Attack Patterns Tested

| Pattern | Attack | Expected | Result |
|---|---|---|---|
| A | `approve(uint256.max)` to unknown spender | BLOCK | 10/10 ✓ |
| B | `increaseAllowance(uint256.max)` to unknown spender | BLOCK | 10/10 ✓ |
| C | Near-max approval (2^255) — phishing pattern | BLOCK | 10/10 ✓ |
| D | High-value ETH transfer to unknown recipient | BLOCK | 10/10 ✓ |
| E | Unknown function selector (proxy upgrades, mints) | ESCALATE | 10/10 ✓ |
| F | Small USDC transfer to allowlisted address | APPROVE | 9/10 ✓ |
| G | Bounded approval to known DEX router | APPROVE | 10/10 ✓ |
| H | Native ETH transfer to allowlisted EOA | APPROVE | 10/10 ✓ |
| I | WETH transfer to allowlisted address | APPROVE | 9/10 ✓ |
| J | Revoke approval (`approve(spender, 0)`) | APPROVE | 10/10 ✓ |

Pattern B (increaseAllowance) is worth noting: `increaseAllowance(uint256.max)` is a documented phishing vector used by drainer kits to acquire unlimited token access without triggering the more-recognized `approve` pattern. It is caught at 100% recall.

---

## Stack

| Layer | Technology |
|---|---|
| Agent | Coinbase AgentKit + ViemWalletProvider |
| Chain | Base Sepolia (EVM) |
| Simulation | Foundry/anvil — self-hosted fork, no external dependency |
| Classifier | Claude API (claude-sonnet-4-6, forced tool-use, Zod validation) |
| Service | Node.js / TypeScript / Express |
| Dashboard | Next.js 15 / React 19 |
| Audit log | SQLite (better-sqlite3, WAL mode) |
| Testing | Vitest — 80 unit tests |
| Eval | Custom harness — 100 labeled cases, precision/recall/FPR |

---

## Running Locally

**Prerequisites:** Node.js 20+, Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)

```bash
# 1. Clone and install
git clone https://github.com/nirxnjxnCodeS/agent-tx-firewall
cd agent-tx-firewall
npm install

# 2. Configure environment
cp service/.env.example service/.env
# Fill in: ANTHROPIC_API_KEY, BASE_SEPOLIA_RPC_URL, AGENT_PRIVATE_KEY

# 3. Start anvil fork (terminal 1)
npm run anvil:fork --workspace=service

# 4. Start firewall service (terminal 2)
npm run dev --workspace=service

# 5. Start dashboard (terminal 3)
npm run dev --workspace=dashboard
# → http://localhost:3000

# 6. Run the agent (triggers a demo transaction)
npm run agent --workspace=service

# 7. Run eval harness
npm run eval --workspace=service
```

---

## Limitations

These are documented design constraints, not oversights:

**Classifier latency: 6–11s per transaction, non-deterministic.** The local pipeline (decode + simulate + rules) takes ~1.6s. The Claude API round-trip adds 6–11s with ~2× run-to-run variance. This is acceptable for a pre-signing checkpoint where correctness matters more than speed, but would require caching or a faster inference endpoint for high-frequency agent workflows.

**Storage diffs not implemented.** The simulator captures ETH and ERC-20 balance changes but not raw storage slot diffs. Full slot-level diffs would require `debug_traceCall`, which is buildable but out of scope for this version.

**Eval dataset is synthetic.** Attack patterns are modeled on real documented exploits but constructed synthetically rather than replayed from mainnet. This makes the eval reproducible and independent of fork-block state but means real-world attack variation isn't fully represented.

**Two benign WETH→Permit2 transfers escalate rather than approve.** The classifier correctly identifies direct WETH transfers to the Permit2 contract as an unusual pattern (score 62, above the 50-point escalation threshold). This is the intended fail-safe behavior — uncertain cases go to humans, not through automatically. Raising the escalation threshold to 65 would resolve these two cases but would be tuning the threshold to pass tests rather than to real risk.

**No cross-chain support.** The firewall is scoped to EVM-compatible chains. Non-EVM agent activity (Solana, SUI, TON) is out of scope.

---

## Project Context

Built as a portfolio project to demonstrate production-level AI engineering patterns in a Web3 context:

- **Agentic tool-use with restraint** — the classifier is constrained to advisory output (score + reasoning only, no verdict), with policy applying thresholds. The LLM cannot override deterministic safety rules.
- **Evaluation rigor** — a labeled dataset with precision/recall/FPR metrics and a CI-gatable eval runner, not just "it works in the demo."
- **Fail-safe design** — fail-escalate (not fail-block, not fail-crash), CRITICAL short-circuit before classifier, audit trail that distinguishes "escalated because risky" from "escalated because classifier unavailable."
- **Honest limitations** — the section above documents exactly where this system breaks. Production hardening would address latency (batching/caching), storage diffs (debug_traceCall), and cross-chain support.

---

*Stack: Node.js · TypeScript · Solidity/EVM · Foundry · Coinbase AgentKit · Claude API · Next.js · SQLite*
