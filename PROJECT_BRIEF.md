# Agent Transaction Firewall — Project Brief (v1: Weeks 1–2)

## One-line pitch
A safety checkpoint that intercepts AI-agent-initiated blockchain transactions before they're signed, simulates and risk-scores them, enforces policy, and either auto-approves, blocks, or escalates to a human — with every decision logged for a future evaluation harness.

## Why this exists (for context, not implementation)
AI agents are increasingly given on-chain wallets to act autonomously (Coinbase AgentKit, GOAT SDK, etc.). Once a transaction is signed and broadcast, it's irreversible. There is no equivalent yet of pre-trade risk controls (the kind regulated finance requires, e.g. SEC 15c3-5) for autonomous on-chain agents. This project builds that layer.

## Stack (locked)
- Agent framework: **Coinbase AgentKit** (Node/TypeScript)
- Simulation: **Tenderly Simulation API** (v1 — may migrate to Foundry/anvil fork later, not in scope now)
- Chain: **Base Sepolia** testnet
- Service: **Single Node/TypeScript service**, modular internals (NOT split into microservices — that's an explicit non-goal for v1)
- Frontend: Minimal **Next.js** dashboard
- LLM: Claude API (structured/JSON output) for risk classification
- Storage: Simple DB (SQLite or Postgres — pick whichever is faster to stand up) for decision logs

## Scope for THIS phase (weeks 1–2 only)

### In scope
1. An AgentKit-based agent that can attempt basic on-chain actions on Base Sepolia: native transfer, ERC-20 transfer, ERC-20 approval, and a simple swap (use a testnet DEX or mock if a real one isn't practical on Sepolia).
2. Interception point: hook into AgentKit's **action-provider layer** (not the wallet provider, since the wallet provider is what signs — the firewall must run *before* signing happens).
3. Middleware pipeline, in this order, as separate modules under one service:
   - `decoder/` — decode calldata: function selector, recipient address, value, token approval amount if applicable. Output a normalized `DecodedTransaction` type.
   - `simulator/` — call Tenderly Simulation API with the decoded tx, return predicted state changes / simulation result.
   - `rules/` — deterministic rule checks: unlimited/excessive approval amounts, recipient not in an allowlist, value exceeding a configured ceiling. Output a list of triggered flags.
   - `classifier/` — call Claude with the decoded tx + simulation result + rule flags, get back a structured JSON risk assessment: `{ riskScore: number, reasoning: string, category: string }`.
   - `policy/` — YAML-configured policy engine. Inputs: rule flags + classifier output. Outputs one of `APPROVE | BLOCK | ESCALATE`, based on configurable thresholds (spend ceilings, allowlist enforcement, risk score thresholds).
   - `audit/` — log every decision (full pipeline input/output at each stage) to the DB. This log is also the future eval dataset — schema should be designed with that reuse in mind (i.e., easy to later add a `groundTruthLabel` field).
   - A pipeline orchestrator that wires these together and exposes a single function: `evaluateTransaction(tx) -> Decision`.
4. If policy verdict is `ESCALATE`: the transaction is paused (not signed), surfaced via an API endpoint, and waits for a human approve/reject action.
5. If `APPROVE`: passed through to the wallet provider for actual signing/broadcast.
6. If `BLOCK`: rejected, never reaches signing, reason logged.
7. Minimal Next.js dashboard: a live feed/list of past decisions (tx details, simulation summary, flags, classifier output, policy verdict, outcome) and a simple approve/reject UI for items in `ESCALATE` state.

### Explicitly OUT of scope for this phase (do not build yet)
- Evaluation harness / labeled benign-vs-malicious dataset / precision-recall metrics
- CI/CD, automated regression testing of the classifier
- Immutable/tamper-evident audit trail (plain DB logging is fine for now)
- Polished UI/UX — functional only
- Splitting into multiple services
- Foundry/anvil migration

## Success criteria for this phase
- An agent attempts a transaction on Base Sepolia → it visibly passes through every pipeline stage → ends in APPROVE (signs & broadcasts), BLOCK (rejected), or ESCALATE (paused for human) → decision is logged → dashboard shows it.
- At least one test case demonstrably triggers BLOCK (e.g., unlimited approval to an unknown address) and one demonstrably triggers APPROVE (e.g., small transfer to an allowlisted address), proving the pipeline actually discriminates rather than rubber-stamping everything.

## Notes for implementation
- Keep module boundaries clean and independently testable even though they live in one service — this matters for the portfolio story (demonstrates the separation exists in design, not just convenience).
- Design the audit log schema now with the eventual eval harness in mind, since that's the next phase and reusing this data is the point.
- Use structured/JSON-mode output from Claude for the classifier — don't parse free text.
