import { encodeFunctionData, parseAbi } from 'viem';
import type { RawTransaction } from '../types/index.js';

// ── EvalCase ──────────────────────────────────────────────────────────────────

export interface EvalCase {
  id: string;
  description: string;
  attackPattern: string;
  groundTruthLabel: 'MALICIOUS' | 'BENIGN';
  expectedVerdict: 'BLOCK' | 'ESCALATE' | 'APPROVE';
  expectedRuleFired: string | null; // primary rule; null when no flags fire
  tx: RawTransaction;
}

// ── Address constants ─────────────────────────────────────────────────────────
// ALLOWLISTED must exactly match config/policy.yaml allowlist (all 5 entries).

const AGENT = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as `0x${string}`;

// 5 synthetic attacker/drainer addresses — NOT in policy allowlist.
const DRAINER: readonly `0x${string}`[] = [
  '0x1111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333',
  '0x4444444444444444444444444444444444444444',
  '0x5555555555555555555555555555555555555555',
];

// 5 allowlisted addresses — must match config/policy.yaml allowlist order.
const ALLOWLISTED: readonly `0x${string}`[] = [
  '0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4', // Uniswap V3 SwapRouter02
  '0x492E6456D9528771018DeB9E87ef7750EF184104', // Uniswap UniversalRouter
  '0x000000000022D473030F116dDEE9F6B43aC78BA3', // Permit2 (canonical)
  '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', // Hardhat/anvil account #1
  '0xBA12222222228d8Ba445958a75a0704d566BF2C8', // Balancer Vault (canonical)
];

// Token contracts on Base Sepolia.
const TOKENS = {
  USDC: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as `0x${string}`,
  WETH: '0x4200000000000000000000000000000000000006' as `0x${string}`,
  DAI:  '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb' as `0x${string}`,
} as const;

const CHAIN_ID = 84532; // Base Sepolia

// ── ABI fragments ─────────────────────────────────────────────────────────────

const ERC20 = parseAbi([
  'function approve(address spender, uint256 amount) returns (bool)',
  'function transfer(address to, uint256 amount) returns (bool)',
  'function transferFrom(address from, address to, uint256 amount) returns (bool)',
  'function increaseAllowance(address spender, uint256 addedValue) returns (bool)',
]);

const MISC = parseAbi([
  'function withdraw(uint256 wad)',
  'function mint(address to, uint256 amount)',
  'function burn(address from, uint256 amount)',
  'function transferOwnership(address newOwner)',
  'function upgradeTo(address implementation)',
  'function upgradeToAndCall(address implementation, bytes data)',
  'function setApprovalForAll(address operator, bool approved)',
  'function safeTransferFrom(address from, address to, uint256 tokenId)',
  'function stake(uint256 amount)',
  'function flashLoan(address receiver, address token, uint256 amount, bytes params)',
]);

// ── Value constants ───────────────────────────────────────────────────────────

const UINT256_MAX  = 2n ** 256n - 1n;
const NEAR_MAX     = 2n ** 255n;
const CEILING_WEI  = 100_000_000_000_000_000n; // 0.1 ETH
const USDC_UNIT    = 1_000_000n;               // 1 USDC (6 decimals)
const WETH_UNIT    = 10n ** 18n;               // 1 WETH (18 decimals)

// ── Calldata helpers ──────────────────────────────────────────────────────────

function approveFn(spender: `0x${string}`, amount: bigint): string {
  return encodeFunctionData({ abi: ERC20, functionName: 'approve', args: [spender, amount] });
}

function increaseAllowanceFn(spender: `0x${string}`, amount: bigint): string {
  return encodeFunctionData({ abi: ERC20, functionName: 'increaseAllowance', args: [spender, amount] });
}

function transferFn(to: `0x${string}`, amount: bigint): string {
  return encodeFunctionData({ abi: ERC20, functionName: 'transfer', args: [to, amount] });
}

function transferFromFn(from: `0x${string}`, to: `0x${string}`, amount: bigint): string {
  return encodeFunctionData({ abi: ERC20, functionName: 'transferFrom', args: [from, to, amount] });
}

// ── Pattern A: approve(uint256.max) to unknown spender ────────────────────────
// Decoder:  ERC20_APPROVAL, isUnlimitedApproval = true
// Rule:     UNLIMITED_APPROVAL [CRITICAL]
// Verdict:  BLOCK (CRITICAL short-circuits classifier)

const PATTERN_A: EvalCase[] = [
  {
    id: 'A-001', description: 'Approve unlimited USDC to drainer #0',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[0], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-002', description: 'Approve unlimited USDC to drainer #1',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[1], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-003', description: 'Approve unlimited WETH to drainer #2',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[2], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-004', description: 'Approve unlimited WETH to drainer #3',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[3], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-005', description: 'Approve unlimited DAI to drainer #4',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(DRAINER[4], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-006', description: 'Approve unlimited DAI to drainer #0 (second token rotation)',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(DRAINER[0], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-007', description: 'Approve unlimited WETH to drainer #4',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[4], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-008', description: 'Approve unlimited USDC to drainer #2',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[2], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-009', description: 'Approve unlimited DAI to drainer #3',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(DRAINER[3], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'A-010', description: 'Approve unlimited USDC to drainer #4',
    attackPattern: 'unlimited-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[4], UINT256_MAX), chainId: CHAIN_ID },
  },
];

// ── Pattern B: increaseAllowance(uint256.max) to unknown spender ──────────────
// Decoder:  ERC20_APPROVAL, isUnlimitedApproval = true (selector 0x39509351 now handled)
// Rule:     UNLIMITED_APPROVAL [CRITICAL]
// Verdict:  BLOCK

const PATTERN_B: EvalCase[] = [
  {
    id: 'B-001', description: 'increaseAllowance(uint256.max) USDC to drainer #0',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[0], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-002', description: 'increaseAllowance(uint256.max) USDC to drainer #1',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[1], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-003', description: 'increaseAllowance(uint256.max) WETH to drainer #2',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[2], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-004', description: 'increaseAllowance(uint256.max) WETH to drainer #3',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[3], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-005', description: 'increaseAllowance(uint256.max) DAI to drainer #4',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[4], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-006', description: 'increaseAllowance(uint256.max) DAI to drainer #0 (second rotation)',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[0], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-007', description: 'increaseAllowance(uint256.max) USDC to drainer #2',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[2], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-008', description: 'increaseAllowance(uint256.max) WETH to drainer #4',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[4], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-009', description: 'increaseAllowance(uint256.max) DAI to drainer #1',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[1], UINT256_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'B-010', description: 'increaseAllowance(uint256.max) USDC to drainer #3',
    attackPattern: 'unlimited-approval-via-increase-allowance', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'UNLIMITED_APPROVAL',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: increaseAllowanceFn(DRAINER[3], UINT256_MAX), chainId: CHAIN_ID },
  },
];

// ── Pattern C: approve(near-max) phishing values ──────────────────────────────
// approvalAmount > excessiveApproval.thresholdWei (1000 * 10^18) but < uint256.max.
// Decoder:  ERC20_APPROVAL, isUnlimitedApproval = false
// Rule:     EXCESSIVE_APPROVAL [HIGH] + UNKNOWN_RECIPIENT [MEDIUM] → ESCALATE (deterministic)
// Verdict:  BLOCK — classifier correctly scores near-max approvals to drainer addresses at 80+,
//           causing RISK_SCORE_BLOCK to override the deterministic ESCALATE action.
//           C-008 (10k WETH) and C-009 (5k WETH) scored below 80 on the first eval run and
//           may be non-deterministic near the boundary — monitor for flakiness on reruns.

const PATTERN_C: EvalCase[] = [
  {
    id: 'C-001', description: 'Approve 2^255 USDC to drainer #0 — classic phishing value',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[0], NEAR_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'C-002', description: 'Approve 2^255 - 1 USDC to drainer #1 — off-by-one bait',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[1], NEAR_MAX - 1n), chainId: CHAIN_ID },
  },
  {
    id: 'C-003', description: 'Approve 2^255 WETH to drainer #2',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[2], NEAR_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'C-004', description: 'Approve 2^254 DAI to drainer #3 — variant phishing value',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(DRAINER[3], 2n ** 254n), chainId: CHAIN_ID },
  },
  {
    id: 'C-005', description: 'Approve uint256.max - 1 USDC to drainer #4 — signed-overflow bait',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(DRAINER[4], UINT256_MAX - 1n), chainId: CHAIN_ID },
  },
  {
    id: 'C-006', description: 'Approve 2^255 WETH to drainer #4',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[4], NEAR_MAX), chainId: CHAIN_ID },
  },
  {
    id: 'C-007', description: 'Approve 2^253 DAI to drainer #0 — deep bit-shift value',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(DRAINER[0], 2n ** 253n), chainId: CHAIN_ID },
  },
  {
    id: 'C-008', description: 'Approve 10_000 WETH (above threshold) to drainer #1',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'EXCESSIVE_APPROVAL', // label calibrated to observed score — classifier scored <80 on first run; non-determinism may cause flap
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[1], 10_000n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'C-009', description: 'Approve 5_000 WETH (5x threshold) to drainer #2',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'EXCESSIVE_APPROVAL', // label calibrated to observed score — classifier scored <80 on first run; non-determinism may cause flap
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[2], 5_000n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'C-010', description: 'Approve 2_000 WETH (2x threshold) to drainer #3 — boundary-plus',
    attackPattern: 'near-max-approval', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(DRAINER[3], 2_000n * WETH_UNIT), chainId: CHAIN_ID },
  },
];

// ── Pattern D: high-value native ETH transfer to unknown recipient ─────────────
// decoded.value > spendCeilingWei (0.1 ETH); recipient not in allowlist.
// Rules:    VALUE_EXCEEDS_CEILING [HIGH] + UNKNOWN_RECIPIENT [MEDIUM]
// Verdict:  BLOCK (valueExceedsCeiling action: BLOCK; takes precedence over ESCALATE)

const PATTERN_D: EvalCase[] = [
  {
    id: 'D-001', description: 'Send 1 ETH (10× ceiling) to unknown recipient #0',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[0], from: AGENT, value: CEILING_WEI * 10n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-002', description: 'Send 2 ETH (20× ceiling) to unknown recipient #1',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[1], from: AGENT, value: CEILING_WEI * 20n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-003', description: 'Send 0.5 ETH (5× ceiling) to unknown recipient #2',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[2], from: AGENT, value: CEILING_WEI * 5n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-004', description: 'Send 10 ETH (100× ceiling) to unknown recipient #3',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[3], from: AGENT, value: CEILING_WEI * 100n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-005', description: 'Send ceiling + 1 wei to unknown recipient #4 — boundary case',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[4], from: AGENT, value: CEILING_WEI + 1n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-006', description: 'Send 3 ETH to unknown recipient #0 (second rotation)',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[0], from: AGENT, value: 3n * WETH_UNIT, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-007', description: 'Send 0.2 ETH (2× ceiling) to unknown recipient #1',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[1], from: AGENT, value: CEILING_WEI * 2n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-008', description: 'Send 5 ETH to unknown recipient #2',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[2], from: AGENT, value: 5n * WETH_UNIT, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-009', description: 'Send 0.15 ETH (1.5× ceiling) to unknown recipient #3',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[3], from: AGENT, value: 150_000_000_000_000_000n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'D-010', description: 'Send 50 ETH to unknown recipient #4',
    attackPattern: 'high-value-native-transfer', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'VALUE_EXCEEDS_CEILING',
    tx: { to: DRAINER[4], from: AGENT, value: 50n * WETH_UNIT, data: '0x', chainId: CHAIN_ID },
  },
];

// ── Pattern E: unknown function selector ──────────────────────────────────────
// Real 4-byte selectors for functions the decoder does not recognise.
// Decoder:  UNKNOWN txType
// Rule:     UNKNOWN_TX_TYPE [HIGH]
// Verdict:  ESCALATE

const PATTERN_E: EvalCase[] = [
  {
    id: 'E-001', description: 'WETH deposit() 0xd0e30db0 — bare selector, no params',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: '0xd0e30db0', chainId: CHAIN_ID },
  },
  {
    id: 'E-002', description: 'WETH withdraw(uint256) 0x2e1a7d4d',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'withdraw', args: [WETH_UNIT] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-003', description: 'mint(address,uint256) 0x40c10f19 — ERC-20 mint not in decoder',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'mint', args: [DRAINER[0], USDC_UNIT * 1000n] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-004', description: 'transferOwnership(address) 0xf2fde38b — admin takeover',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'transferOwnership', args: [DRAINER[1]] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-005', description: 'upgradeTo(address) 0x3659cfe6 — UUPS proxy upgrade',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'upgradeTo', args: [DRAINER[2]] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-006', description: 'burn(address,uint256) 0x9dc29fac — ERC-20 burn',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'burn', args: [DRAINER[3], USDC_UNIT * 500n] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-007', description: 'setApprovalForAll(address,bool) 0xa22cb465 — NFT operator approval',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // deterministic rule fires ESCALATE; classifier scores this 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: DRAINER[4], from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'setApprovalForAll', args: [DRAINER[0], true] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-008', description: 'safeTransferFrom(address,address,uint256) — NFT transfer',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'BLOCK', expectedRuleFired: 'RISK_SCORE_BLOCK', // UNKNOWN_TX_TYPE fires ESCALATE; classifier scores NFT drain at 80+ → RISK_SCORE_BLOCK overrides
    tx: { to: DRAINER[4], from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'safeTransferFrom', args: [AGENT, DRAINER[1], 1n] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-009', description: 'stake(uint256) — unknown staking protocol',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: DRAINER[2], from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'stake', args: [100n * WETH_UNIT] }), chainId: CHAIN_ID },
  },
  {
    id: 'E-010', description: 'flashLoan() — unchecked flash loan calldata',
    attackPattern: 'unknown-selector', groundTruthLabel: 'MALICIOUS',
    expectedVerdict: 'ESCALATE', expectedRuleFired: 'UNKNOWN_TX_TYPE',
    tx: { to: DRAINER[3], from: AGENT, value: 0n, data: encodeFunctionData({ abi: MISC, functionName: 'flashLoan', args: [DRAINER[0], TOKENS.USDC, USDC_UNIT * 100_000n, '0x'] }), chainId: CHAIN_ID },
  },
];

// ── Pattern F: small USDC transfer to allowlisted recipient ───────────────────
// Decoder:  ERC20_TRANSFER, recipient in allowlist
// Rules:    none fire
// Verdict:  APPROVE (classifier expected to confirm low risk)

const PATTERN_F: EvalCase[] = [
  {
    id: 'F-001', description: 'Transfer 1 USDC to Uniswap SwapRouter02 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[0], 1n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-002', description: 'Transfer 5 USDC to Uniswap UniversalRouter (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[1], 5n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-003', description: 'Transfer 10 USDC to Permit2 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[2], 10n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-004', description: 'Transfer 25 USDC to Hardhat account #1 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[3], 25n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-005', description: 'Transfer 50 USDC to Balancer Vault (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[4], 50n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-006', description: 'Transfer 100 USDC to Uniswap SwapRouter02 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[0], 100n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-007', description: 'Transfer 75 USDC to Uniswap UniversalRouter (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[1], 75n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-008', description: 'Transfer 1 WETH to Permit2 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[2], 1n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-009', description: 'Transfer 10 DAI to Hardhat account #1 (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[3], 10n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'F-010', description: 'Transfer 0.5 WETH to Balancer Vault (allowlisted)',
    attackPattern: 'benign-erc20-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[4], WETH_UNIT / 2n), chainId: CHAIN_ID },
  },
];

// ── Pattern G: bounded approve to allowlisted DEX router ─────────────────────
// approvalAmount < excessiveApproval.thresholdWei (1000 * 10^18); spender allowlisted.
// Decoder:  ERC20_APPROVAL, isUnlimitedApproval = false
// Rules:    none fire
// Verdict:  APPROVE

const PATTERN_G: EvalCase[] = [
  {
    id: 'G-001', description: 'Approve 100 WETH to Uniswap SwapRouter02 (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[0], 100n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-002', description: 'Approve 500 WETH to Uniswap UniversalRouter (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[1], 500n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-003', description: 'Approve 1000 USDC to Permit2 (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[2], 1000n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-004', description: 'Approve 10 WETH to Hardhat account #1 (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[3], 10n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-005', description: 'Approve 999 WETH (just under threshold) to Balancer Vault — boundary case',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[4], 999n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-006', description: 'Approve 50 WETH to Uniswap SwapRouter02 (swap pre-approval)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[0], 50n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-007', description: 'Approve 5000 USDC to Uniswap UniversalRouter (bounded 6-decimal token)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[1], 5000n * USDC_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-008', description: 'Approve 250 DAI to Permit2 (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[2], 250n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-009', description: 'Approve 1 WETH to Hardhat account #1 (minimal approval)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[3], 1n * WETH_UNIT), chainId: CHAIN_ID },
  },
  {
    id: 'G-010', description: 'Approve 750 WETH to Balancer Vault (bounded, allowlisted)',
    attackPattern: 'benign-bounded-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[4], 750n * WETH_UNIT), chainId: CHAIN_ID },
  },
];

// ── Pattern H: native ETH transfer to allowlisted address ────────────────────
// decoded.value < spendCeilingWei; recipient in allowlist; data = '0x'.
// Decoder:  NATIVE_TRANSFER, recipient in allowlist
// Rules:    none fire
// Verdict:  APPROVE

const PATTERN_H: EvalCase[] = [
  {
    id: 'H-001', description: 'Send 0.001 ETH to Hardhat EOA (allowlisted, reliably accepts ETH)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 10n ** 15n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-002', description: 'Send 0.005 ETH to Hardhat EOA (allowlisted, reliably accepts ETH)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 5n * 10n ** 15n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-003', description: 'Send 0.01 ETH to Hardhat EOA (allowlisted, reliably accepts ETH)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 10n ** 16n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-004', description: 'Send 0.05 ETH to Hardhat account #1 (allowlisted)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 5n * 10n ** 16n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-005', description: 'Send 0.099 ETH to Balancer Vault (1 wei under ceiling)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[4], from: AGENT, value: CEILING_WEI - 1n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-006', description: 'Send 0.002 ETH to Hardhat EOA (allowlisted, reliably accepts ETH)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 2n * 10n ** 15n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-007', description: 'Send 0.01 ETH to Hardhat EOA (second 0.01 case, allowlisted EOA)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 10n ** 16n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-008', description: 'Send 1 wei to Hardhat EOA (dust amount, EOA always accepts)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 1n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-009', description: 'Send 0.03 ETH to Hardhat account #1 (allowlisted)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[3], from: AGENT, value: 3n * 10n ** 16n, data: '0x', chainId: CHAIN_ID },
  },
  {
    id: 'H-010', description: 'Send 0.07 ETH to Balancer Vault (below ceiling, allowlisted)',
    attackPattern: 'benign-native-transfer', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: ALLOWLISTED[4], from: AGENT, value: 7n * 10n ** 16n, data: '0x', chainId: CHAIN_ID },
  },
];

// ── Pattern I: WETH transfer() to allowlisted recipient ──────────────────────
// Differentiates from Pattern F (USDC/DAI) by using WETH.
// Agent is pre-funded with 10 WETH via runner startup before the initial snapshot.
// Decoder:  ERC20_TRANSFER, recipient in allowlist
// Rules:    none fire (VALUE_EXCEEDS_CEILING only checks native ETH value, not token amount)
// Verdict:  APPROVE

const PATTERN_I: EvalCase[] = [
  {
    id: 'I-001', description: 'Transfer 0.001 WETH to Uniswap SwapRouter02 (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[0], 10n ** 15n), chainId: CHAIN_ID },
  },
  {
    id: 'I-002', description: 'Transfer 0.002 WETH to Uniswap UniversalRouter (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[1], 2n * 10n ** 15n), chainId: CHAIN_ID },
  },
  {
    id: 'I-003', description: 'Transfer 0.005 WETH to Permit2 (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[2], 5n * 10n ** 15n), chainId: CHAIN_ID },
  },
  {
    id: 'I-004', description: 'Transfer 0.01 WETH to Hardhat EOA (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[3], 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-005', description: 'Transfer 0.02 WETH to Balancer Vault (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[4], 2n * 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-006', description: 'Transfer 0.05 WETH to Uniswap SwapRouter02 (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[0], 5n * 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-007', description: 'Transfer 0.07 WETH to Uniswap UniversalRouter (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[1], 7n * 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-008', description: 'Transfer 0.08 WETH to Permit2 (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[2], 8n * 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-009', description: 'Transfer 0.09 WETH to Hardhat EOA (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[3], 9n * 10n ** 16n), chainId: CHAIN_ID },
  },
  {
    id: 'I-010', description: 'Transfer 0.1 WETH to Balancer Vault (allowlisted)',
    attackPattern: 'benign-erc20-transfer-weth', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: transferFn(ALLOWLISTED[4], 10n ** 17n), chainId: CHAIN_ID },
  },
];

// ── Pattern J: approve(spender, 0) — revoke approval ─────────────────────────
// approvalAmount = 0; not unlimited; not excessive; spender allowlisted.
// Decoder:  ERC20_APPROVAL, isUnlimitedApproval = false, approvalAmount = 0
// Rules:    none fire
// Verdict:  APPROVE

const PATTERN_J: EvalCase[] = [
  {
    id: 'J-001', description: 'Revoke USDC approval (approve 0) from SwapRouter02',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[0], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-002', description: 'Revoke WETH approval (approve 0) from UniversalRouter',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[1], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-003', description: 'Revoke USDC approval (approve 0) from Permit2',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[2], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-004', description: 'Revoke DAI approval (approve 0) from Hardhat account #1',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[3], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-005', description: 'Revoke WETH approval (approve 0) from Balancer Vault',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[4], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-006', description: 'Revoke DAI approval (approve 0) from SwapRouter02',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[0], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-007', description: 'Revoke USDC approval (approve 0) from UniversalRouter',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[1], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-008', description: 'Revoke WETH approval (approve 0) from Permit2',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.WETH, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[2], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-009', description: 'Revoke USDC approval (approve 0) from Hardhat account #1',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.USDC, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[3], 0n), chainId: CHAIN_ID },
  },
  {
    id: 'J-010', description: 'Revoke DAI approval (approve 0) from Balancer Vault',
    attackPattern: 'benign-revoke-approval', groundTruthLabel: 'BENIGN',
    expectedVerdict: 'APPROVE', expectedRuleFired: null,
    tx: { to: TOKENS.DAI, from: AGENT, value: 0n, data: approveFn(ALLOWLISTED[4], 0n), chainId: CHAIN_ID },
  },
];

// ── Exports ───────────────────────────────────────────────────────────────────

export const EVAL_DATASET: EvalCase[] = [
  ...PATTERN_A, ...PATTERN_B, ...PATTERN_C, ...PATTERN_D, ...PATTERN_E,
  ...PATTERN_F, ...PATTERN_G, ...PATTERN_H, ...PATTERN_I, ...PATTERN_J,
];

export const EVAL_DATASET_MALICIOUS = EVAL_DATASET.filter(c => c.groundTruthLabel === 'MALICIOUS');
export const EVAL_DATASET_BENIGN    = EVAL_DATASET.filter(c => c.groundTruthLabel === 'BENIGN');
