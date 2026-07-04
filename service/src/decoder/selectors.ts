import { parseAbi } from 'viem';

// ─── ERC-20 ABI fragments ────────────────────────────────────────────────────

export const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function transferFrom(address from, address to, uint256 amount) returns (bool)',
  'function increaseAllowance(address spender, uint256 addedValue) returns (bool)',
]);

// ─── Well-known 4-byte selectors ─────────────────────────────────────────────

export const SELECTOR = {
  ERC20_TRANSFER:           '0xa9059cbb' as const, // transfer(address,uint256)
  ERC20_APPROVE:            '0x095ea7b3' as const, // approve(address,uint256)
  ERC20_TRANSFER_FROM:      '0x23b872dd' as const, // transferFrom(address,address,uint256)
  ERC20_INCREASE_ALLOWANCE: '0x39509351' as const, // increaseAllowance(address,uint256)
} as const;

/**
 * Selectors that indicate a swap/routing call.
 * Extended as new DEX interfaces are seen in the wild.
 */
export const SWAP_SELECTORS = new Set<string>([
  // Uniswap V2 Router
  '0x38ed1739', // swapExactTokensForTokens
  '0x8803dbee', // swapTokensForExactTokens
  '0x7ff36ab5', // swapExactETHForTokens
  '0xfb3bdb41', // swapETHForExactTokens
  '0x18cbafe5', // swapExactTokensForETH
  '0x4a25d94a', // swapTokensForExactETH
  // Uniswap V3 Router / SwapRouter02
  '0x414bf389', // exactInputSingle
  '0xdb3e2198', // exactOutputSingle
  '0xc04b8d59', // exactInput
  '0xf28c0498', // exactOutput
  '0x5ae401dc', // multicall (V3 Router02 batched swaps)
  // 1inch AggregationRouterV5
  '0x12aa3caf', // swap
  '0x0502b1c5', // uniswapV3Swap
]);

// uint256.max — the canonical "unlimited" approval value
export const UINT256_MAX = 2n ** 256n - 1n;
