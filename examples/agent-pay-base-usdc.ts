// Pay $0.05 USDC on Base (8453) via PayAI x402 EIP-3009 settlement to run a 7-layer Cerberus repo scan.
// Usage: X402_PAYER_PRIVATE_KEY=0x... npx tsx examples/agent-pay-base-usdc.ts
import { scanRepo } from "@boxxji/cerberus-x402-mcp";

const report = await scanRepo({ repoUrl: "Boxxji/cerberus-x402-mcp" }, { preferredNetwork: "base", payerPrivateKey: process.env.X402_PAYER_PRIVATE_KEY });
console.log(JSON.stringify(report, null, 2));
