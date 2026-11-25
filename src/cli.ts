#!/usr/bin/env node
import {
  DEFAULT_BASE_URL,
  SI_GEMINI_EVM_PAYOUT_ADDRESS,
  SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
  SI_GEMINI_WALLET_ALIAS,
  discover,
  type SupportedNetwork,
} from "./client.js";
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, createMcpServer } from "./mcp-server.js";

function printHelp(): void {
  process.stderr.write(
    [
      `${MCP_SERVER_NAME} v${MCP_SERVER_VERSION}`,
      "",
      "Model Context Protocol (MCP) JSON-RPC 2.0 stdio server & x402 USDC client",
      `for the live Cerberus Web3 & AI supply-chain security edge API (${DEFAULT_BASE_URL}).`,
      "",
      "Usage:",
      "  cerberus-x402-mcp              Start MCP JSON-RPC 2.0 server on stdio",
      "  cerberus-x402-mcp --discover   Query live /health and /.well-known/x402.json",
      "  cerberus-x402-mcp --version    Print package version",
      "  cerberus-x402-mcp --help       Show this help text",
      "",
      "Environment Variables:",
      `  CERBERUS_X402_BASE_URL   API base URL (default: ${DEFAULT_BASE_URL})`,
      "  X402_NETWORK             Preferred USDC network: 'base' (8453) or 'arbitrum' (42161)",
      "  X402_PAYER_PRIVATE_KEY   Optional caller-supplied EVM private key for local EIP-3009",
      "                           USDC signing. If omitted, paid tools return HTTP 402 quotes.",
      "",
      `Payout Wallet (${SI_GEMINI_WALLET_ALIAS}):`,
      `  EVM (Base / Arbitrum USDC): ${SI_GEMINI_EVM_PAYOUT_ADDRESS}`,
      `  Solana:                     ${SI_GEMINI_SOLANA_PAYOUT_ADDRESS}`,
      "",
    ].join("\n"),
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }

  if (args.includes("--version") || args.includes("-v")) {
    process.stdout.write(`${MCP_SERVER_VERSION}\n`);
    return;
  }

  const baseUrl = process.env.CERBERUS_X402_BASE_URL ?? DEFAULT_BASE_URL;

  if (args.includes("--discover")) {
    const result = await discover({ baseUrl });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  const preferredNetwork: SupportedNetwork =
    process.env.X402_NETWORK === "arbitrum" ? "arbitrum" : "base";

  const server = createMcpServer({
    baseUrl,
    preferredNetwork,
    payerPrivateKey: process.env.X402_PAYER_PRIVATE_KEY,
  });

  server.startStdio(process.stdin, process.stdout);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`[${MCP_SERVER_NAME}] Fatal error: ${message}\n`);
  process.exitCode = 1;
});
