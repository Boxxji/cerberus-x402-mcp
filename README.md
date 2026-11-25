# Cerberus x402 MCP Server & SDK

[![CI](https://github.com/Boxxji/cerberus-x402-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Boxxji/cerberus-x402-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-8A2BE2)](https://modelcontextprotocol.io)
[![x402 Protocol](https://img.shields.io/badge/x402-EIP--3009%20USDC-0052FF)](https://x402-cerberus-worker.boxxon.workers.dev/.well-known/x402.json)

Zero-bloat **Model Context Protocol (MCP) JSON-RPC 2.0 stdio server** and **TypeScript x402 client SDK** for the live Cerberus Web3 & AI supply-chain security edge API at:

> **Live Edge API:** `https://x402-cerberus-worker.boxxon.workers.dev`  
> **Discovery Manifest:** `https://x402-cerberus-worker.boxxon.workers.dev/.well-known/x402.json`  
> **Health Check:** `https://x402-cerberus-worker.boxxon.workers.dev/health`

No API keys, no accounts, no monthly subscriptions — AI agents and developers pay per request in **Base (`8453`)** or **Arbitrum (`42161`) USDC** using **HTTP 402 + EIP-3009 `TransferWithAuthorization`**, signed locally via `viem`.

---

## Pricing & Endpoints

| MCP Tool | HTTP Endpoint | Price (USDC) | Description |
| :--- | :--- | :---: | :--- |
| `cerberus_list_endpoints` | `GET /health` & `/.well-known/x402.json` | **FREE** | Live health, schema, pricing, and payout discovery |
| `cerberus_token_risk` | `POST /v1/onchain/token-risk` | **$0.03** | Read-only EVM bytecode, EIP-1967 proxy slot, opcode (`SELFDESTRUCT`/`DELEGATECALL`), and 4-byte selector risk scan |
| `cerberus_scan_repo` | `POST /v1/cerberus/scan-repo` | **$0.05** | 7-layer anti-honeypot, prompt-injection, suspicious binary, `postinstall` hook, obfuscation, drainer, and DLP secret scan |
| `cerberus_sbom_audit` | `POST /v1/sbom/audit` | **$0.10** | CycloneDX 1.5 JSON SBOM generator + typosquatting, unpinned versions, lifecycle hooks, and license risk audit (`package.json`, `requirements.txt`, `Cargo.toml`) |
| `cerberus_audit_solidity` | `POST /v1/cerberus/audit-solidity` | **$0.15** | 10-detector Solidity contest auditor (ERC-4626 inflation, oracle staleness, unchecked ERC-20, reentrancy, signature replay, `tx.origin`, `delegatecall`, precision loss, unprotected init/selfdestruct, fee-on-transfer) + Foundry `Test.sol` scaffold |

---

## Quick Start: Claude Desktop / Cursor / Windsurf / Antigravity

Add `@boxxji/cerberus-x402-mcp` to your MCP client configuration:

```json
{
  "mcpServers": {
    "cerberus-x402": {
      "command": "npx",
      "args": ["-y", "@boxxji/cerberus-x402-mcp"],
      "env": {
        "X402_NETWORK": "base",
        "X402_PAYER_PRIVATE_KEY": "0xYOUR_LOCAL_PAYER_PRIVATE_KEY_OPTIONAL"
      }
    }
  }
}
```

- **Read-only / Quote Mode (no key required):** Omit `X402_PAYER_PRIVATE_KEY` to run `cerberus_list_endpoints` for free and inspect structured HTTP 402 payment quotes on paid tools without spending funds.
- **Autonomous x402 Settlement Mode:** Supply your own funded Base or Arbitrum USDC wallet private key via `X402_PAYER_PRIVATE_KEY` locally on your machine. Private keys are **never transmitted, logged, or hardcoded** — they only sign EIP-3009 typed data locally via `viem/accounts`.

### CLI Usage

```bash
# Discover live endpoints and pricing (free)
npx -y @boxxji/cerberus-x402-mcp --discover

# Run as an MCP JSON-RPC 2.0 stdio server
npx -y @boxxji/cerberus-x402-mcp
```

---

## How the x402 EIP-3009 USDC Flow Works

```text
Agent / SDK                            Cerberus Edge Worker (Cloudflare)
    │                                                │
    ├── POST /v1/cerberus/scan-repo ────────────────►│
    │                                                │
    │◄── HTTP 402 Payment Required ──────────────────┤
    │    (accepts: Base 8453 & Arbitrum 42161 USDC,  │
    │     payTo: 0x51E2...C5A1, amount: 50000)       │
    │                                                │
    ├─ 1. Verify payTo === Wallet 1 :: SI_Gemini     │
    ├─ 2. Verify canonical Base/Arbitrum USDC asset  │
    ├─ 3. Sign EIP-3009 TransferWithAuthorization    │
    │     locally via viem (gasless for payer)       │
    │                                                │
    ├── POST /v1/cerberus/scan-repo ────────────────►│
    │    Header: X-PAYMENT: <base64 x402 payload>    │
    │                                                │
    │◄── HTTP 200 OK + Security Audit JSON ──────────┤
```

---

## TypeScript SDK Examples

```bash
npm install @boxxji/cerberus-x402-mcp
```

```ts
import {
  CerberusX402Client,
  discover,
  auditSolidity,
  checkTokenRisk,
  scanRepo,
  auditSbom,
} from "@boxxji/cerberus-x402-mcp";

// 1. Free discovery
const info = await discover();
console.log(info.health.status, info.manifest.endpoints.map((e) => e.path));

// 2. Call with automatic HTTP 402 -> EIP-3009 USDC signing -> retry
const client = new CerberusX402Client({
  preferredNetwork: "base", // or "arbitrum"
  payerPrivateKey: process.env.X402_PAYER_PRIVATE_KEY, // optional; returns 402 quote if omitted
});

const repoReport = await client.scanRepo({
  repoUrl: "Boxxji/cerberus-x402-mcp",
});

const tokenReport = await client.checkTokenRisk({
  chain: "base",
  address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
});

const sbomReport = await client.auditSbom({
  format: "package.json",
  content: JSON.stringify({ name: "demo", dependencies: { viem: "^2.23.0" } }),
});

const solidityReport = await client.auditSolidity({
  filename: "Vault.sol",
  source: "pragma solidity ^0.8.24; contract Vault { }",
});

console.log({ repoReport, tokenReport, sbomReport, solidityReport });
```

### `curl` Examples

```bash
# Free health & x402 discovery
curl -sS https://x402-cerberus-worker.boxxon.workers.dev/health | jq .
curl -sS https://x402-cerberus-worker.boxxon.workers.dev/.well-known/x402.json | jq '.endpoints[] | {id, path, pricing}'

# Inspect HTTP 402 payment challenge for a paid endpoint
curl -i -sS -X POST https://x402-cerberus-worker.boxxon.workers.dev/v1/onchain/token-risk \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}'
```

---

## Security & Payout Pinning (`Wallet 1 :: SI_Gemini`)

Before signing any EIP-3009 authorization, `signEip3009Payment()` strictly verifies:

1. **Pinned Payout Address:** `challenge.payTo` MUST match `Wallet 1 :: SI_Gemini` (`0x51E24000948150400166b40d486dB7b3C5b2C5A1`) — preventing MITM or redirected payment challenges.
2. **Canonical USDC Contracts Only:**
   - **Base (`8453`):** `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
   - **Arbitrum (`42161`):** `0xaf88d065e77c8cC2239327C5EDb3A432268e5831`
3. **Local-Only Keys:** Private keys are supplied exclusively by the caller via `X402_PAYER_PRIVATE_KEY` or runtime option and never leave the caller's process.

### Verified Public Receiving Addresses (`Wallet 1 :: SI_Gemini`)

- **EVM (Base `8453` & Arbitrum `42161` USDC):** `0x51E24000948150400166b40d486dB7b3C5b2C5A1` ([Basescan](https://basescan.org/address/0x51E24000948150400166b40d486dB7b3C5b2C5A1) | [Arbiscan](https://arbiscan.io/address/0x51E24000948150400166b40d486dB7b3C5b2C5A1))
- **Solana:** `H8ckc19KdGFoCAXh1cGjQL4bGP75DdAvnRQMBpGypRQx` ([Solscan](https://solscan.io/account/H8ckc19KdGFoCAXh1cGjQL4bGP75DdAvnRQMBpGypRQx))

---

## Development

```bash
npm install
npm run typecheck
npm run build
npm test
npm pack --dry-run
```

## License

[MIT](LICENSE)
