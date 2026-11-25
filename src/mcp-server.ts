import { createInterface } from "node:readline";
import {
  DEFAULT_BASE_URL,
  SI_GEMINI_EVM_PAYOUT_ADDRESS,
  SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
  SI_GEMINI_WALLET_ALIAS,
  auditSbom,
  auditSolidity,
  checkTokenRisk,
  discover,
  scanRepo,
  type AuditSolidityRequest,
  type CallEndpointOptions,
  type EvmChainName,
  type FetchLike,
  type SbomAuditRequest,
  type SbomFormat,
  type ScanRepoRequest,
  type SupportedNetwork,
  type TokenRiskRequest,
} from "./client.js";

export const MCP_SERVER_NAME = "@boxxji/cerberus-x402-mcp";
export const MCP_SERVER_VERSION = "1.1.0";
export const DEFAULT_MCP_PROTOCOL_VERSION = "2024-11-05";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcSuccessResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpServerOptions {
  baseUrl?: string;
  payerPrivateKey?: string;
  preferredNetwork?: SupportedNetwork;
  fetch?: FetchLike;
}

const NETWORK_PROP_SCHEMA = {
  type: "string",
  enum: ["base", "arbitrum"],
  description:
    "Optional USDC settlement network for x402 EIP-3009 payment (defaults to X402_NETWORK or 'base').",
};

export const MCP_TOOLS: readonly McpToolDefinition[] = [
  {
    name: "cerberus_list_endpoints",
    description:
      "FREE discovery tool. Fetches live /health and /.well-known/x402.json from the Cerberus x402 edge worker, listing all paid security endpoints, USDC pricing, supported networks (Base 8453 & Arbitrum 42161), and Wallet 1 :: SI_Gemini payout addresses.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "cerberus_scan_repo",
    description:
      "Paid ($0.05 USDC via x402 EIP-3009). 7-layer Cerberus anti-honeypot, prompt-injection, suspicious binary (encryptly), postinstall shell-hook, obfuscation, drainer, and DLP secret scan for GitHub repositories, files, or issue text. Returns a structured HTTP 402 payment quote if X402_PAYER_PRIVATE_KEY is not configured.",
    inputSchema: {
      type: "object",
      properties: {
        repoUrl: {
          type: "string",
          description: "Public GitHub repository URL or owner/repo slug.",
        },
        files: {
          description: "Map of path -> content or array of { path, content } objects.",
          oneOf: [
            { type: "object", additionalProperties: { type: "string" } },
            {
              type: "array",
              items: {
                type: "object",
                required: ["path", "content"],
                properties: {
                  path: { type: "string" },
                  content: { type: "string" },
                },
              },
            },
          ],
        },
        issueText: {
          type: "string",
          description: "Optional GitHub issue, PR, or bounty description text to inspect.",
        },
        network: NETWORK_PROP_SCHEMA,
      },
      additionalProperties: false,
    },
  },
  {
    name: "cerberus_token_risk",
    description:
      "Paid ($0.03 USDC via x402 EIP-3009). Read-only on-chain EVM smart contract risk analyzer using eth_getCode, EIP-1967 proxy slot inspection, opcode disassembly (SELFDESTRUCT/DELEGATECALL), and 4-byte selector detection (mint/blacklist/pause/setFee).",
    inputSchema: {
      type: "object",
      required: ["chain", "address"],
      properties: {
        chain: {
          type: "string",
          enum: ["arbitrum", "base", "ethereum", "optimism", "polygon"],
          description: "Target EVM chain to query read-only bytecode from.",
        },
        address: {
          type: "string",
          pattern: "^0x[0-9a-fA-F]{40}$",
          description: "0x-prefixed 40-hex-character EVM contract address.",
        },
        network: NETWORK_PROP_SCHEMA,
      },
      additionalProperties: false,
    },
  },
  {
    name: "cerberus_sbom_audit",
    description:
      "Paid ($0.10 USDC via x402 EIP-3009). Dependency manifest security auditor & CycloneDX 1.5 JSON SBOM generator supporting package.json, requirements.txt, and Cargo.toml (typosquatting, wildcard/unpinned versions, lifecycle hooks, license risk).",
    inputSchema: {
      type: "object",
      required: ["format", "content"],
      properties: {
        format: {
          type: "string",
          enum: ["package.json", "requirements.txt", "Cargo.toml"],
          description: "Dependency manifest format.",
        },
        content: {
          type: "string",
          description: "Raw dependency manifest file content.",
        },
        projectName: {
          type: "string",
          description: "Optional project name metadata for CycloneDX SBOM.",
        },
        projectVersion: {
          type: "string",
          description: "Optional project version metadata for CycloneDX SBOM.",
        },
        network: NETWORK_PROP_SCHEMA,
      },
      additionalProperties: false,
    },
  },
  {
    name: "cerberus_audit_solidity",
    description:
      "Paid ($0.15 USDC via x402 EIP-3009). 10-detector Solidity static & invariant contest auditor (ERC-4626 inflation, Chainlink/L2 sequencer staleness, unchecked ERC-20 return, reentrancy CEI, signature replay, tx.origin, delegatecall, div-before-mul, unprotected initializer/selfdestruct, fee-on-transfer) with CWE/SWC tags and Foundry Test.sol scaffolds.",
    inputSchema: {
      type: "object",
      properties: {
        filename: {
          type: "string",
          description: "Optional Solidity filename when supplying single 'source'.",
        },
        source: {
          type: "string",
          description: "Single Solidity contract source code string.",
        },
        files: {
          description: "Map of path -> Solidity source or array of { path, content }.",
          oneOf: [
            { type: "object", additionalProperties: { type: "string" } },
            {
              type: "array",
              items: {
                type: "object",
                required: ["path", "content"],
                properties: {
                  path: { type: "string" },
                  content: { type: "string" },
                },
              },
            },
          ],
        },
        network: NETWORK_PROP_SCHEMA,
      },
      additionalProperties: false,
    },
  },
];

function extractPreferredNetwork(
  args: Record<string, unknown>,
  fallback?: SupportedNetwork,
): SupportedNetwork {
  if (args.network === "base" || args.network === "arbitrum") {
    return args.network;
  }
  if (fallback) {
    return fallback;
  }
  return process.env.X402_NETWORK === "arbitrum" ? "arbitrum" : "base";
}

function makeToolResult(payload: unknown, isError = false) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2),
      },
    ],
    ...(isError ? { isError: true } : {}),
  };
}

export interface CerberusMcpServer {
  handleMessage(message: unknown): Promise<JsonRpcResponse | null>;
  startStdio(input?: NodeJS.ReadableStream, output?: NodeJS.WritableStream): void;
}

export function createMcpServer(options: McpServerOptions = {}): CerberusMcpServer {
  const baseUrl = options.baseUrl ?? process.env.CERBERUS_X402_BASE_URL ?? DEFAULT_BASE_URL;

  function buildCallOptions(args: Record<string, unknown>): CallEndpointOptions {
    return {
      baseUrl,
      payerPrivateKey: options.payerPrivateKey,
      preferredNetwork: extractPreferredNetwork(args, options.preferredNetwork),
      fetch: options.fetch,
    };
  }

  async function executeTool(name: string, args: Record<string, unknown>) {
    switch (name) {
      case "cerberus_list_endpoints": {
        const discovery = await discover({ baseUrl, fetch: options.fetch });
        return makeToolResult({
          baseUrl: discovery.baseUrl,
          status: discovery.health.status,
          service: discovery.health.service,
          version: discovery.health.version,
          wallet: {
            alias: SI_GEMINI_WALLET_ALIAS,
            evmPayoutAddress: SI_GEMINI_EVM_PAYOUT_ADDRESS,
            solanaPayoutAddress: SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
          },
          x402Version: discovery.manifest.x402Version,
          acceptedNetworks: discovery.health.x402.acceptedNetworks,
          endpoints: discovery.manifest.endpoints.map((ep) => ({
            id: ep.id,
            method: ep.method,
            path: ep.path,
            resource: ep.resource,
            description: ep.description,
            pricing: ep.pricing,
          })),
        });
      }

      case "cerberus_scan_repo": {
        const payload: ScanRepoRequest = {};
        if (typeof args.repoUrl === "string") payload.repoUrl = args.repoUrl;
        if (args.files !== undefined) payload.files = args.files as ScanRepoRequest["files"];
        if (typeof args.issueText === "string") payload.issueText = args.issueText;
        if (!payload.repoUrl && !payload.files && !payload.issueText) {
          return makeToolResult(
            {
              error: "INVALID_ARGUMENTS",
              message: "Provide at least one of repoUrl, files, or issueText.",
            },
            true,
          );
        }
        const res = await scanRepo(payload, buildCallOptions(args));
        return makeToolResult(res);
      }

      case "cerberus_token_risk": {
        if (typeof args.chain !== "string" || typeof args.address !== "string") {
          return makeToolResult(
            {
              error: "INVALID_ARGUMENTS",
              message: "Both 'chain' and 'address' are required.",
            },
            true,
          );
        }
        const payload: TokenRiskRequest = {
          chain: args.chain as EvmChainName,
          address: args.address,
        };
        const res = await checkTokenRisk(payload, buildCallOptions(args));
        return makeToolResult(res);
      }

      case "cerberus_sbom_audit": {
        if (typeof args.format !== "string" || typeof args.content !== "string") {
          return makeToolResult(
            {
              error: "INVALID_ARGUMENTS",
              message: "Both 'format' and 'content' are required.",
            },
            true,
          );
        }
        const payload: SbomAuditRequest = {
          format: args.format as SbomFormat,
          content: args.content,
          ...(typeof args.projectName === "string" ? { projectName: args.projectName } : {}),
          ...(typeof args.projectVersion === "string"
            ? { projectVersion: args.projectVersion }
            : {}),
        };
        const res = await auditSbom(payload, buildCallOptions(args));
        return makeToolResult(res);
      }

      case "cerberus_audit_solidity": {
        const payload: AuditSolidityRequest = {};
        if (typeof args.filename === "string") payload.filename = args.filename;
        if (typeof args.source === "string") payload.source = args.source;
        if (args.files !== undefined) payload.files = args.files as AuditSolidityRequest["files"];
        if (!payload.source && !payload.files) {
          return makeToolResult(
            {
              error: "INVALID_ARGUMENTS",
              message: "Provide either 'source' or 'files' containing Solidity code.",
            },
            true,
          );
        }
        const res = await auditSolidity(payload, buildCallOptions(args));
        return makeToolResult(res);
      }

      default:
        return null;
    }
  }

  async function handleMessage(raw: unknown): Promise<JsonRpcResponse | null> {
    if (!raw || typeof raw !== "object") {
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid Request" },
      };
    }

    const msg = raw as Partial<JsonRpcRequest>;
    const hasId = msg.id !== undefined;
    const id = msg.id ?? null;

    if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32600, message: "Invalid JSON-RPC 2.0 request" },
      };
    }

    // Notifications (no id) must not receive a JSON-RPC response per spec
    if (!hasId) {
      return null;
    }

    switch (msg.method) {
      case "initialize": {
        const clientVersion =
          typeof msg.params?.protocolVersion === "string"
            ? msg.params.protocolVersion
            : DEFAULT_MCP_PROTOCOL_VERSION;
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: clientVersion,
            capabilities: {
              tools: {},
            },
            serverInfo: {
              name: MCP_SERVER_NAME,
              version: MCP_SERVER_VERSION,
            },
          },
        };
      }

      case "ping": {
        return {
          jsonrpc: "2.0",
          id,
          result: {},
        };
      }

      case "tools/list": {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            tools: MCP_TOOLS,
          },
        };
      }

      case "tools/call": {
        const params = (msg.params ?? {}) as {
          name?: unknown;
          arguments?: unknown;
        };
        if (typeof params.name !== "string") {
          return {
            jsonrpc: "2.0",
            id,
            error: { code: -32602, message: "Missing tool name in tools/call params" },
          };
        }
        const args =
          params.arguments && typeof params.arguments === "object"
            ? (params.arguments as Record<string, unknown>)
            : {};

        try {
          const toolResult = await executeTool(params.name, args);
          if (!toolResult) {
            return {
              jsonrpc: "2.0",
              id,
              error: { code: -32602, message: `Unknown tool: ${params.name}` },
            };
          }
          return {
            jsonrpc: "2.0",
            id,
            result: toolResult,
          };
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          return {
            jsonrpc: "2.0",
            id,
            result: makeToolResult({ error: "TOOL_EXECUTION_ERROR", message }, true),
          };
        }
      }

      default:
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Method not found: ${msg.method}` },
        };
    }
  }

  function startStdio(
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stdout,
  ): void {
    const rl = createInterface({
      input,
      crlfDelay: Infinity,
    });

    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        const parseErr: JsonRpcErrorResponse = {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        };
        output.write(`${JSON.stringify(parseErr)}\n`);
        return;
      }

      void handleMessage(parsed).then((response) => {
        if (response !== null) {
          output.write(`${JSON.stringify(response)}\n`);
        }
      });
    });
  }

  return {
    handleMessage,
    startStdio,
  };
}
