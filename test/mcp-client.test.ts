import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { getAddress, verifyTypedData } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  CERBERUS_ENDPOINTS,
  DEFAULT_BASE_URL,
  EIP3009_TRANSFER_TYPES,
  SI_GEMINI_EVM_PAYOUT_ADDRESS,
  SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
  SUPPORTED_NETWORKS,
  auditSbom,
  auditSolidity,
  callEndpoint,
  checkTokenRisk,
  discover,
  getQuote,
  resolveEndpointPath,
  scanRepo,
  signEip3009Payment,
  verifyLive,
  type FetchLike,
  type X402Challenge,
  type X402PaymentPayload,
} from "../src/client.js";
import {
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
  MCP_TOOLS,
  createMcpServer,
  type JsonRpcResponse,
} from "../src/mcp-server.js";

function makeMockChallenge(
  path: string,
  amountMicroUsdc: string,
  payTo: string = getAddress(SI_GEMINI_EVM_PAYOUT_ADDRESS),
): X402Challenge {
  return {
    x402Version: 1,
    error: "Payment Required",
    accepts: [
      {
        scheme: "exact",
        network: "base",
        chainId: 8453,
        caip2: "eip155:8453",
        maxAmountRequired: amountMicroUsdc,
        resource: `${DEFAULT_BASE_URL}${path}`,
        description: `Mock challenge for ${path}`,
        mimeType: "application/json",
        payTo,
        maxTimeoutSeconds: 300,
        asset: SUPPORTED_NETWORKS.base.usdcContract,
        extra: {
          name: "USD Coin",
          version: "2",
          eip3009: true,
          walletAlias: "Wallet 1 :: SI_Gemini",
        },
      },
      {
        scheme: "exact",
        network: "arbitrum",
        chainId: 42161,
        caip2: "eip155:42161",
        maxAmountRequired: amountMicroUsdc,
        resource: `${DEFAULT_BASE_URL}${path}`,
        description: `Mock challenge for ${path}`,
        mimeType: "application/json",
        payTo,
        maxTimeoutSeconds: 300,
        asset: SUPPORTED_NETWORKS.arbitrum.usdcContract,
        extra: {
          name: "USD Coin",
          version: "2",
          eip3009: true,
          walletAlias: "Wallet 1 :: SI_Gemini",
        },
      },
    ],
  };
}

describe("x402 EIP-3009 Client Signing & 402 Retry Flow", () => {
  it("signs a cryptographically verifiable EIP-3009 TransferWithAuthorization on Base & Arbitrum", async () => {
    const ephemeralKey = generatePrivateKey();
    const expectedSigner = privateKeyToAccount(ephemeralKey).address;
    const challenge = makeMockChallenge(CERBERUS_ENDPOINTS.scanRepo, "50000");

    for (const network of ["base", "arbitrum"] as const) {
      const signed = await signEip3009Payment(ephemeralKey, challenge, network, {
        nowSeconds: 1_750_000_000,
      });

      assert.equal(signed.headerName, "X-PAYMENT");
      assert.equal(signed.network, network);
      assert.equal(signed.chainId, SUPPORTED_NETWORKS[network].chainId);
      assert.equal(signed.amountMicroUsdc, "50000");
      assert.equal(signed.amountUsd, "0.05");
      assert.equal(signed.payer.toLowerCase(), expectedSigner.toLowerCase());
      assert.equal(signed.payTo.toLowerCase(), SI_GEMINI_EVM_PAYOUT_ADDRESS.toLowerCase());

      const decoded = JSON.parse(
        Buffer.from(signed.headerValue, "base64").toString("utf8"),
      ) as X402PaymentPayload;

      assert.equal(decoded.x402Version, 1);
      assert.equal(decoded.scheme, "exact");
      assert.equal(decoded.network, network);
      assert.equal(decoded.payload.authorization.value, "50000");
      assert.equal(
        decoded.payload.authorization.to.toLowerCase(),
        SI_GEMINI_EVM_PAYOUT_ADDRESS.toLowerCase(),
      );

      const isValidSig = await verifyTypedData({
        address: expectedSigner,
        domain: {
          name: "USD Coin",
          version: "2",
          chainId: SUPPORTED_NETWORKS[network].chainId,
          verifyingContract: SUPPORTED_NETWORKS[network].usdcContract,
        },
        types: EIP3009_TRANSFER_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from: decoded.payload.authorization.from,
          to: decoded.payload.authorization.to,
          value: BigInt(decoded.payload.authorization.value),
          validAfter: BigInt(decoded.payload.authorization.validAfter),
          validBefore: BigInt(decoded.payload.authorization.validBefore),
          nonce: decoded.payload.authorization.nonce,
        },
        signature: decoded.payload.signature,
      });

      assert.equal(isValidSig, true, `EIP-3009 signature must verify on ${network}`);
    }
  });

  it("strictly refuses to sign if payTo does not match Wallet 1 :: SI_Gemini", async () => {
    const ephemeralKey = generatePrivateKey();
    const tamperedChallenge = makeMockChallenge(
      CERBERUS_ENDPOINTS.scanRepo,
      "50000",
      "0x000000000000000000000000000000000000dEaD",
    );

    await assert.rejects(
      () => signEip3009Payment(ephemeralKey, tamperedChallenge, "base"),
      /does not match expected Wallet 1 :: SI_Gemini address/,
    );
  });

  it("returns a structured 402 payment quote when no payer private key is supplied", async () => {
    const prevKey = process.env.X402_PAYER_PRIVATE_KEY;
    delete process.env.X402_PAYER_PRIVATE_KEY;
    try {
      const challenge = makeMockChallenge(CERBERUS_ENDPOINTS.tokenRisk, "30000");
      const mockFetch: FetchLike = async () =>
        new Response(JSON.stringify(challenge), {
          status: 402,
          headers: { "content-type": "application/json" },
        });

      const res = await checkTokenRisk(
        { chain: "base", address: SUPPORTED_NETWORKS.base.usdcContract },
        { fetch: mockFetch },
      );

      assert.equal(res.ok, false);
      assert.equal(res.status, 402);
      assert.equal(res.paymentRequired, true);
      assert.equal(res.payTo, SI_GEMINI_EVM_PAYOUT_ADDRESS);
      assert.equal(res.solanaPayoutAddress, SI_GEMINI_SOLANA_PAYOUT_ADDRESS);
      assert.equal(res.challenge.accepts.length, 2);
      assert.match(res.instructions, /\$0\.03 USDC/);
    } finally {
      if (prevKey !== undefined) {
        process.env.X402_PAYER_PRIVATE_KEY = prevKey;
      }
    }
  });

  it("automatically handles HTTP 402 -> EIP-3009 sign -> retry with X-PAYMENT -> HTTP 200", async () => {
    const ephemeralKey = generatePrivateKey();
    const expectedPayer = privateKeyToAccount(ephemeralKey).address;
    const challenge = makeMockChallenge(CERBERUS_ENDPOINTS.auditSolidity, "150000");
    let callCount = 0;
    let capturedPaymentHeader: string | null = null;

    const mockFetch: FetchLike = async (input, init) => {
      callCount += 1;
      const url = typeof input === "string" ? input : input.toString();
      assert.equal(url, `${DEFAULT_BASE_URL}${CERBERUS_ENDPOINTS.auditSolidity}`);

      const headers = new Headers(init?.headers);
      const xPayment = headers.get("x-payment");

      if (!xPayment) {
        return new Response(JSON.stringify(challenge), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "x-payment-required": Buffer.from(JSON.stringify(challenge), "utf8").toString("base64"),
          },
        });
      }

      capturedPaymentHeader = xPayment;
      const receipt = { settled: true, network: "arbitrum", txHash: "0xmock" };
      return new Response(
        JSON.stringify({
          scanner: "cerberus-solidity",
          filesScanned: 1,
          linesScanned: 12,
          verdict: "PASS",
          riskScore: 0,
          severityCounts: {},
          findingsCount: 0,
          findings: [],
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "x-payment-response": Buffer.from(JSON.stringify(receipt), "utf8").toString("base64"),
          },
        },
      );
    };

    const result = await auditSolidity(
      { filename: "Safe.sol", source: "pragma solidity ^0.8.24; contract Safe {}" },
      {
        payerPrivateKey: ephemeralKey,
        preferredNetwork: "arbitrum",
        fetch: mockFetch,
      },
    );

    assert.equal(callCount, 2);
    assert.ok(capturedPaymentHeader, "Expected X-PAYMENT header on retry");
    assert.equal(result.ok, true);
    assert.equal(result.paid, true);
    assert.equal(result.status, 200);
    assert.equal(result.payment?.network, "arbitrum");
    assert.equal(result.payment?.chainId, 42161);
    assert.equal(result.payment?.amountMicroUsdc, "150000");
    assert.equal(result.payment?.payer.toLowerCase(), expectedPayer.toLowerCase());
    assert.equal(result.data.verdict, "PASS");
    assert.deepEqual(result.paymentResponse, {
      settled: true,
      network: "arbitrum",
      txHash: "0xmock",
    });
  });

  it("routes typed helpers scanRepo and auditSbom to the exact worker paths", async () => {
    const visitedPaths: string[] = [];
    const mockFetch: FetchLike = async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      visitedPaths.push(url.pathname);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    await scanRepo({ repoUrl: "Boxxji/cerberus-x402-mcp" }, { fetch: mockFetch });
    await auditSbom(
      { format: "package.json", content: '{"name":"demo"}' },
      { fetch: mockFetch },
    );
    await callEndpoint("/v1/onchain/token-risk", { chain: "base", address: "0x0" }, { fetch: mockFetch });

    assert.deepEqual(visitedPaths, [
      "/v1/cerberus/scan-repo",
      "/v1/sbom/audit",
      "/v1/onchain/token-risk",
    ]);
  });
});

describe("MCP JSON-RPC 2.0 Stdio Server", () => {
  it("handles initialize, ping, notifications/initialized, and tools/list (5 tools)", async () => {
    const server = createMcpServer();

    const initRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    });
    assert.ok(initRes && "result" in initRes);
    const initResult = initRes.result as {
      protocolVersion: string;
      serverInfo: { name: string; version: string };
      capabilities: { tools: Record<string, unknown> };
    };
    assert.equal(initResult.protocolVersion, "2024-11-05");
    assert.equal(initResult.serverInfo.name, MCP_SERVER_NAME);
    assert.equal(initResult.serverInfo.version, MCP_SERVER_VERSION);
    assert.ok(initResult.capabilities.tools);

    const notifRes = await server.handleMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    assert.equal(notifRes, null);

    const pingRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "ping",
    });
    assert.deepEqual(pingRes, { jsonrpc: "2.0", id: 2, result: {} });

    const listRes = await server.handleMessage({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
    });
    assert.ok(listRes && "result" in listRes);
    const tools = (listRes.result as { tools: typeof MCP_TOOLS }).tools;
    assert.equal(tools.length, 5);
    assert.deepEqual(
      tools.map((t) => t.name),
      [
        "cerberus_list_endpoints",
        "cerberus_scan_repo",
        "cerberus_token_risk",
        "cerberus_sbom_audit",
        "cerberus_audit_solidity",
      ],
    );
  });

  it("handles tools/call for cerberus_list_endpoints and 402 quotes over stdio transport", async () => {
    const prevKey = process.env.X402_PAYER_PRIVATE_KEY;
    delete process.env.X402_PAYER_PRIVATE_KEY;

    try {
      const mockFetch: FetchLike = async (input) => {
        const url = typeof input === "string" ? input : input.toString();
        if (url.endsWith("/health")) {
          return new Response(
            JSON.stringify({
              status: "ok",
              service: "x402-cerberus-worker",
              version: "1.0.0",
              timestamp: new Date().toISOString(),
              wallet: {
                alias: "Wallet 1 :: SI_Gemini",
                evmPayoutAddress: SI_GEMINI_EVM_PAYOUT_ADDRESS,
                solanaPayoutAddress: SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
              },
              x402: {
                version: 1,
                acceptedNetworks: [
                  {
                    network: "base",
                    chainId: 8453,
                    usdcContract: SUPPORTED_NETWORKS.base.usdcContract,
                  },
                  {
                    network: "arbitrum",
                    chainId: 42161,
                    usdcContract: SUPPORTED_NETWORKS.arbitrum.usdcContract,
                  },
                ],
                discoveryManifest: `${DEFAULT_BASE_URL}/.well-known/x402.json`,
              },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (url.endsWith("/.well-known/x402.json")) {
          return new Response(
            JSON.stringify({
              x402Version: 1,
              name: "SI_Gemini Cerberus x402 Security API",
              version: "1.0.0",
              description: "Mock manifest",
              wallet: {
                alias: "Wallet 1 :: SI_Gemini",
                evmPayoutAddress: SI_GEMINI_EVM_PAYOUT_ADDRESS,
                solanaPayoutAddress: SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
              },
              paymentMethods: [],
              endpoints: [
                {
                  id: "cerberus-scan-repo",
                  method: "POST",
                  path: "/v1/cerberus/scan-repo",
                  resource: `${DEFAULT_BASE_URL}/v1/cerberus/scan-repo`,
                  description: "7-layer scan",
                  pricing: { currency: "USDC", amountUsd: "0.05", amountMicroUsdc: "50000" },
                  accepts: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(
          JSON.stringify(makeMockChallenge(CERBERUS_ENDPOINTS.scanRepo, "50000")),
          { status: 402, headers: { "content-type": "application/json" } },
        );
      };

      const server = createMcpServer({ fetch: mockFetch });
      const input = new PassThrough();
      const output = new PassThrough();
      server.startStdio(input, output);

      const responses: JsonRpcResponse[] = [];
      output.setEncoding("utf8");
      const receivedAll = new Promise<void>((resolve) => {
        let buffer = "";
        output.on("data", (chunk: string) => {
          buffer += chunk;
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            if (line.trim()) {
              responses.push(JSON.parse(line) as JsonRpcResponse);
            }
          }
          if (responses.length >= 2) {
            resolve();
          }
        });
      });

      input.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 10,
          method: "tools/call",
          params: { name: "cerberus_list_endpoints", arguments: {} },
        })}\n`,
      );
      input.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 11,
          method: "tools/call",
          params: {
            name: "cerberus_scan_repo",
            arguments: { repoUrl: "Boxxji/cerberus-x402-mcp" },
          },
        })}\n`,
      );
      input.end();

      await receivedAll;

      const listCall = responses.find((r) => r.id === 10);
      assert.ok(listCall && "result" in listCall);
      const listContent = (listCall.result as { content: Array<{ text: string }> }).content[0];
      assert.ok(listContent);
      const listParsed = JSON.parse(listContent.text) as {
        status: string;
        wallet: { evmPayoutAddress: string };
        endpoints: Array<{ id: string }>;
      };
      assert.equal(listParsed.status, "ok");
      assert.equal(listParsed.wallet.evmPayoutAddress, SI_GEMINI_EVM_PAYOUT_ADDRESS);
      assert.equal(listParsed.endpoints[0]?.id, "cerberus-scan-repo");

      const scanCall = responses.find((r) => r.id === 11);
      assert.ok(scanCall && "result" in scanCall);
      const scanContent = (scanCall.result as { content: Array<{ text: string }> }).content[0];
      assert.ok(scanContent);
      const scanParsed = JSON.parse(scanContent.text) as {
        status: number;
        paymentRequired: boolean;
        payTo: string;
      };
      assert.equal(scanParsed.status, 402);
      assert.equal(scanParsed.paymentRequired, true);
      assert.equal(scanParsed.payTo, SI_GEMINI_EVM_PAYOUT_ADDRESS);
    } finally {
      if (prevKey !== undefined) {
        process.env.X402_PAYER_PRIVATE_KEY = prevKey;
      }
    }
  });
});

describe("CLI Helpers, Quote Resolution, & Distribution Manifests", () => {
  it("resolves short endpoint aliases and full paths for --quote", () => {
    assert.equal(resolveEndpointPath("scan-repo"), CERBERUS_ENDPOINTS.scanRepo);
    assert.equal(resolveEndpointPath("cerberus_scan_repo"), CERBERUS_ENDPOINTS.scanRepo);
    assert.equal(resolveEndpointPath("token-risk"), CERBERUS_ENDPOINTS.tokenRisk);
    assert.equal(resolveEndpointPath("sbom-audit"), CERBERUS_ENDPOINTS.sbomAudit);
    assert.equal(resolveEndpointPath("audit-solidity"), CERBERUS_ENDPOINTS.auditSolidity);
    assert.equal(resolveEndpointPath("/v1/cerberus/scan-repo"), CERBERUS_ENDPOINTS.scanRepo);
    assert.throws(() => resolveEndpointPath("   "), /Endpoint is required/);
  });

  it("returns structured Base & Arbitrum EIP-3009 payment requirements from getQuote()", async () => {
    const mockFetch: FetchLike = async (input) => {
      const url = typeof input === "string" ? input : input.toString();
      assert.equal(url, `${DEFAULT_BASE_URL}${CERBERUS_ENDPOINTS.scanRepo}`);
      return new Response(
        JSON.stringify(makeMockChallenge(CERBERUS_ENDPOINTS.scanRepo, "50000")),
        { status: 402, headers: { "content-type": "application/json" } },
      );
    };

    const quote = await getQuote("scan-repo", { fetch: mockFetch });
    assert.equal(quote.ok, true);
    assert.equal(quote.status, 402);
    assert.equal(quote.path, "/v1/cerberus/scan-repo");
    assert.equal(quote.priceUsd, "0.05");
    assert.equal(quote.amountMicroUsdc, "50000");
    assert.equal(quote.eip3009Requirements.length, 2);
    assert.deepEqual(
      quote.eip3009Requirements.map((r) => r.network).sort(),
      ["arbitrum", "base"],
    );
    for (const req of quote.eip3009Requirements) {
      assert.equal(req.payToVerified, true);
      assert.equal(req.eip712Domain.name, "USD Coin");
      assert.equal(req.eip712Domain.version, "2");
    }
  });

  it("verifies server.json, package.json version alignment, and examples JSON manifests", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      name: string;
      version: string;
    };
    const serverManifest = JSON.parse(
      readFileSync(new URL("../server.json", import.meta.url), "utf8"),
    ) as {
      name: string;
      version: string;
      packages: Array<{ identifier: string; version: string }>;
      _meta: { "io.github.Boxxji/x402": { endpoints: Record<string, string> } };
    };
    const openAiAction = JSON.parse(
      readFileSync(new URL("../examples/openai-action.json", import.meta.url), "utf8"),
    ) as { openapi_url: string };
    const claudeConfig = JSON.parse(
      readFileSync(new URL("../examples/claude-desktop-config.json", import.meta.url), "utf8"),
    ) as { mcpServers: { "cerberus-x402": { command: string; args: string[] } } };

    assert.equal(pkg.version, MCP_SERVER_VERSION);
    assert.equal(serverManifest.version, pkg.version);
    assert.equal(serverManifest.packages[0]?.identifier, pkg.name);
    assert.equal(serverManifest.packages[0]?.version, pkg.version);
    assert.equal(
      serverManifest._meta["io.github.Boxxji/x402"].endpoints.openApi,
      `${DEFAULT_BASE_URL}/openapi.json`,
    );
    assert.equal(
      serverManifest._meta["io.github.Boxxji/x402"].endpoints.llmsTxt,
      `${DEFAULT_BASE_URL}/llms.txt`,
    );
    assert.equal(openAiAction.openapi_url, `${DEFAULT_BASE_URL}/openapi.json`);
    assert.equal(claudeConfig.mcpServers["cerberus-x402"].command, "npx");
    assert.deepEqual(claudeConfig.mcpServers["cerberus-x402"].args, ["-y", pkg.name]);
  });
});

describe("Live Read-Only Smoke Test (x402-cerberus-worker.boxxon.workers.dev)", () => {
  const skipLive = process.env.SKIP_LIVE_SMOKE === "1";

  it(
    "verifies live /health (facilitatorConfigured: true), /, /llms.txt, /openapi.json, /.well-known/x402.json, and all 4 endpoints",
    { skip: skipLive },
    async () => {
      const [discovery, liveVerification] = await Promise.all([
        discover({ baseUrl: DEFAULT_BASE_URL }),
        verifyLive({ baseUrl: DEFAULT_BASE_URL }),
      ]);

      assert.equal(discovery.health.status, "ok");
      assert.equal(discovery.health.service, "x402-cerberus-worker");
      assert.equal(discovery.health.facilitatorConfigured, true);
      assert.equal(
        discovery.health.wallet.evmPayoutAddress.toLowerCase(),
        SI_GEMINI_EVM_PAYOUT_ADDRESS.toLowerCase(),
      );
      assert.equal(
        discovery.health.wallet.solanaPayoutAddress,
        SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
      );

      assert.equal(liveVerification.ok, true, JSON.stringify(liveVerification, null, 2));
      assert.equal(liveVerification.facilitatorConfigured, true);
      assert.equal(liveVerification.walletVerified, true);
      assert.equal(liveVerification.checks.health.ok, true);
      assert.equal(liveVerification.checks.landing.ok, true);
      assert.equal(liveVerification.checks.llmsTxt.ok, true);
      assert.equal(liveVerification.checks.openApi.ok, true);
      assert.equal(liveVerification.checks.x402Manifest.ok, true);

      assert.equal(discovery.manifest.x402Version, 1);
      assert.equal(discovery.manifest.endpoints.length, 4);

      const endpointPaths = discovery.manifest.endpoints.map((e) => e.path).sort();
      assert.deepEqual(endpointPaths, [
        "/v1/cerberus/audit-solidity",
        "/v1/cerberus/scan-repo",
        "/v1/onchain/token-risk",
        "/v1/sbom/audit",
      ]);

      for (const ep of discovery.manifest.endpoints) {
        const networks = ep.accepts.map((a) => a.network).sort();
        assert.deepEqual(networks, ["arbitrum", "base"]);
        for (const accept of ep.accepts) {
          assert.equal(
            accept.payTo.toLowerCase(),
            SI_GEMINI_EVM_PAYOUT_ADDRESS.toLowerCase(),
            `Unexpected payTo on ${ep.path}`,
          );
        }
      }

      // Verify unpaid POST & getQuote() return live HTTP 402 quotes without spending any funds
      const prevKey = process.env.X402_PAYER_PRIVATE_KEY;
      delete process.env.X402_PAYER_PRIVATE_KEY;
      try {
        const [tokenQuote, scanQuote] = await Promise.all([
          checkTokenRisk({
            chain: "base",
            address: SUPPORTED_NETWORKS.base.usdcContract,
          }),
          getQuote("scan-repo"),
        ]);

        assert.equal(tokenQuote.ok, false);
        assert.equal(tokenQuote.status, 402);
        assert.equal(tokenQuote.paymentRequired, true);
        assert.equal(tokenQuote.challenge.accepts.length, 2);

        assert.equal(scanQuote.ok, true);
        assert.equal(scanQuote.status, 402);
        assert.equal(scanQuote.priceUsd, "0.05");
        assert.equal(scanQuote.eip3009Requirements.length, 2);
        assert.equal(
          scanQuote.eip3009Requirements.every((r) => r.payToVerified),
          true,
        );
      } finally {
        if (prevKey !== undefined) {
          process.env.X402_PAYER_PRIVATE_KEY = prevKey;
        }
      }
    },
  );
});

