import { randomBytes } from "node:crypto";
import { getAddress, isHex, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const DEFAULT_BASE_URL = "https://x402-cerberus-worker.boxxon.workers.dev";

/**
 * Exclusive public receiving addresses for Wallet 1 :: SI_Gemini.
 * Client-side EIP-3009 signing strictly enforces that every payment challenge's
 * `payTo` address matches SI_GEMINI_EVM_PAYOUT_ADDRESS before signing.
 */
export const SI_GEMINI_WALLET_ALIAS = "Wallet 1 :: SI_Gemini";
export const SI_GEMINI_EVM_PAYOUT_ADDRESS = "0x51E24000948150400166b40d486dB7b3C5b2C5A1";
export const SI_GEMINI_SOLANA_PAYOUT_ADDRESS = "H8ckc19KdGFoCAXh1cGjQL4bGP75DdAvnRQMBpGypRQx";

export type SupportedNetwork = "base" | "arbitrum";

export interface NetworkUsdcConfig {
  readonly network: SupportedNetwork;
  readonly chainId: number;
  readonly caip2: string;
  readonly usdcContract: Address;
  readonly eip712Name: string;
  readonly eip712Version: string;
}

export const SUPPORTED_NETWORKS: Record<SupportedNetwork, NetworkUsdcConfig> = {
  base: {
    network: "base",
    chainId: 8453,
    caip2: "eip155:8453",
    usdcContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
  arbitrum: {
    network: "arbitrum",
    chainId: 42161,
    caip2: "eip155:42161",
    usdcContract: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
};

export const CERBERUS_ENDPOINTS = {
  scanRepo: "/v1/cerberus/scan-repo",
  tokenRisk: "/v1/onchain/token-risk",
  sbomAudit: "/v1/sbom/audit",
  auditSolidity: "/v1/cerberus/audit-solidity",
} as const;

export const EIP3009_TRANSFER_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export interface X402AcceptOption {
  scheme: string;
  network: string;
  chainId?: number;
  caip2?: string;
  maxAmountRequired: string;
  resource?: string;
  description?: string;
  mimeType?: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  asset: string;
  extra?: {
    name?: string;
    version?: string;
    eip3009?: boolean;
    walletAlias?: string;
    [key: string]: unknown;
  };
}

export interface X402Challenge {
  x402Version: number;
  error?: string;
  accepts: X402AcceptOption[];
}

export interface Eip3009Authorization {
  from: Address;
  to: Address;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: Hex;
}

export interface X402PaymentPayload {
  x402Version: number;
  scheme: string;
  network: SupportedNetwork;
  payload: {
    signature: Hex;
    authorization: Eip3009Authorization;
  };
}

export interface SignedEip3009Payment {
  headerName: "X-PAYMENT";
  headerValue: string;
  payload: X402PaymentPayload;
  network: SupportedNetwork;
  chainId: number;
  asset: Address;
  amountMicroUsdc: string;
  amountUsd: string;
  payTo: Address;
  payer: Address;
}

export interface X402HealthResponse {
  status: string;
  service: string;
  version: string;
  timestamp: string;
  nonceStoreBackend?: string;
  facilitatorConfigured?: boolean;
  wallet: {
    alias: string;
    exclusive?: boolean;
    evmPayoutAddress: string;
    evmPayoutAddressChecksum?: string;
    solanaPayoutAddress: string;
  };
  x402: {
    version: number;
    acceptedNetworks: Array<{
      network: string;
      chainId: number;
      usdcContract: string;
    }>;
    discoveryManifest: string;
  };
}

export interface X402EndpointManifest {
  id: string;
  method: string;
  path: string;
  resource: string;
  description: string;
  pricing: {
    currency: string;
    amountUsd: string;
    amountMicroUsdc: string;
  };
  accepts: X402AcceptOption[];
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
}

export interface X402DiscoveryManifest {
  x402Version: number;
  name: string;
  version: string;
  description: string;
  wallet: {
    alias: string;
    evmPayoutAddress: string;
    solanaPayoutAddress: string;
  };
  paymentMethods: Array<Record<string, unknown>>;
  endpoints: X402EndpointManifest[];
}

export interface DiscoveryResult {
  baseUrl: string;
  health: X402HealthResponse;
  manifest: X402DiscoveryManifest;
}

export type FetchLike = typeof fetch;

export interface ClientBaseOptions {
  baseUrl?: string;
  fetch?: FetchLike;
}

export interface CallEndpointOptions extends ClientBaseOptions {
  /**
   * Optional 0x-prefixed 32-byte EVM private key supplied locally by the caller.
   * Defaults to `process.env.X402_PAYER_PRIVATE_KEY` when omitted.
   * Never persisted or logged.
   */
  payerPrivateKey?: string;
  /** Preferred settlement network when signing EIP-3009 USDC authorizations. Defaults to "base". */
  preferredNetwork?: SupportedNetwork;
  /** Optional extra headers merged into the HTTP request. */
  headers?: Record<string, string>;
  /** Override current unix timestamp (seconds) for deterministic testing. */
  nowSeconds?: number;
}

export interface SignEip3009Options {
  /** Optional deterministic unix timestamp in seconds (testing only). */
  nowSeconds?: number;
  /** Optional deterministic 32-byte hex nonce (testing only). */
  nonce?: Hex;
}

export interface X402SuccessResult<T = unknown> {
  ok: true;
  status: number;
  paymentRequired: false;
  paid: boolean;
  endpoint: string;
  data: T;
  payment?: {
    network: SupportedNetwork;
    chainId: number;
    asset: Address;
    amountMicroUsdc: string;
    amountUsd: string;
    payTo: Address;
    payer: Address;
  };
  paymentResponse?: unknown;
}

export interface X402QuoteResult {
  ok: false;
  status: 402;
  paymentRequired: true;
  paid: false;
  endpoint: string;
  payTo: string;
  solanaPayoutAddress: string;
  walletAlias: string;
  challenge: X402Challenge;
  instructions: string;
}

export type X402CallResult<T = unknown> = X402SuccessResult<T> | X402QuoteResult;

export interface FileEntry {
  path: string;
  content: string;
}

export interface ScanRepoRequest {
  repoUrl?: string;
  files?: Record<string, string> | FileEntry[];
  issueText?: string;
}

export interface ScanRepoResponse {
  verdict: "ALLOW" | "WARN" | "BLOCK";
  riskScore: number;
  layers: unknown[];
  findings: unknown[];
  [key: string]: unknown;
}

export type EvmChainName = "arbitrum" | "base" | "ethereum" | "optimism" | "polygon";

export interface TokenRiskRequest {
  chain: EvmChainName;
  address: string;
}

export interface TokenRiskResponse {
  chain: string;
  address: string;
  isContract: boolean;
  isProxy: boolean;
  eip1967Implementation?: string | null;
  opcodes: Record<string, unknown>;
  detectedSelectors: unknown[];
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  [key: string]: unknown;
}

export type SbomFormat = "package.json" | "requirements.txt" | "Cargo.toml";

export interface SbomAuditRequest {
  format: SbomFormat;
  content: string;
  projectName?: string;
  projectVersion?: string;
}

export interface SbomAuditResponse {
  verdict: "PASS" | "WARN" | "FAIL";
  riskScore: number;
  summary: Record<string, unknown>;
  findings: unknown[];
  sbom: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AuditSolidityRequest {
  filename?: string;
  source?: string;
  files?: Record<string, string> | FileEntry[];
}

export interface AuditSolidityResponse {
  scanner: string;
  filesScanned: number;
  linesScanned: number;
  verdict: "PASS" | "MEDIUM_RISK" | "HIGH_RISK" | "CRITICAL_RISK";
  riskScore: number;
  severityCounts: Record<string, number>;
  findingsCount: number;
  findings: unknown[];
  [key: string]: unknown;
}

export function normalizeBaseUrl(baseUrl?: string): string {
  return (baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
}

export function isTrustedPayTo(address: string): boolean {
  return address.toLowerCase() === SI_GEMINI_EVM_PAYOUT_ADDRESS.toLowerCase();
}

export function formatMicroUsdc(microUsdc: string | bigint): string {
  const value = typeof microUsdc === "bigint" ? microUsdc : BigInt(microUsdc);
  const whole = value / 1_000_000n;
  const frac = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  const displayFrac = frac.length < 2 ? frac.padEnd(2, "0") : frac;
  return `${whole.toString()}.${displayFrac}`;
}

function normalizePrivateKey(privateKey: string): Hex {
  const trimmed = privateKey.trim();
  const prefixed = trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
  if (!isHex(prefixed) || prefixed.length !== 66) {
    throw new Error("Invalid X402_PAYER_PRIVATE_KEY: expected a 32-byte 0x-prefixed hex private key.");
  }
  return prefixed;
}

function parseBase64Json<T>(raw: string): T | null {
  try {
    const decoded = Buffer.from(raw, "base64").toString("utf8");
    return JSON.parse(decoded) as T;
  } catch {
    return null;
  }
}

async function parseChallenge(response: Response): Promise<X402Challenge> {
  const headerValue =
    response.headers.get("x-payment-required") ?? response.headers.get("payment-required");
  if (headerValue) {
    const parsedHeader = parseBase64Json<X402Challenge>(headerValue);
    if (parsedHeader && Array.isArray(parsedHeader.accepts)) {
      return parsedHeader;
    }
  }

  const body = (await response.json()) as Partial<X402Challenge>;
  if (!body || !Array.isArray(body.accepts)) {
    throw new Error("Received HTTP 402 without a valid x402 payment challenge.");
  }
  return {
    x402Version: body.x402Version ?? 1,
    error: body.error,
    accepts: body.accepts,
  };
}

function selectAcceptOption(
  challenge: X402Challenge,
  preferredNetwork: SupportedNetwork,
): { accept: X402AcceptOption; networkConfig: NetworkUsdcConfig } {
  const preferred = challenge.accepts.find(
    (entry) => entry.network.toLowerCase() === preferredNetwork.toLowerCase(),
  );
  const chosen =
    preferred ??
    challenge.accepts.find((entry) => {
      const n = entry.network.toLowerCase();
      return n === "base" || n === "arbitrum";
    });

  if (!chosen) {
    throw new Error(
      `No supported x402 network found in challenge (expected base or arbitrum, got: ${challenge.accepts.map((a) => a.network).join(", ") || "none"}).`,
    );
  }

  const networkKey = chosen.network.toLowerCase() as SupportedNetwork;
  const networkConfig = SUPPORTED_NETWORKS[networkKey];
  if (!networkConfig) {
    throw new Error(`Unsupported x402 network "${chosen.network}".`);
  }

  return { accept: chosen, networkConfig };
}

/**
 * Fetch live `/health` and `/.well-known/x402.json` discovery metadata from the worker.
 */
export async function discover(options: ClientBaseOptions = {}): Promise<DiscoveryResult> {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const fetchFn = options.fetch ?? globalThis.fetch;

  const [healthRes, manifestRes] = await Promise.all([
    fetchFn(`${baseUrl}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
    }),
    fetchFn(`${baseUrl}/.well-known/x402.json`, {
      method: "GET",
      headers: { Accept: "application/json" },
    }),
  ]);

  if (!healthRes.ok) {
    throw new Error(`Health check failed with HTTP ${healthRes.status} at ${baseUrl}/health`);
  }
  if (!manifestRes.ok) {
    throw new Error(
      `x402 discovery manifest fetch failed with HTTP ${manifestRes.status} at ${baseUrl}/.well-known/x402.json`,
    );
  }

  const [health, manifest] = (await Promise.all([
    healthRes.json(),
    manifestRes.json(),
  ])) as [X402HealthResponse, X402DiscoveryManifest];

  return { baseUrl, health, manifest };
}

/**
 * Sign a real EIP-3009 USDC `TransferWithAuthorization` payload via `viem/accounts`.
 *
 * Security invariants enforced before signing:
 * 1. `accept.payTo` MUST equal `0x51E24000948150400166b40d486dB7b3C5b2C5A1` (case-insensitive).
 * 2. `accept.asset` MUST match the canonical USDC contract for Base (8453) or Arbitrum (42161).
 * 3. `accept.maxAmountRequired` MUST be a positive integer in micro-USDC.
 */
export async function signEip3009Payment(
  privateKey: string,
  challenge: X402Challenge,
  preferredNetwork: SupportedNetwork = "base",
  options: SignEip3009Options = {},
): Promise<SignedEip3009Payment> {
  const normalizedKey = normalizePrivateKey(privateKey);
  const { accept, networkConfig } = selectAcceptOption(challenge, preferredNetwork);

  if (!isTrustedPayTo(accept.payTo)) {
    throw new Error(
      `Refusing to sign x402 payment: challenge payTo (${accept.payTo}) does not match expected ${SI_GEMINI_WALLET_ALIAS} address (${SI_GEMINI_EVM_PAYOUT_ADDRESS}).`,
    );
  }

  if (accept.asset.toLowerCase() !== networkConfig.usdcContract.toLowerCase()) {
    throw new Error(
      `Refusing to sign x402 payment: unexpected asset (${accept.asset}) for ${networkConfig.network}; expected canonical USDC (${networkConfig.usdcContract}).`,
    );
  }

  const chainId = accept.chainId ?? networkConfig.chainId;
  if (chainId !== networkConfig.chainId) {
    throw new Error(
      `Refusing to sign x402 payment: challenge chainId (${chainId}) does not match ${networkConfig.network} (${networkConfig.chainId}).`,
    );
  }

  const valueBigInt = BigInt(accept.maxAmountRequired);
  if (valueBigInt <= 0n) {
    throw new Error(
      `Refusing to sign x402 payment: maxAmountRequired must be positive, got ${accept.maxAmountRequired}.`,
    );
  }

  const account = privateKeyToAccount(normalizedKey);
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const validAfter = BigInt(Math.max(0, nowSeconds - 60));
  const timeoutSeconds =
    typeof accept.maxTimeoutSeconds === "number" && accept.maxTimeoutSeconds > 0
      ? accept.maxTimeoutSeconds
      : 300;
  const validBefore = BigInt(nowSeconds + timeoutSeconds);
  const nonce: Hex = options.nonce ?? (`0x${randomBytes(32).toString("hex")}` as Hex);

  const toAddress = getAddress(SI_GEMINI_EVM_PAYOUT_ADDRESS);
  const verifyingContract = getAddress(networkConfig.usdcContract);

  const domain = {
    name: accept.extra?.name ?? networkConfig.eip712Name,
    version: accept.extra?.version ?? networkConfig.eip712Version,
    chainId,
    verifyingContract,
  } as const;

  const signature = await account.signTypedData({
    domain,
    types: EIP3009_TRANSFER_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: account.address,
      to: toAddress,
      value: valueBigInt,
      validAfter,
      validBefore,
      nonce,
    },
  });

  const payload: X402PaymentPayload = {
    x402Version: challenge.x402Version ?? 1,
    scheme: accept.scheme ?? "exact",
    network: networkConfig.network,
    payload: {
      signature,
      authorization: {
        from: account.address,
        to: toAddress,
        value: valueBigInt.toString(),
        validAfter: validAfter.toString(),
        validBefore: validBefore.toString(),
        nonce,
      },
    },
  };

  const headerValue = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");

  return {
    headerName: "X-PAYMENT",
    headerValue,
    payload,
    network: networkConfig.network,
    chainId,
    asset: verifyingContract,
    amountMicroUsdc: valueBigInt.toString(),
    amountUsd: formatMicroUsdc(valueBigInt),
    payTo: toAddress,
    payer: account.address,
  };
}

/**
 * Call a paid Cerberus x402 endpoint.
 * - If HTTP 402 is returned and a caller private key is available (via `options.payerPrivateKey`
 *   or `process.env.X402_PAYER_PRIVATE_KEY`), signs EIP-3009 USDC `TransferWithAuthorization`
 *   locally and retries automatically with the `X-PAYMENT` header.
 * - If no payer private key is configured, returns a structured 402 payment quote instead of throwing.
 */
export async function callEndpoint<TResponse = unknown>(
  path: string,
  body: Record<string, unknown>,
  options: CallEndpointOptions = {},
): Promise<X402CallResult<TResponse>> {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = `${baseUrl}${normalizedPath}`;
  const fetchFn = options.fetch ?? globalThis.fetch;
  const preferredNetwork: SupportedNetwork =
    options.preferredNetwork ??
    (process.env.X402_NETWORK === "arbitrum" ? "arbitrum" : "base");

  const baseHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...options.headers,
  };

  const initialResponse = await fetchFn(url, {
    method: "POST",
    headers: baseHeaders,
    body: JSON.stringify(body),
  });

  if (initialResponse.ok) {
    const data = (await initialResponse.json()) as TResponse;
    return {
      ok: true,
      status: initialResponse.status,
      paymentRequired: false,
      paid: false,
      endpoint: url,
      data,
    };
  }

  if (initialResponse.status !== 402) {
    const errText = await initialResponse.text();
    throw new Error(`Cerberus API error (${initialResponse.status}) at ${url}: ${errText}`);
  }

  const challenge = await parseChallenge(initialResponse);
  const payerKey = options.payerPrivateKey ?? process.env.X402_PAYER_PRIVATE_KEY;

  if (!payerKey || payerKey.trim().length === 0) {
    const primaryQuote = challenge.accepts[0];
    const usd = primaryQuote ? formatMicroUsdc(primaryQuote.maxAmountRequired) : "0.00";
    return {
      ok: false,
      status: 402,
      paymentRequired: true,
      paid: false,
      endpoint: url,
      payTo: SI_GEMINI_EVM_PAYOUT_ADDRESS,
      solanaPayoutAddress: SI_GEMINI_SOLANA_PAYOUT_ADDRESS,
      walletAlias: SI_GEMINI_WALLET_ALIAS,
      challenge,
      instructions:
        `HTTP 402 Payment Required ($${usd} USDC on Base 8453 or Arbitrum 42161 to ${SI_GEMINI_EVM_PAYOUT_ADDRESS}). ` +
        `Set X402_PAYER_PRIVATE_KEY in your local environment (or pass payerPrivateKey to the SDK) to automatically sign EIP-3009 USDC TransferWithAuthorization and retry.`,
    };
  }

  const signed = await signEip3009Payment(payerKey, challenge, preferredNetwork, {
    nowSeconds: options.nowSeconds,
  });

  const paidResponse = await fetchFn(url, {
    method: "POST",
    headers: {
      ...baseHeaders,
      [signed.headerName]: signed.headerValue,
    },
    body: JSON.stringify(body),
  });

  if (!paidResponse.ok) {
    const errText = await paidResponse.text();
    throw new Error(
      `Cerberus paid request failed (${paidResponse.status}) at ${url} on ${signed.network}: ${errText}`,
    );
  }

  const paymentResponseHeader =
    paidResponse.headers.get("x-payment-response") ??
    paidResponse.headers.get("payment-response");
  const paymentResponse = paymentResponseHeader
    ? parseBase64Json(paymentResponseHeader) ?? paymentResponseHeader
    : undefined;

  const data = (await paidResponse.json()) as TResponse;

  return {
    ok: true,
    status: paidResponse.status,
    paymentRequired: false,
    paid: true,
    endpoint: url,
    data,
    payment: {
      network: signed.network,
      chainId: signed.chainId,
      asset: signed.asset,
      amountMicroUsdc: signed.amountMicroUsdc,
      amountUsd: signed.amountUsd,
      payTo: signed.payTo,
      payer: signed.payer,
    },
    paymentResponse,
  };
}

export async function scanRepo(
  request: ScanRepoRequest,
  options?: CallEndpointOptions,
): Promise<X402CallResult<ScanRepoResponse>> {
  return callEndpoint<ScanRepoResponse>(
    CERBERUS_ENDPOINTS.scanRepo,
    request as Record<string, unknown>,
    options,
  );
}

export async function checkTokenRisk(
  request: TokenRiskRequest,
  options?: CallEndpointOptions,
): Promise<X402CallResult<TokenRiskResponse>> {
  return callEndpoint<TokenRiskResponse>(
    CERBERUS_ENDPOINTS.tokenRisk,
    request as unknown as Record<string, unknown>,
    options,
  );
}

export async function auditSbom(
  request: SbomAuditRequest,
  options?: CallEndpointOptions,
): Promise<X402CallResult<SbomAuditResponse>> {
  return callEndpoint<SbomAuditResponse>(
    CERBERUS_ENDPOINTS.sbomAudit,
    request as unknown as Record<string, unknown>,
    options,
  );
}

export async function auditSolidity(
  request: AuditSolidityRequest,
  options?: CallEndpointOptions,
): Promise<X402CallResult<AuditSolidityResponse>> {
  return callEndpoint<AuditSolidityResponse>(
    CERBERUS_ENDPOINTS.auditSolidity,
    request as Record<string, unknown>,
    options,
  );
}

export class CerberusX402Client {
  readonly baseUrl: string;
  readonly preferredNetwork: SupportedNetwork;
  private readonly payerPrivateKey?: string;
  private readonly fetchFn?: FetchLike;

  constructor(options: CallEndpointOptions = {}) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.preferredNetwork = options.preferredNetwork ?? "base";
    this.payerPrivateKey = options.payerPrivateKey;
    this.fetchFn = options.fetch;
  }

  private mergeOptions(override?: CallEndpointOptions): CallEndpointOptions {
    return {
      baseUrl: override?.baseUrl ?? this.baseUrl,
      preferredNetwork: override?.preferredNetwork ?? this.preferredNetwork,
      payerPrivateKey: override?.payerPrivateKey ?? this.payerPrivateKey,
      fetch: override?.fetch ?? this.fetchFn,
      headers: override?.headers,
      nowSeconds: override?.nowSeconds,
    };
  }

  discover(): Promise<DiscoveryResult> {
    return discover({ baseUrl: this.baseUrl, fetch: this.fetchFn });
  }

  callEndpoint<TResponse = unknown>(
    path: string,
    body: Record<string, unknown>,
    override?: CallEndpointOptions,
  ): Promise<X402CallResult<TResponse>> {
    return callEndpoint<TResponse>(path, body, this.mergeOptions(override));
  }

  scanRepo(
    request: ScanRepoRequest,
    override?: CallEndpointOptions,
  ): Promise<X402CallResult<ScanRepoResponse>> {
    return scanRepo(request, this.mergeOptions(override));
  }

  checkTokenRisk(
    request: TokenRiskRequest,
    override?: CallEndpointOptions,
  ): Promise<X402CallResult<TokenRiskResponse>> {
    return checkTokenRisk(request, this.mergeOptions(override));
  }

  auditSbom(
    request: SbomAuditRequest,
    override?: CallEndpointOptions,
  ): Promise<X402CallResult<SbomAuditResponse>> {
    return auditSbom(request, this.mergeOptions(override));
  }

  auditSolidity(
    request: AuditSolidityRequest,
    override?: CallEndpointOptions,
  ): Promise<X402CallResult<AuditSolidityResponse>> {
    return auditSolidity(request, this.mergeOptions(override));
  }
}
