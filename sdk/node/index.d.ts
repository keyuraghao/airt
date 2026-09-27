export interface InstallOptions {
  /** Base URL of the AIRT gateway, e.g. "http://localhost:8080". Falls back to AIRT_GATEWAY_URL. */
  gatewayUrl?: string;
  /** Agent key issued by AIRT ("airt_..."). Falls back to AIRT_AGENT_KEY. */
  agentKey?: string;
  /** Hosts (host or host:port) to intercept. Defaults to DEFAULT_HOSTS. */
  hosts?: string[];
  /** Send X-AIRT-Async: 1 so the gateway returns 202 immediately; poll with waitForTicket(). */
  asyncMode?: boolean;
  /** X-AIRT-Source value: "sdk" (default), "gateway", "mitm" or "redteam". */
  source?: "sdk" | "gateway" | "mitm" | "redteam";
  /** Optional X-AIRT-Correlation-Id applied to every intercepted request. */
  correlationId?: string;
  /** Remove Authorization / x-api-key / api-key / x-goog-api-key before sending (default true). */
  stripProviderAuth?: boolean;
  /** Called for every intercepted request. */
  onIntercept?: (info: { originalUrl: string; gatewayUrl: string }) => void;
}

export interface SdkClientOptions {
  baseURL: string;
  apiKey: string;
  defaultHeaders: Record<string, string>;
}

export interface RewriteResult {
  input: string | Request;
  init: RequestInit | undefined;
  intercepted: boolean;
  originalUrl: string | null;
}

export type TicketStatus = "PENDING" | "APPROVED" | "FORWARDING" | "COMPLETED" | "DENIED" | "EXPIRED" | "FAILED";

export interface TicketResult {
  ticketId: string;
  status: TicketStatus;
  httpStatus: number;
  body: unknown;
  decidedBy: string | null;
  decisionNote: string;
  timedOut?: boolean;
}

export interface WaitOptions {
  gatewayUrl?: string;
  agentKey?: string;
  pollIntervalMs?: number;
  maxWaitMs?: number;
  fetch?: typeof fetch;
}

export const DEFAULT_HOSTS: readonly string[];
export const FINAL_TICKET_STATUSES: readonly TicketStatus[];
/** Wrap globalThis.fetch (and undici.fetch when present). Returns the uninstall function. */
export function install(options: InstallOptions): () => void;
export function uninstall(): void;
export function isInstalled(): boolean;
/** Gateway URL for a provider URL, or null when the host is not intercepted. */
export function rewriteUrl(originalUrl: string | URL, options?: InstallOptions): string | null;
export function rewriteRequest(input: string | URL | Request, init?: RequestInit, options?: InstallOptions): RewriteResult;
/** Options for `new OpenAI(...)` from the openai package. */
export function configureOpenAI(options: InstallOptions): SdkClientOptions;
/** Options for `new Anthropic(...)` from @anthropic-ai/sdk. */
export function configureAnthropic(options: InstallOptions): SdkClientOptions;
/** Poll /gateway/tickets/{id} until the ticket is COMPLETED, DENIED, EXPIRED or FAILED. */
export function waitForTicket(ticketId: string, options?: WaitOptions): Promise<TicketResult>;
