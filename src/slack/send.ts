import crypto from "node:crypto";
import os from "node:os";
import {
  type Block,
  type FilesUploadV2Arguments,
  type KnownBlock,
  type WebClient,
} from "@slack/web-api";
import {
  chunkMarkdownTextWithMode,
  resolveChunkMode,
  resolveTextChunkLimit,
} from "../auto-reply/chunk.js";
import { loadConfig } from "../config/config.js";
import { resolveMarkdownTableMode } from "../config/markdown-tables.js";
import { logVerbose } from "../globals.js";
import { loadWebMedia } from "../web/media.js";
import type { SlackTokenSource } from "./accounts.js";
import { resolveSlackAccount } from "./accounts.js";
import { buildSlackBlocksFallbackText } from "./blocks-fallback.js";
import { validateSlackBlocksArray } from "./blocks-input.js";
import { createSlackWebClient } from "./client.js";
import { markdownToSlackMrkdwnChunks } from "./format.js";
import { parseSlackTarget } from "./targets.js";
import { resolveSlackBotToken } from "./token.js";

const SLACK_TEXT_LIMIT = 4000;
const LEGAL_END_STATE_RE = /\b(CLOSURE PACKET|BLOCKED PACKET|CHECKPOINT PLAN)\b/i;
const ILLEGAL_OUTBOUND_RE =
  /(https?:\/\/|\bLive URL\b|\bdeployed\b|\bit['’]s live\b|\bDone\s*—\b|\bbuilt and deployed\b|\bvercel\.app\b)/i;

type SlackRecipient =
  | {
      kind: "user";
      id: string;
    }
  | {
      kind: "channel";
      id: string;
    };

export type SlackSendIdentity = {
  username?: string;
  iconUrl?: string;
  iconEmoji?: string;
};

type SlackSendOpts = {
  token?: string;
  accountId?: string;
  mediaUrl?: string;
  mediaLocalRoots?: readonly string[];
  client?: WebClient;
  threadTs?: string;
  identity?: SlackSendIdentity;
  blocks?: (Block | KnownBlock)[];
};

function hasCustomIdentity(identity?: SlackSendIdentity): boolean {
  return Boolean(identity?.username || identity?.iconUrl || identity?.iconEmoji);
}

function isSlackCustomizeScopeError(err: unknown): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  const maybeData = err as Error & {
    data?: {
      error?: string;
      needed?: string;
      response_metadata?: { scopes?: string[]; acceptedScopes?: string[] };
    };
  };
  const code = maybeData.data?.error?.toLowerCase();
  if (code !== "missing_scope") {
    return false;
  }
  const needed = maybeData.data?.needed?.toLowerCase();
  if (needed?.includes("chat:write.customize")) {
    return true;
  }
  const scopes = [
    ...(maybeData.data?.response_metadata?.scopes ?? []),
    ...(maybeData.data?.response_metadata?.acceptedScopes ?? []),
  ].map((scope) => scope.toLowerCase());
  return scopes.includes("chat:write.customize");
}

function textHashPreview(text: string): string {
  const normalized = text.trim();
  if (!normalized) {
    return "empty";
  }
  return crypto.createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

function resolveSlackRequestId(value: unknown): string {
  if (!value || typeof value !== "object") {
    return "n/a";
  }
  const candidate = (value as { response_metadata?: { request_id?: string } }).response_metadata
    ?.request_id;
  return candidate?.trim() || "n/a";
}

function logSlackSendCorrelation(params: {
  ok: boolean;
  channelId: string;
  messageTs?: string;
  text: string;
  requestId?: string;
  error?: string;
}) {
  const host = os.hostname();
  const hash = textHashPreview(params.text);
  const requestId = params.requestId?.trim() || "n/a";
  if (params.ok) {
    console.log(
      `[SLACK_SEND] ok=true provider=slack channel_id=${params.channelId} ts=${params.messageTs ?? "unknown"} text_hash=${hash} request_id=${requestId} host=${host}`,
    );
    return;
  }
  console.log(
    `[SLACK_SEND] ok=false provider=slack channel_id=${params.channelId} ts=unknown text_hash=${hash} request_id=${requestId} error=${(params.error ?? "unknown").replace(/\s+/g, " ")} host=${host}`,
  );
}

function buildSendGuardRewriteText(originalText: string): string {
  const missing: string[] = [];
  if (!process.env.MC_API_URL?.trim()) {
    missing.push("MC_API_URL");
  }
  if (!process.env.MC_API_TOKEN?.trim()) {
    missing.push("MC_API_TOKEN");
  }
  const appBase =
    process.env.MC_APP_BASE_URL?.trim() ||
    process.env.MC_API_URL?.trim()
      ?.replace(/\/$/, "")
      .replace(/\/api(?:\/runtime)?$/i, "");
  if (missing.length > 0) {
    return `BLOCKED PACKET\nMissing requirement: ${missing.join(", ")}\nRequired next step: configure Mission Control runtime env vars before publish claims.`;
  }
  const taskLink = appBase
    ? `${appBase.replace(/\/$/, "")}/tasks/new`
    : "<MC task link unavailable>";
  const objective = originalText.replace(/\s+/g, " ").trim().slice(0, 180);
  return `MC Task: ${taskLink}\nCHECKPOINT PLAN\n1) Create/bind Mission Control task before publish/deploy claims. Proof: task link.\n2) Execute one bounded step and capture evidence (commit/deploy output). Proof: evidence artifact.\n3) Return with legal end-state packet (Closure/Blocked/Checkpoint).\n\nObjective: ${objective}`;
}

function applySlackSendGuard(text: string, channelId: string): { blocked: boolean; text: string } {
  const hasIllegal = ILLEGAL_OUTBOUND_RE.test(text);
  const hasMcTask = /\bMC Task:\b/i.test(text);
  const hasLegalState = LEGAL_END_STATE_RE.test(text);
  if (hasIllegal && !(hasMcTask && hasLegalState)) {
    const textHash = textHashPreview(text);
    console.warn(
      `[POLICY_GUARD_SEND] blocked_illegal_outbound provider=slack channel_id=${channelId} text_hash=${textHash}`,
    );
    console.warn(
      `[POLICY_VIOLATION_SEND_GUARD] provider=slack channel_id=${channelId} text_hash=${textHash}`,
    );
    return { blocked: true, text: buildSendGuardRewriteText(text) };
  }
  return { blocked: false, text };
}

async function postSlackMessageBestEffort(params: {
  client: WebClient;
  channelId: string;
  text: string;
  threadTs?: string;
  identity?: SlackSendIdentity;
  blocks?: (Block | KnownBlock)[];
}) {
  const basePayload = {
    channel: params.channelId,
    text: params.text,
    thread_ts: params.threadTs,
    ...(params.blocks?.length ? { blocks: params.blocks } : {}),
  };
  try {
    // Slack Web API types model icon_url and icon_emoji as mutually exclusive.
    // Build payloads in explicit branches so TS and runtime stay aligned.
    if (params.identity?.iconUrl) {
      const response = await params.client.chat.postMessage({
        ...basePayload,
        ...(params.identity.username ? { username: params.identity.username } : {}),
        icon_url: params.identity.iconUrl,
      });
      logSlackSendCorrelation({
        ok: true,
        channelId: params.channelId,
        messageTs: response.ts,
        text: params.text,
        requestId: resolveSlackRequestId(response),
      });
      return response;
    }
    if (params.identity?.iconEmoji) {
      const response = await params.client.chat.postMessage({
        ...basePayload,
        ...(params.identity.username ? { username: params.identity.username } : {}),
        icon_emoji: params.identity.iconEmoji,
      });
      logSlackSendCorrelation({
        ok: true,
        channelId: params.channelId,
        messageTs: response.ts,
        text: params.text,
        requestId: resolveSlackRequestId(response),
      });
      return response;
    }
    const response = await params.client.chat.postMessage({
      ...basePayload,
      ...(params.identity?.username ? { username: params.identity.username } : {}),
    });
    logSlackSendCorrelation({
      ok: true,
      channelId: params.channelId,
      messageTs: response.ts,
      text: params.text,
      requestId: resolveSlackRequestId(response),
    });
    return response;
  } catch (err) {
    if (!hasCustomIdentity(params.identity) || !isSlackCustomizeScopeError(err)) {
      const error = err instanceof Error ? err.message : String(err);
      const requestId = resolveSlackRequestId(err);
      logSlackSendCorrelation({
        ok: false,
        channelId: params.channelId,
        text: params.text,
        requestId,
        error,
      });
      throw err;
    }
    logVerbose("slack send: missing chat:write.customize, retrying without custom identity");
    const response = await params.client.chat.postMessage(basePayload);
    logSlackSendCorrelation({
      ok: true,
      channelId: params.channelId,
      messageTs: response.ts,
      text: params.text,
      requestId: resolveSlackRequestId(response),
    });
    return response;
  }
}

export type SlackSendResult = {
  messageId: string;
  channelId: string;
};

function resolveToken(params: {
  explicit?: string;
  accountId: string;
  fallbackToken?: string;
  fallbackSource?: SlackTokenSource;
}) {
  const explicit = resolveSlackBotToken(params.explicit);
  if (explicit) {
    return explicit;
  }
  const fallback = resolveSlackBotToken(params.fallbackToken);
  if (!fallback) {
    logVerbose(
      `slack send: missing bot token for account=${params.accountId} explicit=${Boolean(
        params.explicit,
      )} source=${params.fallbackSource ?? "unknown"}`,
    );
    throw new Error(
      `Slack bot token missing for account "${params.accountId}" (set channels.slack.accounts.${params.accountId}.botToken or SLACK_BOT_TOKEN for default).`,
    );
  }
  return fallback;
}

function parseRecipient(raw: string): SlackRecipient {
  const target = parseSlackTarget(raw);
  if (!target) {
    throw new Error("Recipient is required for Slack sends");
  }
  return { kind: target.kind, id: target.id };
}

async function resolveChannelId(
  client: WebClient,
  recipient: SlackRecipient,
): Promise<{ channelId: string; isDm?: boolean }> {
  // Bare Slack user IDs (U-prefix) may arrive with kind="channel" when the
  // target string had no explicit prefix (parseSlackTarget defaults bare IDs
  // to "channel"). chat.postMessage tolerates user IDs directly, but
  // files.uploadV2 → completeUploadExternal validates channel_id against
  // ^[CGDZ][A-Z0-9]{8,}$ and rejects U-prefixed IDs.  Always resolve user
  // IDs via conversations.open to obtain the DM channel ID.
  const isUserId = recipient.kind === "user" || /^U[A-Z0-9]+$/i.test(recipient.id);
  if (!isUserId) {
    return { channelId: recipient.id };
  }
  const response = await client.conversations.open({ users: recipient.id });
  const channelId = response.channel?.id;
  if (!channelId) {
    throw new Error("Failed to open Slack DM channel");
  }
  return { channelId, isDm: true };
}

async function uploadSlackFile(params: {
  client: WebClient;
  channelId: string;
  mediaUrl: string;
  mediaLocalRoots?: readonly string[];
  caption?: string;
  threadTs?: string;
  maxBytes?: number;
}): Promise<string> {
  const {
    buffer,
    contentType: _contentType,
    fileName,
  } = await loadWebMedia(params.mediaUrl, {
    maxBytes: params.maxBytes,
    localRoots: params.mediaLocalRoots,
  });
  const basePayload = {
    channel_id: params.channelId,
    file: buffer,
    filename: fileName,
    ...(params.caption ? { initial_comment: params.caption } : {}),
    // Note: filetype is deprecated in files.uploadV2, Slack auto-detects from file content
  };
  const payload: FilesUploadV2Arguments = params.threadTs
    ? { ...basePayload, thread_ts: params.threadTs }
    : basePayload;
  const response = await params.client.files.uploadV2(payload);
  const parsed = response as {
    files?: Array<{ id?: string; name?: string }>;
    file?: { id?: string; name?: string };
  };
  const fileId =
    parsed.files?.[0]?.id ??
    parsed.file?.id ??
    parsed.files?.[0]?.name ??
    parsed.file?.name ??
    "unknown";
  return fileId;
}

export async function sendMessageSlack(
  to: string,
  message: string,
  opts: SlackSendOpts = {},
): Promise<SlackSendResult> {
  const trimmedMessage = message?.trim() ?? "";
  const blocks = opts.blocks == null ? undefined : validateSlackBlocksArray(opts.blocks);
  if (!trimmedMessage && !opts.mediaUrl && !blocks) {
    throw new Error("Slack send requires text, blocks, or media");
  }
  const cfg = loadConfig();
  const account = resolveSlackAccount({
    cfg,
    accountId: opts.accountId,
  });
  const token = resolveToken({
    explicit: opts.token,
    accountId: account.accountId,
    fallbackToken: account.botToken,
    fallbackSource: account.botTokenSource,
  });
  const client = opts.client ?? createSlackWebClient(token);
  const recipient = parseRecipient(to);
  const { channelId } = await resolveChannelId(client, recipient);
  const guardedPrimary = applySlackSendGuard(trimmedMessage, channelId);
  const effectivePrimaryText = guardedPrimary.text;

  if (blocks) {
    if (opts.mediaUrl) {
      throw new Error("Slack send does not support blocks with mediaUrl");
    }
    const fallbackText = effectivePrimaryText || buildSlackBlocksFallbackText(blocks);
    const guardedFallback = applySlackSendGuard(fallbackText, channelId);
    const response = await postSlackMessageBestEffort({
      client,
      channelId,
      text: guardedFallback.text,
      threadTs: opts.threadTs,
      identity: opts.identity,
      blocks,
    });
    return {
      messageId: response.ts ?? "unknown",
      channelId,
    };
  }
  const textLimit = resolveTextChunkLimit(cfg, "slack", account.accountId);
  const chunkLimit = Math.min(textLimit, SLACK_TEXT_LIMIT);
  const tableMode = resolveMarkdownTableMode({
    cfg,
    channel: "slack",
    accountId: account.accountId,
  });
  const chunkMode = resolveChunkMode(cfg, "slack", account.accountId);
  const markdownChunks =
    chunkMode === "newline"
      ? chunkMarkdownTextWithMode(effectivePrimaryText, chunkLimit, chunkMode)
      : [effectivePrimaryText];
  const chunks = markdownChunks.flatMap((markdown) =>
    markdownToSlackMrkdwnChunks(markdown, chunkLimit, { tableMode }),
  );
  if (!chunks.length && effectivePrimaryText) {
    chunks.push(effectivePrimaryText);
  }
  const mediaMaxBytes =
    typeof account.config.mediaMaxMb === "number"
      ? account.config.mediaMaxMb * 1024 * 1024
      : undefined;

  let lastMessageId = "";
  if (opts.mediaUrl) {
    const [firstChunk, ...rest] = chunks;
    lastMessageId = await uploadSlackFile({
      client,
      channelId,
      mediaUrl: opts.mediaUrl,
      mediaLocalRoots: opts.mediaLocalRoots,
      caption: firstChunk,
      threadTs: opts.threadTs,
      maxBytes: mediaMaxBytes,
    });
    for (const chunk of rest) {
      const response = await postSlackMessageBestEffort({
        client,
        channelId,
        text: chunk,
        threadTs: opts.threadTs,
        identity: opts.identity,
      });
      lastMessageId = response.ts ?? lastMessageId;
    }
  } else {
    for (const chunk of chunks.length ? chunks : [""]) {
      const response = await postSlackMessageBestEffort({
        client,
        channelId,
        text: chunk,
        threadTs: opts.threadTs,
        identity: opts.identity,
      });
      lastMessageId = response.ts ?? lastMessageId;
    }
  }

  return {
    messageId: lastMessageId || "unknown",
    channelId,
  };
}
