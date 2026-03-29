/**
 * Atlas Protocol — Telegram Integration
 *
 * Lightweight Telegram Bot API client using native fetch (Node 20+).
 * Polls for incoming messages and forwards authorized messages to the channel.
 * Sends permission prompts and collects human verdicts.
 */

import type { AtlasConfig } from "./config.js";

interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    from?: { id: number; first_name: string; username?: string };
    chat: { id: number; type: string };
    text?: string;
    date: number;
  };
}

interface TelegramResponse<T> {
  ok: boolean;
  result: T;
  description?: string;
}

export interface IncomingMessage {
  chat_id: number;
  from_id: number;
  from_name: string;
  text: string;
  timestamp: number;
}

export interface VerdictOutcome {
  decision: "allow" | "deny" | "timeout";
  responder_chat_id?: number;
}

export interface SendReplyOptions {
  chatId?: number;
  broadcast?: boolean;
}

export type MessageHandler = (msg: IncomingMessage) => void;

interface PendingVerdict {
  request_id: string;
  resolve: (outcome: VerdictOutcome) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class TelegramBot {
  private readonly token: string;
  private readonly allowedChatIds: Set<number>;
  private readonly baseUrl: string;
  private readonly pollIntervalMs: number;
  private offset = 0;
  private running = false;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private messageHandlers: MessageHandler[] = [];
  private pendingVerdicts: Map<string, PendingVerdict> = new Map();
  private lastInboundChatId: number | null = null;

  constructor(config: AtlasConfig) {
    this.token = config.telegram_bot_token;
    this.allowedChatIds = new Set(config.telegram_allowed_chat_ids);
    this.baseUrl = `https://api.telegram.org/bot${this.token}`;
    this.pollIntervalMs = config.telegram_poll_interval_ms;
  }

  onMessage(handler: MessageHandler): void {
    this.messageHandlers.push(handler);
  }

  getStatus(): {
    configured: boolean;
    allowed_chat_ids: number[];
    pending_verdicts: number;
    last_inbound_chat_id: number | null;
  } {
    return {
      configured: !!this.token,
      allowed_chat_ids: Array.from(this.allowedChatIds),
      pending_verdicts: this.pendingVerdicts.size,
      last_inbound_chat_id: this.lastInboundChatId,
    };
  }

  async start(): Promise<void> {
    if (!this.token) {
      console.error("[atlas-telegram] No bot token configured. Telegram integration disabled.");
      return;
    }
    this.running = true;
    this.poll();
  }

  stop(): void {
    this.running = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    for (const [, pending] of this.pendingVerdicts) {
      clearTimeout(pending.timer);
      pending.resolve({ decision: "timeout" });
    }
    this.pendingVerdicts.clear();
  }

  private async poll(): Promise<void> {
    if (!this.running) return;

    try {
      const updates = await this.getUpdates();
      for (const update of updates) {
        this.handleUpdate(update);
        this.offset = update.update_id + 1;
      }
    } catch (err) {
      console.error("[atlas-telegram] Poll error:", err);
    }

    this.pollTimer = setTimeout(() => this.poll(), this.pollIntervalMs);
  }

  private async getUpdates(): Promise<TelegramUpdate[]> {
    const url = `${this.baseUrl}/getUpdates?offset=${this.offset}&timeout=5&allowed_updates=["message"]`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    const data = (await res.json()) as TelegramResponse<TelegramUpdate[]>;
    if (!data.ok) {
      throw new Error(`Telegram API error: ${data.description}`);
    }
    return data.result;
  }

  private handleUpdate(update: TelegramUpdate): void {
    const msg = update.message;
    if (!msg?.text || !msg.from) return;

    const text = msg.text.trim();

    if (this.allowedChatIds.size === 0) {
      console.error(
        `[atlas-telegram] Ignoring message from chat ${msg.chat.id}: no authorized chats configured`
      );
      return;
    }

    if (!this.allowedChatIds.has(msg.chat.id)) {
      console.error(`[atlas-telegram] Dropped message from unauthorized chat ${msg.chat.id}`);
      return;
    }

    this.lastInboundChatId = msg.chat.id;

    const verdictMatch = text.match(/^(yes|no|approve|deny)\s+([a-km-z]{5})$/i);
    if (verdictMatch) {
      const approved = ["yes", "approve"].includes(verdictMatch[1].toLowerCase());
      const requestId = verdictMatch[2].toLowerCase();
      const pending = this.pendingVerdicts.get(requestId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingVerdicts.delete(requestId);
        pending.resolve({
          decision: approved ? "allow" : "deny",
          responder_chat_id: msg.chat.id,
        });
        this.sendMessage(
          msg.chat.id,
          `✅ Verdict recorded: ${approved ? "APPROVED" : "DENIED"} for ${requestId}`
        ).catch(() => {});
        return;
      }
    }

    const incoming: IncomingMessage = {
      chat_id: msg.chat.id,
      from_id: msg.from.id,
      from_name: msg.from.first_name + (msg.from.username ? ` (@${msg.from.username})` : ""),
      text,
      timestamp: msg.date,
    };

    for (const handler of this.messageHandlers) {
      try {
        handler(incoming);
      } catch (err) {
        console.error("[atlas-telegram] Handler error:", err);
      }
    }
  }

  async sendMessage(chatId: number, text: string, parseMode = "HTML"): Promise<void> {
    const url = `${this.baseUrl}/sendMessage`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: parseMode,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      throw new Error(`Telegram HTTP ${res.status} ${res.statusText}`);
    }

    const data = (await res.json()) as TelegramResponse<{ message_id: number }>;
    if (!data.ok) {
      throw new Error(`Telegram API error: ${data.description || "unknown error"}`);
    }
  }

  async requestVerdict(
    requestId: string,
    toolName: string,
    description: string,
    inputPreview: string,
    anomalyFlags: string[],
    timeoutSeconds: number
  ): Promise<VerdictOutcome> {
    const anomalySection =
      anomalyFlags.length > 0
        ? `\n\n⚠️ <b>ANOMALY FLAGS:</b>\n${anomalyFlags.map((f) => `• ${escapeHtml(f)}`).join("\n")}`
        : "";

    const prompt = [
      `🔐 <b>ATLAS PERMISSION REQUEST</b>`,
      ``,
      `<b>Tool:</b> <code>${escapeHtml(toolName)}</code>`,
      `<b>Action:</b> ${escapeHtml(description)}`,
      `<b>Input:</b> <code>${escapeHtml(inputPreview.slice(0, 500))}</code>`,
      anomalySection,
      ``,
      `Reply: <code>yes ${requestId}</code> or <code>no ${requestId}</code>`,
      ``,
      `⏱ Auto-deny in ${timeoutSeconds}s (fail-closed)`,
    ].join("\n");

    const chatIds = Array.from(this.allowedChatIds);
    if (chatIds.length === 0) {
      console.error("[atlas-telegram] No allowed chat IDs configured — auto-deny");
      return { decision: "timeout" };
    }

    let delivered = 0;
    for (const chatId of chatIds) {
      try {
        await this.sendMessage(chatId, prompt);
        delivered += 1;
      } catch (err) {
        console.error(`[atlas-telegram] Failed to send to chat ${chatId}:`, err);
      }
    }

    if (delivered === 0) {
      console.error("[atlas-telegram] Permission prompt could not be delivered to any authorized chat — auto-deny");
      return { decision: "timeout" };
    }

    return new Promise<VerdictOutcome>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingVerdicts.delete(requestId);
        resolve({ decision: "timeout" });
      }, timeoutSeconds * 1000);

      this.pendingVerdicts.set(requestId, {
        request_id: requestId,
        resolve,
        timer,
      });
    });
  }

  async sendReply(text: string, options: SendReplyOptions = {}): Promise<void> {
    const targetChatIds = this.resolveReplyTargets(options);
    for (const chatId of targetChatIds) {
      await this.sendMessage(chatId, text, "HTML");
    }
  }

  private resolveReplyTargets(options: SendReplyOptions): number[] {
    if (options.chatId !== undefined) {
      if (!this.allowedChatIds.has(options.chatId)) {
        throw new Error(`Chat ${options.chatId} is not in the allowed chat list`);
      }
      return [options.chatId];
    }

    if (options.broadcast) {
      return Array.from(this.allowedChatIds);
    }

    if (this.lastInboundChatId !== null && this.allowedChatIds.has(this.lastInboundChatId)) {
      return [this.lastInboundChatId];
    }

    if (this.allowedChatIds.size === 1) {
      return [Array.from(this.allowedChatIds)[0]];
    }

    if (this.allowedChatIds.size === 0) {
      throw new Error("No allowed Telegram chat IDs configured");
    }

    throw new Error(
      "Multiple allowed chats are configured and no reply target is known. Pass chat_id or broadcast=true."
    );
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
