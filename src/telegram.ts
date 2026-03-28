/**
 * Fidelis Channel — Telegram Integration
 *
 * Lightweight Telegram Bot API client using native fetch (Node 20+).
 * Polls for incoming messages and forwards them to the channel.
 * Sends formatted permission prompts and collects human verdicts.
 *
 * No external Telegram library needed — just the Bot HTTP API.
 */

import type { FidelisConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

export type MessageHandler = (msg: IncomingMessage) => void;

// ---------------------------------------------------------------------------
// Pending verdict tracking
// ---------------------------------------------------------------------------

interface PendingVerdict {
  request_id: string;
  resolve: (approved: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ---------------------------------------------------------------------------
// Telegram Bot
// ---------------------------------------------------------------------------

export class TelegramBot {
  private readonly token: string;
  private readonly allowedChatIds: Set<number>;
  private readonly baseUrl: string;
  private readonly pollIntervalMs: number;
  private offset: number = 0;
  private running: boolean = false;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  /** Handlers for non-verdict messages (forwarded to Claude as channel events) */
  private messageHandlers: MessageHandler[] = [];

  /** Map of request_id → pending verdict promise */
  private pendingVerdicts: Map<string, PendingVerdict> = new Map();

  constructor(config: FidelisConfig) {
    this.token = config.telegram_bot_token;
    this.allowedChatIds = new Set(config.telegram_allowed_chat_ids);
    this.baseUrl = `https://api.telegram.org/bot${this.token}`;
    this.pollIntervalMs = config.telegram_poll_interval_ms;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  onMessage(handler: MessageHandler): void {
    this.messageHandlers.push(handler);
  }

  async start(): Promise<void> {
    if (!this.token) {
      console.error("[fidelis-telegram] No bot token configured. Telegram integration disabled.");
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
    // Reject all pending verdicts (fail-closed)
    for (const [, pending] of this.pendingVerdicts) {
      clearTimeout(pending.timer);
      pending.resolve(false);
    }
    this.pendingVerdicts.clear();
  }

  // -------------------------------------------------------------------------
  // Polling loop
  // -------------------------------------------------------------------------

  private async poll(): Promise<void> {
    if (!this.running) return;

    try {
      const updates = await this.getUpdates();
      for (const update of updates) {
        this.handleUpdate(update);
        this.offset = update.update_id + 1;
      }
    } catch (err) {
      console.error("[fidelis-telegram] Poll error:", err);
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

    // Sender gating: only allowed chat IDs
    if (this.allowedChatIds.size > 0 && !this.allowedChatIds.has(msg.chat.id)) {
      console.error(`[fidelis-telegram] Dropped message from unauthorized chat ${msg.chat.id}`);
      return;
    }

    const text = msg.text.trim();

    // Check if this is a verdict reply: "yes <id>" or "no <id>"
    const verdictMatch = text.match(/^(yes|no|approve|deny)\s+([a-z]{5})$/i);
    if (verdictMatch) {
      const approved = verdictMatch[1].toLowerCase() === "yes" || verdictMatch[1].toLowerCase() === "approve";
      const requestId = verdictMatch[2].toLowerCase();
      const pending = this.pendingVerdicts.get(requestId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingVerdicts.delete(requestId);
        pending.resolve(approved);
        // Acknowledge
        this.sendMessage(msg.chat.id, `✅ Verdict recorded: ${approved ? "APPROVED" : "DENIED"} for ${requestId}`).catch(() => {});
        return;
      }
    }

    // Non-verdict message → forward to channel handlers
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
        console.error("[fidelis-telegram] Handler error:", err);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Outbound messaging
  // -------------------------------------------------------------------------

  async sendMessage(chatId: number, text: string, parseMode: string = "HTML"): Promise<void> {
    const url = `${this.baseUrl}/sendMessage`;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: parseMode,
      }),
      signal: AbortSignal.timeout(10_000),
    });
  }

  /**
   * Send a permission prompt to all allowed chats and wait for a verdict.
   * Returns true if approved, false if denied or timed out (fail-closed).
   */
  async requestVerdict(
    requestId: string,
    toolName: string,
    description: string,
    inputPreview: string,
    anomalyFlags: string[],
    timeoutSeconds: number
  ): Promise<boolean> {
    // Build the Telegram prompt
    const anomalySection =
      anomalyFlags.length > 0
        ? `\n\n⚠️ <b>ANOMALY FLAGS:</b>\n${anomalyFlags.map((f) => `• ${f}`).join("\n")}`
        : "";

    const prompt = [
      `🔐 <b>FIDELIS PERMISSION REQUEST</b>`,
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

    // Send to all allowed chats
    const chatIds = this.allowedChatIds.size > 0
      ? Array.from(this.allowedChatIds)
      : [];

    if (chatIds.length === 0) {
      console.error("[fidelis-telegram] No allowed chat IDs configured — auto-deny");
      return false;
    }

    for (const chatId of chatIds) {
      await this.sendMessage(chatId, prompt).catch((err) => {
        console.error(`[fidelis-telegram] Failed to send to chat ${chatId}:`, err);
      });
    }

    // Wait for verdict or timeout
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingVerdicts.delete(requestId);
        resolve(false); // FAIL-CLOSED
      }, timeoutSeconds * 1000);

      this.pendingVerdicts.set(requestId, { request_id: requestId, resolve, timer });
    });
  }

  /**
   * Send a reply message (for the Claude reply tool).
   */
  async sendReply(text: string): Promise<void> {
    const chatIds = Array.from(this.allowedChatIds);
    for (const chatId of chatIds) {
      await this.sendMessage(chatId, text, "HTML").catch(() => {});
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
