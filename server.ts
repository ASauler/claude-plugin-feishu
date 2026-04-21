#!/usr/bin/env bun
/**
 * Feishu/Lark channel for Claude Code.
 *
 * Self-contained MCP server with full access control: pairing, allowlists,
 * group support with mention-triggering. State lives in
 * ~/.claude/channels/feishu/access.json — managed by the /feishu:access skill.
 *
 * WebSocket long connection, bot-identity (tenant_access_token) only.
 * No OAuth-as-user flows. DM and group chats both supported.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import * as lark from '@larksuiteoapi/node-sdk'
import { randomBytes } from 'crypto'
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  chmodSync,
  existsSync,
} from 'fs'
import { homedir } from 'os'
import { join } from 'path'

// ---------------------------------------------------------------------------
// Paths & state
// ---------------------------------------------------------------------------
const STATE_DIR =
  process.env.FEISHU_STATE_DIR ?? join(homedir(), '.claude', 'channels', 'feishu')
const ACCESS_FILE = join(STATE_DIR, 'access.json')
const ENV_FILE = join(STATE_DIR, '.env')
const PID_FILE = join(STATE_DIR, 'bot.pid')

mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 })

// Load ~/.claude/channels/feishu/.env into process.env. Real env wins.
// Plugin-spawned servers don't get an env block — this is where secrets live.
try {
  chmodSync(ENV_FILE, 0o600)
  for (const line of readFileSync(ENV_FILE, 'utf8').split('\n')) {
    const m = line.match(/^(\w+)=(.*)$/)
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2]
  }
} catch {}

const APP_ID = process.env.FEISHU_APP_ID
const APP_SECRET = process.env.FEISHU_APP_SECRET
const DOMAIN = (process.env.FEISHU_DOMAIN ?? 'feishu') as 'feishu' | 'lark'

if (!APP_ID || !APP_SECRET) {
  process.stderr.write(
    `feishu channel: FEISHU_APP_ID and FEISHU_APP_SECRET required\n` +
      `  set in ${ENV_FILE}\n` +
      `  format:\n` +
      `    FEISHU_APP_ID=cli_xxxxxxxxxxxxxxxxx\n` +
      `    FEISHU_APP_SECRET=...\n`
  )
  process.exit(1)
}

// Stale PID killer. WebSocket endpoint tolerates multiple clients per app,
// but running two instances doubles message deliveries. Kill stragglers.
try {
  const stale = parseInt(readFileSync(PID_FILE, 'utf8'), 10)
  if (stale > 1 && stale !== process.pid) {
    process.kill(stale, 0)
    process.stderr.write(`feishu channel: replacing stale poller pid=${stale}\n`)
    process.kill(stale, 'SIGTERM')
  }
} catch {}
writeFileSync(PID_FILE, String(process.pid))

process.on('unhandledRejection', err => {
  dlog(`unhandled rejection: ${err}`)
})
process.on('uncaughtException', err => {
  dlog(`uncaught exception: ${err}`)
})

// --- Debug log sink: write to both stderr AND a tailable file ---
import { appendFileSync } from 'fs'
const DEBUG_LOG = join(STATE_DIR, 'server.log')
function dlog(...parts: any[]): void {
  const line = `[${new Date().toISOString()}] ${parts.map(p => typeof p === 'string' ? p : JSON.stringify(p)).join(' ')}\n`
  try {
    process.stderr.write(line)
  } catch {}
  try {
    appendFileSync(DEBUG_LOG, line)
  } catch {}
}
dlog('=== server boot ===')

// ---------------------------------------------------------------------------
// Access control state
// ---------------------------------------------------------------------------
type Policy = 'open' | 'allowlist' | 'pairing'
type GroupPolicy = 'open' | 'allowlist' | 'disabled'

interface AccessState {
  /** DM senders who can push messages. open_id values. */
  allowlist: string[]
  /** Policy for unknown DM senders. */
  dmPolicy: Policy
  /** Chats (groups) where the bot is allowed to listen. */
  groupAllowlist: string[]
  /** Group chat policy. */
  groupPolicy: GroupPolicy
  /** Require @mention in group chats. */
  requireMention: boolean
  /** Pending pair codes → sender open_id. TTL 10 min. */
  pending: Record<string, { senderId: string; createdAt: number }>
}

function defaultAccess(): AccessState {
  return {
    allowlist: [],
    dmPolicy: 'pairing',
    groupAllowlist: [],
    groupPolicy: 'disabled',
    requireMention: true,
    pending: {},
  }
}

function loadAccess(): AccessState {
  try {
    const raw = JSON.parse(readFileSync(ACCESS_FILE, 'utf8'))
    return { ...defaultAccess(), ...raw }
  } catch {
    return defaultAccess()
  }
}

function saveAccess(s: AccessState): void {
  writeFileSync(ACCESS_FILE, JSON.stringify(s, null, 2))
  try {
    chmodSync(ACCESS_FILE, 0o600)
  } catch {}
}

let access = loadAccess()

/**
 * Re-read access.json on every check. The /feishu:access skill mutates the
 * file out-of-band; we need to pick those changes up without restart.
 */
function checkAllowed(openId: string): boolean {
  access = loadAccess()
  if (access.dmPolicy === 'open') return true
  return access.allowlist.includes(openId)
}

function checkGroupAllowed(chatId: string): boolean {
  access = loadAccess()
  if (access.groupPolicy === 'disabled') return false
  if (access.groupPolicy === 'open') return true
  return access.groupAllowlist.includes(chatId)
}

function generatePairCode(): string {
  // 8 hex chars. Uppercase for phone-typing clarity.
  return randomBytes(4).toString('hex').toUpperCase()
}

function createPairing(senderId: string): string {
  access = loadAccess()
  // Prune codes older than 10 min.
  const now = Date.now()
  for (const [code, entry] of Object.entries(access.pending)) {
    if (now - entry.createdAt > 10 * 60 * 1000) delete access.pending[code]
  }
  const code = generatePairCode()
  access.pending[code] = { senderId, createdAt: now }
  saveAccess(access)
  return code
}

// ---------------------------------------------------------------------------
// Permission relay
// ---------------------------------------------------------------------------
// Format: "y abcde" / "yes abcde" / "n abcde" / "no abcde".
// ID alphabet is [a-km-z] (lowercase, skips 'l'). /i tolerates phone autocorrect.
const PERMISSION_REPLY_RE = /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i

// ---------------------------------------------------------------------------
// Lark SDK
// ---------------------------------------------------------------------------
const client = new lark.Client({
  appId: APP_ID,
  appSecret: APP_SECRET,
  domain: DOMAIN === 'lark' ? lark.Domain.Lark : lark.Domain.Feishu,
  disableTokenCache: false,
})

const wsClient = new lark.WSClient({
  appId: APP_ID,
  appSecret: APP_SECRET,
  domain: DOMAIN === 'lark' ? lark.Domain.Lark : lark.Domain.Feishu,
})

/** Probe bot identity once. Used to strip self-@mentions and skip own messages. */
let botOpenId = ''
let botAppName = ''

async function probeBotIdentity(): Promise<void> {
  // Two probes: app info (for name) + bot info (for open_id).
  try {
    const app = await client.application.application.get({
      path: { app_id: APP_ID! },
      params: { lang: 'zh_cn' },
    })
    botAppName = (app as any)?.data?.app?.app_name ?? 'bot'
  } catch {}

  try {
    // tenant scope; returns { bot: { open_id, app_name, avatar_url, ... } }
    const bot = await client.request({ url: '/open-apis/bot/v3/info', method: 'GET' })
    botOpenId = (bot as any)?.data?.bot?.open_id ?? botOpenId
    botAppName = (bot as any)?.data?.bot?.app_name ?? botAppName
  } catch (err) {
    process.stderr.write(
      `feishu channel: bot identity probe (v3/info) failed: ${String(err)}\n`
    )
  }
}

// ---------------------------------------------------------------------------
// Outbound helpers
// ---------------------------------------------------------------------------
/** Send a plain-text message to a chat (DM or group). */
async function sendText(chatId: string, text: string): Promise<string> {
  const res = await client.im.message.create({
    params: { receive_id_type: 'chat_id' },
    data: {
      receive_id: chatId,
      msg_type: 'text',
      content: JSON.stringify({ text }),
    },
  })
  return (res as any)?.data?.message_id ?? ''
}

// ---------------------------------------------------------------------------
// CardKit streaming — the heart of the "typewriter" UX
// ---------------------------------------------------------------------------
/**
 * Per-chat card state. One active card per chat; if a new user message
 * arrives before the previous card finalizes, we finalize the old one
 * first (as "abandoned") and start a fresh one.
 */
type CardState = {
  cardId: string
  userMessageId: string       // for typing reaction add/remove
  answerBuffer: string        // cumulative answer text
  timelineBuffer: string      // cumulative timeline markdown
  sequence: number            // CardKit monotonically increasing seq
  flushTimer: NodeJS.Timeout | null
  finalized: boolean
  startedAt: number
}
const activeCards = new Map<string, CardState>() // chatId → state

const STREAMING_THINKING_HEADER = '🧐 沃嫩蝶 · 思考中'
const STREAMING_RUNNING_HEADER = '⚡ 沃嫩蝶 · 执行中'
const STREAMING_DONE_HEADER = '✨ 沃嫩蝶 · 完成'
const STREAMING_ERROR_HEADER = '😵 沃嫩蝶 · 失败'

function placeholderCardJSON(): any {
  return {
    schema: '2.0',
    config: {
      streaming_mode: true, // KEY: enables cardElement.content streaming
      summary: { content: '沃嫩蝶正在处理中…' },
    },
    header: {
      title: { tag: 'plain_text', content: STREAMING_THINKING_HEADER },
      template: 'blue',
    },
    body: {
      elements: [
        {
          tag: 'markdown',
          element_id: 'answer',
          content: '',
        },
      ],
    },
  }
}

function finalCardJSON(params: {
  answer: string
  timeline: string
  elapsedMs: number
  state: 'done' | 'error'
}): any {
  const { answer, timeline, elapsedMs, state } = params
  const header = state === 'done' ? STREAMING_DONE_HEADER : STREAMING_ERROR_HEADER
  const template = state === 'done' ? 'green' : 'red'
  const elements: any[] = [
    {
      tag: 'markdown',
      element_id: 'answer',
      content: answer || '（无输出）',
    },
  ]
  if (timeline) {
    elements.push({ tag: 'hr' })
    elements.push({
      tag: 'markdown',
      element_id: 'timeline',
      content: `**💭 过程**\n${timeline}`,
    })
  }
  elements.push({ tag: 'hr' })
  elements.push({
    tag: 'note',
    elements: [
      { tag: 'plain_text', content: `⏱ ${(elapsedMs / 1000).toFixed(1)}s` },
    ],
  })
  return {
    schema: '2.0',
    config: {
      streaming_mode: false, // stop streaming on final state
      summary: { content: state === 'done' ? '已完成' : '失败' },
    },
    header: {
      title: { tag: 'plain_text', content: header },
      template,
    },
    body: { elements },
  }
}

/** Create a streaming card via CardKit, return card_id. */
async function createStreamingCard(): Promise<string | null> {
  try {
    const res: any = await (client as any).cardkit.v1.card.create({
      data: {
        type: 'card_json',
        data: JSON.stringify(placeholderCardJSON()),
      },
    })
    const cardId = res?.data?.card_id ?? res?.card_id ?? null
    dlog('cardkit card.create', { cardId, code: res?.code })
    return cardId
  } catch (err) {
    dlog('cardkit card.create FAILED', String(err))
    return null
  }
}

/** Send the card as an IM message — binds cardId to a chat. Returns im message_id. */
async function sendCardToChat(chatId: string, cardId: string): Promise<string> {
  const res: any = await client.im.message.create({
    params: { receive_id_type: 'chat_id' },
    data: {
      receive_id: chatId,
      msg_type: 'interactive',
      content: JSON.stringify({ type: 'card', data: { card_id: cardId } }),
    },
  })
  return res?.data?.message_id ?? ''
}

/** Stream cumulative content to a named element via CardKit. */
async function streamToElement(
  cardId: string,
  elementId: string,
  cumulativeContent: string,
  sequence: number
): Promise<void> {
  try {
    await (client as any).cardkit.v1.cardElement.content({
      path: { card_id: cardId, element_id: elementId },
      data: { content: cumulativeContent, sequence },
    })
  } catch (err) {
    dlog('cardkit cardElement.content FAILED', {
      elementId,
      sequence,
      err: String(err),
    })
  }
}

/** Fully replace a card (used for the final "done" state). */
async function replaceCard(
  cardId: string,
  cardJson: any,
  sequence: number
): Promise<void> {
  try {
    await (client as any).cardkit.v1.card.update({
      path: { card_id: cardId },
      data: {
        card: { type: 'card_json', data: JSON.stringify(cardJson) },
        sequence,
      },
    })
  } catch (err) {
    dlog('cardkit card.update FAILED', { sequence, err: String(err) })
  }
}

/** Add a "typing" emoji reaction to the user's message (visual ACK). */
async function addTypingReaction(messageId: string): Promise<string | null> {
  try {
    const res: any = await client.im.messageReaction.create({
      path: { message_id: messageId },
      data: { reaction_type: { emoji_type: 'Typing' } },
    })
    return res?.data?.reaction_id ?? null
  } catch (err) {
    dlog('messageReaction.create(Typing) FAILED', String(err))
    return null
  }
}

/** Remove the typing reaction. Best-effort. */
async function removeTypingReaction(
  messageId: string,
  reactionId: string | null
): Promise<void> {
  if (!reactionId) return
  try {
    await client.im.messageReaction.delete({
      path: { message_id: messageId, reaction_id: reactionId },
    })
  } catch (err) {
    dlog('messageReaction.delete FAILED', String(err))
  }
}

/**
 * Ensure an active card exists for this chat. Creates one if missing.
 * Returns state object.
 */
async function ensureCard(
  chatId: string,
  userMessageId: string
): Promise<CardState | null> {
  const existing = activeCards.get(chatId)
  if (existing && !existing.finalized) return existing

  const cardId = await createStreamingCard()
  if (!cardId) return null
  await sendCardToChat(chatId, cardId)
  const state: CardState = {
    cardId,
    userMessageId,
    answerBuffer: '',
    timelineBuffer: '',
    sequence: 1,
    flushTimer: null,
    finalized: false,
    startedAt: Date.now(),
  }
  activeCards.set(chatId, state)
  return state
}

/**
 * Schedule a flush of both answer + timeline to the card (200ms debounce).
 * If already scheduled, coalesce.
 */
function scheduleFlush(chatId: string): void {
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  if (state.flushTimer) return
  state.flushTimer = setTimeout(() => {
    state.flushTimer = null
    flushCard(chatId).catch(err => dlog('flushCard err', String(err)))
  }, 200)
}

async function flushCard(chatId: string): Promise<void> {
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  const seq1 = state.sequence++
  const seq2 = state.sequence++
  await streamToElement(state.cardId, 'answer', state.answerBuffer || '_思考中…_', seq1)
  if (state.timelineBuffer) {
    await streamToElement(state.cardId, 'timeline', state.timelineBuffer, seq2)
  }
}

async function finalizeCard(
  chatId: string,
  status: 'done' | 'error' = 'done'
): Promise<void> {
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  state.finalized = true
  if (state.flushTimer) {
    clearTimeout(state.flushTimer)
    state.flushTimer = null
  }
  const seq = state.sequence++
  const cardJson = finalCardJSON({
    answer: state.answerBuffer,
    timeline: state.timelineBuffer,
    elapsedMs: Date.now() - state.startedAt,
    state: status,
  })
  await replaceCard(state.cardId, cardJson, seq)
  activeCards.delete(chatId)
}

/**
 * Send an interactive card with yes/no buttons for permission prompts.
 * Falls back to text on error.
 */
async function sendPermissionCard(
  chatId: string,
  tool: string,
  description: string,
  inputPreview: string,
  requestId: string
): Promise<void> {
  const card = {
    config: { wide_screen_mode: true, update_multi: true },
    header: {
      title: { tag: 'plain_text', content: `🔐 Claude 请求执行 ${tool}` },
      template: 'orange',
    },
    elements: [
      {
        tag: 'div',
        text: {
          tag: 'lark_md',
          content: `**操作**：${description}\n\n**参数预览**：\n\`\`\`\n${inputPreview.slice(0, 800)}\n\`\`\``,
        },
      },
      {
        tag: 'note',
        elements: [
          {
            tag: 'plain_text',
            content: `Request ID: ${requestId} — 或回复 "yes ${requestId}" / "no ${requestId}"`,
          },
        ],
      },
      {
        tag: 'action',
        actions: [
          {
            tag: 'button',
            text: { tag: 'plain_text', content: '✅ 批准' },
            type: 'primary',
            value: { verdict: 'allow', request_id: requestId },
          },
          {
            tag: 'button',
            text: { tag: 'plain_text', content: '❌ 拒绝' },
            type: 'danger',
            value: { verdict: 'deny', request_id: requestId },
          },
        ],
      },
    ],
  }
  try {
    await client.im.message.create({
      params: { receive_id_type: 'chat_id' },
      data: {
        receive_id: chatId,
        msg_type: 'interactive',
        content: JSON.stringify(card),
      },
    })
  } catch (err) {
    // Fallback to plain text if card fails.
    await sendText(
      chatId,
      `🔐 Claude 想执行 ${tool}: ${description}\n\n回复 "yes ${requestId}" 或 "no ${requestId}"`
    )
  }
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------
const mcp = new Server(
  { name: 'feishu', version: '0.0.1' },
  {
    capabilities: {
      experimental: {
        'claude/channel': {},
        'claude/channel/permission': {},
      },
      tools: {},
    },
    instructions:
      'Messages from Feishu arrive as <channel source="feishu" chat_id="..." sender_id="..." ' +
      'sender_name="..." message_type="dm|group">. Reply with the "reply" tool, passing ' +
      'the chat_id from the tag. Use markdown formatting freely — it renders in Feishu cards. ' +
      'For long replies, feel free to split into multiple reply tool calls.',
  }
)

// reply tool — Claude → Feishu outbound
mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'reply',
      description:
        '**PREFERRED way to reply to Feishu messages.** When a message arrived via ' +
        '<channel source="feishu"> and you want to respond, ALWAYS use this tool — ' +
        'NOT im.v1.message.create or any lark-mcp messaging tool. This tool streams ' +
        'your text into a pre-created card with a native typewriter animation, shows ' +
        'progress/completion states (🧐→⚡→✨), and manages the conversation UX. ' +
        'Supports lark_md markdown (headings, bold, italic, code blocks, lists, links).',
      inputSchema: {
        type: 'object',
        properties: {
          chat_id: {
            type: 'string',
            description: 'The Feishu chat_id from the inbound <channel> tag (required).',
          },
          text: {
            type: 'string',
            description:
              'Your final reply. Markdown supported (lark_md flavor). ' +
              'Can be long — the card handles rendering.',
          },
        },
        required: ['chat_id', 'text'],
      },
    },
  ],
}))

mcp.setRequestHandler(CallToolRequestSchema, async req => {
  if (req.params.name === 'reply') {
    const { chat_id, text } = req.params.arguments as {
      chat_id: string
      text: string
    }
    dlog('=== reply tool called ===', {
      chat_id,
      text_len: text?.length ?? 0,
      has_active_card: activeCards.has(chat_id),
    })
    try {
      const state = activeCards.get(chat_id)
      if (state && !state.finalized) {
        // Stream final answer into the already-created card.
        dlog('streaming reply into active card', { cardId: state.cardId })
        state.answerBuffer = text
        await flushCard(chat_id)
        await finalizeCard(chat_id, 'done')
        dlog('card finalized')
        // Remove typing reaction (best-effort; reaction_id tracked per chat).
        const reactionId = typingReactionsByChat.get(chat_id) ?? null
        if (reactionId && state.userMessageId) {
          await removeTypingReaction(state.userMessageId, reactionId)
          typingReactionsByChat.delete(chat_id)
        }
        return { content: [{ type: 'text', text: `sent (card finalized)` }] }
      }
      // Fallback: no active card, send as plain text.
      const msgId = await sendText(chat_id, text)
      return {
        content: [{ type: 'text', text: `sent (message_id=${msgId})` }],
      }
    } catch (err) {
      return {
        content: [
          { type: 'text', text: `feishu send failed: ${String(err)}` },
        ],
        isError: true,
      }
    }
  }
  throw new Error(`unknown tool: ${req.params.name}`)
})

/** Per-chat typing reaction IDs, so we can remove them on reply. */
const typingReactionsByChat = new Map<string, string>()

// Permission relay: Claude Code → Feishu (card prompt)
const PermissionRequestSchema = z.object({
  method: z.literal('notifications/claude/channel/permission_request'),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
})

/** Track which chat a pending request belongs to, so we know where to post the card. */
const pendingPermissionChat = new Map<string, string>()
/** Most recent approved sender's "home" chat — used as default destination. */
let defaultHomeChat = ''

mcp.setNotificationHandler(PermissionRequestSchema, async ({ params }) => {
  const chat = pendingPermissionChat.get(params.request_id) ?? defaultHomeChat
  if (!chat) {
    process.stderr.write(
      `feishu channel: permission request ${params.request_id} has no target chat\n`
    )
    return
  }
  await sendPermissionCard(
    chat,
    params.tool_name,
    params.description,
    params.input_preview,
    params.request_id
  )
})

// Periodic cleanup of stale permission chat mappings.
setInterval(() => {
  // No-op placeholder; Claude Code drops resolved requests on its side.
}, 60_000)

// ---------------------------------------------------------------------------
// Inbound event handler
// ---------------------------------------------------------------------------
const eventDispatcher = new lark.EventDispatcher({}).register({
  'im.message.receive_v1': async (event: any) => {
    dlog('<<< im.message.receive_v1', {
      chat_id: event?.message?.chat_id,
      chat_type: event?.message?.chat_type,
      msg_type: event?.message?.message_type,
      sender_open_id: event?.sender?.sender_id?.open_id,
    })
    try {
      const msg = event?.message
      const sender = event?.sender
      if (!msg || !sender) { dlog('skip: no msg/sender'); return }

      const chatId: string = msg.chat_id ?? ''
      const chatType: string = msg.chat_type ?? '' // 'p2p' | 'group'
      const senderId: string = sender.sender_id?.open_id ?? ''
      const messageType: string = msg.message_type ?? ''

      // Skip messages from self (bot-to-bot loops).
      if (botOpenId && senderId === botOpenId) return

      // Only handle text messages for now. (Cards / posts / files = future work.)
      if (messageType !== 'text') return

      let text = ''
      try {
        text = JSON.parse(msg.content ?? '{}').text ?? ''
      } catch {
        return
      }
      text = text.trim()
      if (!text) return

      // In groups, strip @bot mention.
      if (chatType === 'group') {
        // mentions array is on the message object in Feishu SDK
        const mentions: any[] = msg.mentions ?? []
        const mentionsBot = mentions.some(
          m => m?.id?.open_id === botOpenId || m?.key === `@_user_${botAppName}`
        )
        if (access.requireMention && !mentionsBot) return
        // Remove @bot text
        text = text.replace(/@_user_\d+\s*/g, '').replace(/@\S+\s*/g, '').trim()
        if (!checkGroupAllowed(chatId)) return
      } else if (chatType === 'p2p') {
        // ---- Pairing path ----
        const allowed = checkAllowed(senderId)
        dlog('p2p allowed check', { senderId, allowed, dmPolicy: access.dmPolicy })
        if (!allowed) {
          if (access.dmPolicy === 'pairing') {
            const code = createPairing(senderId)
            dlog('created pairing code', { code, senderId })
            await sendText(
              chatId,
              `👋 ${botAppName}: access not configured.\n` +
                `Your Feishu user id: ${senderId}\n\n` +
                `Pairing code:\n${code}\n\n` +
                `Ask the bot owner to approve with:\n` +
                `  /feishu:access pair ${code}`
            )
          }
          return
        }
      } else {
        // topic / unknown — drop
        return
      }

      // ---- Permission verdict fast path ----
      const verdict = PERMISSION_REPLY_RE.exec(text)
      if (verdict) {
        const requestId = verdict[2].toLowerCase()
        const behavior = verdict[1].toLowerCase().startsWith('y') ? 'allow' : 'deny'
        await mcp.notification({
          method: 'notifications/claude/channel/permission',
          params: { request_id: requestId, behavior },
        })
        await sendText(chatId, `verdict recorded: ${behavior} (${requestId})`)
        pendingPermissionChat.delete(requestId)
        return
      }

      // ---- Remember this chat for future permission prompts ----
      defaultHomeChat = chatId
      // Any outstanding permission_request without a mapped chat: assign this one.
      // Best-effort; permission_request arrives asynchronously from Claude Code.

      // ---- UX: acknowledge with typing reaction + placeholder card ----
      const userMsgId: string = msg.message_id ?? ''
      if (userMsgId) {
        // Finalize any previous lingering card (abandoned convo).
        if (activeCards.has(chatId)) {
          await finalizeCard(chatId, 'done')
        }
        // Typing emoji reaction on user's msg (visual ACK).
        const reactionId = await addTypingReaction(userMsgId)
        if (reactionId) typingReactionsByChat.set(chatId, reactionId)
        // Create streaming placeholder card — answer element will typewriter in.
        await ensureCard(chatId, userMsgId)
      }

      // ---- Forward to Claude as channel event ----
      dlog('>>> emitting notifications/claude/channel', { chatId, text_prefix: text.slice(0, 40) })
      await mcp.notification({
        method: 'notifications/claude/channel',
        params: {
          content: text,
          meta: {
            chat_id: chatId,
            sender_id: senderId,
            sender_name: sender.sender_id?.user_id ?? '',
            message_type: chatType === 'p2p' ? 'dm' : 'group',
            chat_type: chatType,
          },
        },
      })
      dlog('<<< notification emitted ok')
    } catch (err) {
      dlog('inbound handler error', String(err))
    }
  },
  // Card button callback → permission verdict
  'card.action.trigger': async (event: any) => {
    try {
      const value = event?.action?.value ?? {}
      if (value?.verdict && value?.request_id) {
        await mcp.notification({
          method: 'notifications/claude/channel/permission',
          params: {
            request_id: String(value.request_id),
            behavior: value.verdict === 'allow' ? 'allow' : 'deny',
          },
        })
        pendingPermissionChat.delete(String(value.request_id))
        return {
          toast: {
            type: 'success',
            content: value.verdict === 'allow' ? '已批准' : '已拒绝',
          },
        }
      }
    } catch (err) {
      process.stderr.write(`feishu channel: card action error: ${String(err)}\n`)
    }
  },
})

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function main() {
  await probeBotIdentity()
  process.stderr.write(
    `feishu channel: bot id=${botOpenId || '(unknown)'} name="${botAppName}"\n`
  )
  await mcp.connect(new StdioServerTransport())
  // wsClient.start never resolves; don't await.
  wsClient.start({ eventDispatcher })
  process.stderr.write(`feishu channel: WebSocket client started\n`)
}

main().catch(err => {
  process.stderr.write(`feishu channel: fatal: ${String(err)}\n`)
  process.exit(1)
})
