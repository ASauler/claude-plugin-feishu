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
type TimelineEntry = {
  id: string            // tool_use_id
  tool: string          // raw tool name, e.g. "Bash", "mcp__lark__..."
  preview: string       // short args preview
  startedAt: number
  finishedAt?: number
  error?: boolean
}

type TokenUsage = {
  input: number
  output: number
  cacheRead: number
  cacheWrite: number
}

type CardState = {
  cardId: string
  userMessageId: string       // for typing reaction add/remove
  answerBuffer: string        // cumulative answer text
  timelineBuffer: string      // cumulative timeline markdown
  timelineEntries: TimelineEntry[]
  sequence: number            // CardKit monotonically increasing seq
  flushTimer: NodeJS.Timeout | null
  finalized: boolean
  startedAt: number
  answered: boolean           // reply tool has been called
  pendingFinalizeTimer: NodeJS.Timeout | null
  tokens: TokenUsage | null
  sessionId?: string          // Claude Code session_id, filled on first hook
}
const activeCards = new Map<string, CardState>() // chatId → state
const sessionChatMap = new Map<string, string>() // sessionId → chatId cache

/**
 * Map a raw Claude Code tool name to a display icon + human label.
 * MCP tools come as `mcp__<server>__<tool>`.
 */
function renderToolLabel(tool: string): { icon: string; label: string } {
  if (tool.startsWith('mcp__feishu__')) return { icon: '💬', label: tool.slice('mcp__feishu__'.length) }
  if (tool.startsWith('mcp__lark__')) {
    const rest = tool.slice('mcp__lark__'.length)
    return { icon: '📡', label: rest.replace(/_/g, '.') }
  }
  if (tool.startsWith('mcp__')) {
    const rest = tool.slice(5).replace(/__/g, ':')
    return { icon: '🔌', label: rest }
  }
  const map: Record<string, string> = {
    Bash: '🔧',
    Read: '📖',
    Write: '✍️',
    Edit: '✏️',
    MultiEdit: '✏️',
    Grep: '🔍',
    Glob: '📁',
    WebFetch: '🌐',
    WebSearch: '🔎',
    Task: '🤖',
    TodoWrite: '📋',
    NotebookEdit: '📓',
  }
  return { icon: map[tool] ?? '⚙️', label: tool }
}

/** Build a short preview of tool_input for inline display.
 *  Sanitizes markdown-special chars so long / multiline Bash commands don't
 *  leak headings, lists, or broken code fences into the card.
 */
function renderToolPreview(tool: string, input: any): string {
  if (!input || typeof input !== 'object') return ''
  const sanitize = (s: any, n = 55) => {
    const str = String(s ?? '')
      .replace(/\s+/g, ' ')               // collapse whitespace / newlines
      .replace(/[`*_#>\[\]|~]/g, '')        // strip md-special chars
      .trim()
    return str.length > n ? str.slice(0, n) + '…' : str
  }
  if (tool === 'Bash') {
    // Strip boilerplate "cd /path && " prefix so the actual command shows first.
    let cmd = String(input.command ?? '').replace(/^cd\s+\S+\s*&&\s*/, '')
    return sanitize(cmd, 55)
  }
  if (tool === 'Read') {
    const p = String(input.file_path ?? '')
    const base = p.split('/').pop() || p
    const range = input.offset ? `:${input.offset}${input.limit ? '+' + input.limit : ''}` : ''
    return sanitize(base + range, 50)
  }
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') {
    const p = String(input.file_path ?? '')
    return sanitize(p.split('/').pop() || p, 50)
  }
  if (tool === 'Grep') return sanitize(input.pattern, 50)
  if (tool === 'Glob') return sanitize(input.pattern, 50)
  if (tool === 'WebFetch' || tool === 'WebSearch') return sanitize(input.url ?? input.query, 60)
  if (tool === 'Task') return sanitize(input.description ?? input.subagent_type, 60)
  if (tool === 'TodoWrite') return `${(input.todos ?? []).length} items`
  if (tool.startsWith('mcp__')) {
    const firstKey = Object.keys(input)[0]
    if (firstKey) return sanitize(`${firstKey}=${input[firstKey]}`, 50)
  }
  return ''
}

function renderTimeline(entries: TimelineEntry[]): string {
  if (entries.length === 0) return '_等待工具调用…_'
  const rows = entries.slice(-20).map(e => {
    const { icon, label } = renderToolLabel(e.tool)
    const prev = e.preview ? ` ${e.preview}` : ''
    let trail: string
    if (e.finishedAt) {
      const dur = ((e.finishedAt - e.startedAt) / 1000).toFixed(1)
      trail = e.error ? ` · ❌ ${dur}s` : ` · ${dur}s`
    } else {
      trail = ' · _running…_'
    }
    return `${icon} ${label}${prev}${trail}`
  })
  const dropped = Math.max(0, entries.length - 20)
  return (dropped ? `_…${dropped} earlier_\n` : '') + rows.join('\n')
}

function placeholderCardJSON(): any {
  return {
    schema: '2.0',
    config: {
      streaming_mode: true, // KEY: enables cardElement.content streaming
      summary: { content: '沃嫩蝶正在处理中…' },
    },
    header: {
      title: { tag: 'plain_text', content: '🤖 沃嫩蝶' },
      template: 'blue',
    },
    body: {
      elements: [
        {
          tag: 'markdown',
          element_id: 'status',
          content: '🧐 _思考中…_',
        },
        {
          tag: 'markdown',
          element_id: 'answer',
          content: '',
        },
        {
          tag: 'collapsible_panel',
          expanded: true,
          background_style: 'grey',
          header: {
            title: { tag: 'markdown', content: '💭 **过程**' },
            vertical_align: 'center',
            icon_position: 'right',
          },
          elements: [
            {
              tag: 'markdown',
              element_id: 'timeline',
              content: '_等待工具调用…_',
            },
          ],
        },
        {
          tag: 'markdown',
          element_id: 'footer',
          content: `<font color='grey'>⏱ 0.0s</font>`,
        },
      ],
    },
  }
}

function formatTokens(n: number): string {
  if (n >= 1000) return (n / 1000).toFixed(n >= 10_000 ? 0 : 1) + 'k'
  return String(n)
}

function finalCardJSON(params: {
  answer: string
  timeline: string
  elapsedMs: number
  state: 'done' | 'error'
  tokens: TokenUsage | null
  toolCount: number
}): any {
  const { answer, timeline, elapsedMs, state, tokens, toolCount } = params
  const template = state === 'done' ? 'green' : 'red'
  const statusText = state === 'done' ? '✨ _完成_' : '😵 _失败_'
  const elements: any[] = [
    {
      tag: 'markdown',
      element_id: 'status',
      content: statusText,
    },
    {
      tag: 'markdown',
      element_id: 'answer',
      content: answer || '（无输出）',
    },
  ]
  if (toolCount > 0 && timeline && timeline !== '_等待工具调用…_') {
    elements.push({
      tag: 'collapsible_panel',
      expanded: false, // collapsed by default in final state
      background_style: 'grey',
      header: {
        title: { tag: 'markdown', content: `💭 **过程** · ${toolCount} 步` },
        vertical_align: 'center',
        icon_position: 'right',
      },
      elements: [
        {
          tag: 'markdown',
          element_id: 'timeline',
          content: timeline,
        },
      ],
    })
  }
  const footerParts = [`⏱ ${(elapsedMs / 1000).toFixed(1)}s`]
  if (tokens) {
    const cache = tokens.cacheRead + tokens.cacheWrite
    footerParts.push(
      `📊 in ${formatTokens(tokens.input)} · out ${formatTokens(tokens.output)}` +
      (cache ? ` · cache ${formatTokens(cache)}` : '')
    )
  }
  elements.push({
    tag: 'markdown',
    element_id: 'footer',
    content: `<font color='grey'>${footerParts.join(' · ')}</font>`,
  })
  return {
    schema: '2.0',
    config: {
      streaming_mode: false, // stop streaming on final state
      summary: { content: state === 'done' ? '已完成' : '失败' },
    },
    header: {
      title: { tag: 'plain_text', content: '🤖 沃嫩蝶' },
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

/** Turn streaming_mode off so a subsequent card.update will apply. */
async function setCardStreamingMode(
  cardId: string,
  enabled: boolean,
  sequence: number
): Promise<void> {
  try {
    const resp: any = await (client as any).cardkit.v1.card.settings({
      path: { card_id: cardId },
      data: {
        settings: JSON.stringify({ streaming_mode: enabled }),
        sequence,
      },
    })
    dlog('cardkit card.settings', { sequence, enabled, code: resp?.code, msg: resp?.msg })
  } catch (err) {
    dlog('cardkit card.settings FAILED', { sequence, err: String(err) })
  }
}

/** Fully replace a card (used for the final "done" state). */
async function replaceCard(
  cardId: string,
  cardJson: any,
  sequence: number
): Promise<void> {
  try {
    const resp: any = await (client as any).cardkit.v1.card.update({
      path: { card_id: cardId },
      data: {
        card: { type: 'card_json', data: JSON.stringify(cardJson) },
        sequence,
      },
    })
    dlog('cardkit card.update', { sequence, code: resp?.code, msg: resp?.msg })
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
    timelineEntries: [],
    sequence: 1,
    flushTimer: null,
    finalized: false,
    startedAt: Date.now(),
    answered: false,
    pendingFinalizeTimer: null,
    tokens: null,
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
  // Rebuild timeline from entries (single source of truth).
  state.timelineBuffer = renderTimeline(state.timelineEntries)
  const toolCount = state.timelineEntries.length
  const runningCount = state.timelineEntries.filter(e => !e.finishedAt).length
  const statusText = state.answered
    ? '✨ _回复就绪_'
    : toolCount > 0
      ? `⚡ _执行中 · ${toolCount} 步${runningCount ? ' · ' + runningCount + ' 运行中' : ''}_`
      : '🧐 _思考中…_'
  const elapsed = ((Date.now() - state.startedAt) / 1000).toFixed(1)
  const footerText = `<font color='grey'>⏱ ${elapsed}s</font>`

  const seqStatus = state.sequence++
  const seqTimeline = state.sequence++
  const seqAnswer = state.sequence++
  const seqFooter = state.sequence++

  await streamToElement(state.cardId, 'status', statusText, seqStatus)
  await streamToElement(state.cardId, 'timeline', state.timelineBuffer, seqTimeline)
  await streamToElement(state.cardId, 'answer', state.answerBuffer || '', seqAnswer)
  await streamToElement(state.cardId, 'footer', footerText, seqFooter)
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
  if (state.pendingFinalizeTimer) {
    clearTimeout(state.pendingFinalizeTimer)
    state.pendingFinalizeTimer = null
  }
  // Disable streaming mode FIRST so the subsequent card.update takes effect
  // (otherwise the streaming layer keeps the old header/template alive).
  await setCardStreamingMode(state.cardId, false, state.sequence++)
  const cardJson = finalCardJSON({
    answer: state.answerBuffer,
    timeline: renderTimeline(state.timelineEntries),
    elapsedMs: Date.now() - state.startedAt,
    state: status,
    tokens: state.tokens,
    toolCount: state.timelineEntries.length,
  })
  await replaceCard(state.cardId, cardJson, state.sequence++)
  // Release correlation map entry
  if (state.sessionId) sessionChatMap.delete(state.sessionId)
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
        // Stream the answer into the card immediately, but delay finalization:
        // we want the Stop hook to deliver token usage first. Fall back after 3s
        // in case Stop never arrives.
        dlog('streaming reply into active card', { cardId: state.cardId })
        state.answerBuffer = text
        state.answered = true
        await flushCard(chat_id)
        // Remove typing reaction now — answer is visible.
        const reactionId = typingReactionsByChat.get(chat_id) ?? null
        if (reactionId && state.userMessageId) {
          await removeTypingReaction(state.userMessageId, reactionId)
          typingReactionsByChat.delete(chat_id)
        }
        if (state.pendingFinalizeTimer) clearTimeout(state.pendingFinalizeTimer)
        state.pendingFinalizeTimer = setTimeout(() => {
          dlog('reply: fallback finalize (no Stop hook in 3s)')
          finalizeCard(chat_id, 'done').catch(err => dlog('fallback finalize err', String(err)))
        }, 3000)
        return { content: [{ type: 'text', text: `sent (awaiting Stop)` }] }
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
// Hook relay — local HTTP server on loopback. The plugin's shell hooks
// (hooks/relay.sh) pipe their stdin JSON here. Discovers chat via transcript.
// ---------------------------------------------------------------------------
const HOOK_PORT_FILE = join(STATE_DIR, 'hook.port')

/**
 * Find the most recent Feishu chat_id referenced in the transcript.
 * Reads last ~200KB of file and regexes. Caches by session_id.
 */
async function correlateSession(sessionId: string, transcriptPath: string): Promise<string | null> {
  const cached = sessionChatMap.get(sessionId)
  if (cached) return cached
  try {
    const fh = Bun.file(transcriptPath)
    const size = fh.size
    if (!size) return null
    const tailStart = Math.max(0, size - 200 * 1024)
    const slice = fh.slice(tailStart, size)
    const text = await slice.text()
    // Match meta.chat_id from channel notifications in transcript JSONL.
    const re = /"chat_id":"(oc_[A-Za-z0-9]+)"/g
    let last: string | null = null
    for (const m of text.matchAll(re)) last = m[1]
    if (last) {
      sessionChatMap.set(sessionId, last)
      return last
    }
  } catch (err) {
    dlog('correlateSession failed', String(err))
  }
  return null
}

/**
 * Parse the last assistant message's usage from a transcript JSONL.
 */
async function parseTokenUsage(transcriptPath: string): Promise<TokenUsage | null> {
  try {
    const fh = Bun.file(transcriptPath)
    const size = fh.size
    if (!size) return null
    const tailStart = Math.max(0, size - 300 * 1024)
    const slice = fh.slice(tailStart, size)
    const text = await slice.text()
    const lines = text.split('\n').filter(Boolean)
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const obj = JSON.parse(lines[i])
        // Multiple possible shapes: {type:"assistant", message:{usage:...}}
        // or {message:{usage:...}} or direct {usage:...}.
        const usage =
          obj?.message?.usage ??
          obj?.usage ??
          null
        if (usage && (usage.input_tokens !== undefined || usage.output_tokens !== undefined)) {
          return {
            input: usage.input_tokens ?? 0,
            output: usage.output_tokens ?? 0,
            cacheRead: usage.cache_read_input_tokens ?? 0,
            cacheWrite: usage.cache_creation_input_tokens ?? 0,
          }
        }
      } catch {}
    }
  } catch (err) {
    dlog('parseTokenUsage failed', String(err))
  }
  return null
}

async function onPreToolUse(payload: any): Promise<void> {
  const { session_id, transcript_path, tool_name, tool_use_id, tool_input } = payload
  if (!session_id || !transcript_path) return
  // Skip our own reply tool — it IS the answer, showing it in timeline is noise.
  if (tool_name === 'mcp__feishu__reply') return
  const chatId = await correlateSession(session_id, transcript_path)
  if (!chatId) return
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  state.sessionId = session_id
  state.timelineEntries.push({
    id: tool_use_id ?? `${Date.now()}`,
    tool: tool_name ?? '?',
    preview: renderToolPreview(tool_name, tool_input),
    startedAt: Date.now(),
  })
  scheduleFlush(chatId)
}

async function onPostToolUse(payload: any): Promise<void> {
  const { session_id, transcript_path, tool_name, tool_use_id, tool_response } = payload
  if (!session_id || !transcript_path) return
  if (tool_name === 'mcp__feishu__reply') return
  const chatId = await correlateSession(session_id, transcript_path)
  if (!chatId) return
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  const entry = state.timelineEntries.find(e => e.id === tool_use_id)
  if (entry) {
    entry.finishedAt = Date.now()
    entry.error = Boolean(tool_response?.isError ?? tool_response?.is_error)
  }
  scheduleFlush(chatId)
}

async function onStop(payload: any): Promise<void> {
  const { session_id, transcript_path } = payload
  if (!session_id || !transcript_path) return
  const chatId = await correlateSession(session_id, transcript_path)
  if (!chatId) return
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  const tokens = await parseTokenUsage(transcript_path)
  if (tokens) state.tokens = tokens
  // Only finalize if reply already arrived. If not, Claude may still be working
  // on a multi-step response — don't kill the card prematurely.
  if (state.answered) {
    await finalizeCard(chatId, 'done')
  }
}

function startHookServer(): void {
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0, // ephemeral
    async fetch(req) {
      if (req.method !== 'POST') return new Response('POST only', { status: 405 })
      let body: any
      try {
        body = await req.json()
      } catch {
        return new Response('bad json', { status: 400 })
      }
      const event = body?.hook_event_name
      dlog('hook event', { event, tool: body?.tool_name })
      try {
        if (event === 'PreToolUse') await onPreToolUse(body)
        else if (event === 'PostToolUse') await onPostToolUse(body)
        else if (event === 'Stop') await onStop(body)
      } catch (err) {
        dlog('hook handler err', String(err))
      }
      return new Response('{}', { headers: { 'content-type': 'application/json' } })
    },
  })
  try {
    writeFileSync(HOOK_PORT_FILE, String(server.port))
    chmodSync(HOOK_PORT_FILE, 0o600)
  } catch {}
  dlog('hook HTTP server listening', { port: server.port })
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function main() {
  await probeBotIdentity()
  process.stderr.write(
    `feishu channel: bot id=${botOpenId || '(unknown)'} name="${botAppName}"\n`
  )
  startHookServer()
  await mcp.connect(new StdioServerTransport())
  // wsClient.start never resolves; don't await.
  wsClient.start({ eventDispatcher })
  process.stderr.write(`feishu channel: WebSocket client started\n`)
}

main().catch(err => {
  process.stderr.write(`feishu channel: fatal: ${String(err)}\n`)
  process.exit(1)
})
