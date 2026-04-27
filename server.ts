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
const SCOPES_DIR = join(STATE_DIR, 'scopes')

mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 })
mkdirSync(SCOPES_DIR, { recursive: true, mode: 0o700 })

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
process.on('uncaughtException', (err: any) => {
  // EPIPE on stdio = Claude Code TUI has died/restarted. Plugin can't reach
  // its host anymore. Exit cleanly so the TUI can re-spawn us next time.
  if (err?.code === 'EPIPE' || /EPIPE|ECONNRESET/.test(String(err))) {
    dlog(`stdio pipe broken (host gone), exiting`)
    process.exit(0)
  }
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
type GroupSessionScope = 'group' | 'group_sender' | 'group_topic' | 'group_topic_sender'

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
  /**
   * Default session-scope granularity for groups. A message inside a Feishu
   * topic thread automatically upgrades to the topic-aware variant
   * (group → group_topic, group_sender → group_topic_sender).
   */
  groupSessionScope: GroupSessionScope
  /** How many recent turns to replay in each scope's context prefix. */
  historyPerScope: number
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
    groupSessionScope: 'group',
    historyPerScope: 10,
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
// Conversation scope — per-(chat/sender/topic) workspace with its own
// CLAUDE.md (instructions), memory.md (persistent facts), history.jsonl.
// Completely isolated from user's global ~/.claude/CLAUDE.md.
// ---------------------------------------------------------------------------
type ScopeMeta = {
  chatType: 'p2p' | 'group' | 'private'
  chatId: string
  chatName?: string
  senderId: string
  senderName?: string
  topicId?: string
}

type ResolvedScope = {
  key: string             // human-readable ID, used in conversation_id
  dir: string             // absolute path to scope folder
  effectiveScope: GroupSessionScope | 'dm'
  parentDirs: string[]    // parent scope dirs, closest first (for inheritance seed)
}

/** Sanitize an ID for safe filesystem use (just paranoia — Feishu IDs are alnum+_). */
function sanitizeId(s: string): string {
  return s.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64)
}

/**
 * Resolve the scope directory + key for an inbound message.
 * Auto-upgrades group→group_topic when a Feishu thread_id is present.
 */
function resolveScope(meta: ScopeMeta): ResolvedScope {
  if (meta.chatType === 'p2p') {
    const senderFrag = sanitizeId(meta.senderId)
    const key = `dm/${senderFrag}`
    return { key, dir: join(SCOPES_DIR, 'dm', senderFrag), effectiveScope: 'dm', parentDirs: [] }
  }
  // Group: apply configured scope, auto-upgrade when topic present.
  let scope: GroupSessionScope = access.groupSessionScope
  if (meta.topicId) {
    if (scope === 'group') scope = 'group_topic'
    else if (scope === 'group_sender') scope = 'group_topic_sender'
  }
  const chatFrag = sanitizeId(meta.chatId)
  const senderFrag = sanitizeId(meta.senderId)
  const topicFrag = meta.topicId ? sanitizeId(meta.topicId) : ''
  const groupRel = `group/${chatFrag}`
  const topicRel = topicFrag ? `group/${chatFrag}/topic/${topicFrag}` : ''
  let relative: string
  let parents: string[] = []
  switch (scope) {
    case 'group':
      relative = groupRel
      break
    case 'group_sender':
      relative = `group/${chatFrag}/sender/${senderFrag}`
      parents = [groupRel]
      break
    case 'group_topic':
      relative = topicRel
      parents = [groupRel]
      break
    case 'group_topic_sender':
      relative = `group/${chatFrag}/topic/${topicFrag}/sender/${senderFrag}`
      parents = [topicRel, groupRel]
      break
  }
  return {
    key: relative,
    dir: join(SCOPES_DIR, relative),
    effectiveScope: scope,
    parentDirs: parents.map(p => join(SCOPES_DIR, p)),
  }
}

function scopeClaudeMdDefault(meta: ScopeMeta, scope: ResolvedScope): string {
  if (scope.effectiveScope === 'dm') {
    const who = meta.senderName ? ` (${meta.senderName})` : ''
    return `# Feishu DM scope${who}

You are **沃嫩蝶**, replying to **${meta.senderName || 'a user'}** via Feishu direct message.
- Markdown (lark_md dialect) is supported — use freely.
- Always use the \`reply\` tool to respond; never use other messaging tools.
- Use the \`remember\` tool to persist durable facts about this user across future sessions.

## Style
- Direct. No preambles. Conclusion first.
- Primary Chinese, technical terms in English OK.
- Keep responses compact for mobile.

<!-- You may freely edit this file; it prefixes every message in this scope. -->
`
  }
  const kind = {
    group: '整个群共用一个会话',
    group_sender: '群内每位发送人独立会话',
    group_topic: '每个飞书话题线程独立会话',
    group_topic_sender: '话题 × 发送人最细粒度独立会话',
  }[scope.effectiveScope as GroupSessionScope]
  const groupLabel = meta.chatName ? `「${meta.chatName}」` : ''
  return `# Feishu group scope · ${scope.effectiveScope}${groupLabel ? ` · ${groupLabel}` : ''}

You are **沃嫩蝶**, responding in Feishu group ${groupLabel || '(unnamed)'}.
Scope granularity: **${scope.effectiveScope}** — ${kind}.

- Multiple people may participate; when sender context switches, address them by name from the channel tag.
- Use the \`reply\` tool to respond; use \`remember\` to persist group-wide facts.
- Keep responses concise — group members won't read walls of text.

<!-- This CLAUDE.md is scoped to this group/topic/sender combo. Edit freely. -->
`
}

function ensureScopeDir(scope: ResolvedScope, meta: ScopeMeta): void {
  const isFresh = !existsSync(scope.dir)
  mkdirSync(scope.dir, { recursive: true, mode: 0o700 })
  const claudeFile = join(scope.dir, 'CLAUDE.md')
  const memoryFile = join(scope.dir, 'memory.md')
  const historyFile = join(scope.dir, 'history.jsonl')

  // CLAUDE.md is always scope-specific; never inherited.
  if (!existsSync(claudeFile)) {
    writeFileSync(claudeFile, scopeClaudeMdDefault(meta, scope))
  }

  // On first creation, seed history + memory from the closest parent scope
  // that has content. Parent's values become this child's starting point,
  // then they diverge. OpenClaw-style inheritance, done statically.
  let seededFromParent: string | null = null
  if (isFresh && scope.parentDirs.length > 0) {
    for (const parentDir of scope.parentDirs) {
      const parentHist = join(parentDir, 'history.jsonl')
      const parentMem = join(parentDir, 'memory.md')
      const histContent = existsSync(parentHist) ? readFileSync(parentHist, 'utf8') : ''
      const memContent = existsSync(parentMem) ? readFileSync(parentMem, 'utf8') : ''
      const memBullets = memContent.split('\n').filter(l => l.startsWith('- '))
      if (!histContent.trim() && memBullets.length === 0) continue
      // Seed history verbatim.
      if (histContent.trim() && !existsSync(historyFile)) {
        writeFileSync(historyFile, histContent)
      }
      // Seed memory with a clear "inherited from X" marker.
      if (memBullets.length > 0 && !existsSync(memoryFile)) {
        const parentKey = parentDir.startsWith(SCOPES_DIR)
          ? parentDir.slice(SCOPES_DIR.length + 1)
          : parentDir
        writeFileSync(
          memoryFile,
          `# Memory — ${scope.key}\n\n<!-- seeded on first use from parent scope: ${parentKey} -->\n${memBullets.join('\n')}\n`
        )
      }
      seededFromParent = parentDir
      break
    }
  }
  if (seededFromParent) {
    dlog('scope seeded from parent', { child: scope.key, parent: seededFromParent })
  }

  // Default skeletons for anything still missing.
  if (!existsSync(memoryFile)) {
    writeFileSync(memoryFile, `# Memory — ${scope.key}\n\n<!-- append-only, timestamped notes learned across sessions -->\n`)
  }
  if (!existsSync(historyFile)) {
    writeFileSync(historyFile, '')
  }
}

type HistoryTurn = { role: 'user' | 'assistant'; text: string; ts: number; senderName?: string }

function readScopeContext(scope: ResolvedScope, turnLimit: number): {
  instructions: string
  memory: string
  history: HistoryTurn[]
} {
  const read = (p: string, cap = 8 * 1024) => {
    try { return readFileSync(p, 'utf8').slice(-cap) } catch { return '' }
  }
  const instructions = read(join(scope.dir, 'CLAUDE.md'), 4 * 1024)
  const memory = read(join(scope.dir, 'memory.md'), 8 * 1024)
  const historyRaw = read(join(scope.dir, 'history.jsonl'), 32 * 1024)
  const turns: HistoryTurn[] = []
  for (const line of historyRaw.split('\n')) {
    if (!line.trim()) continue
    try {
      const t = JSON.parse(line) as HistoryTurn
      if (t?.role && typeof t.text === 'string') turns.push(t)
    } catch {}
  }
  return { instructions, memory, history: turns.slice(-turnLimit * 2) }
}

function appendScopeHistory(scope: ResolvedScope, turn: HistoryTurn): void {
  try {
    appendFileSync(join(scope.dir, 'history.jsonl'), JSON.stringify(turn) + '\n')
  } catch (err) {
    dlog('appendScopeHistory failed', String(err))
  }
}

function appendScopeMemory(scope: ResolvedScope, note: string): void {
  try {
    const line = `- [${new Date().toISOString()}] ${note.replace(/\s+/g, ' ').trim()}\n`
    appendFileSync(join(scope.dir, 'memory.md'), line)
  } catch (err) {
    dlog('appendScopeMemory failed', String(err))
  }
}

/**
 * Build the enriched channel-notification content: scope instructions +
 * memory tail + recent history + the current user message.
 */
function buildScopedContent(
  scope: ResolvedScope,
  meta: ScopeMeta,
  currentMessage: string,
  ctx: { instructions: string; memory: string; history: HistoryTurn[] }
): string {
  const parts: string[] = []
  // Short header so Claude always has the human-readable who/where.
  const contextLines = [
    `· 会话类型: ${meta.chatType === 'p2p' ? '私聊' : '群聊'}`,
    meta.chatName ? `· 群名: ${meta.chatName}` : '',
    meta.senderName ? `· 发送人: ${meta.senderName}` : '',
    meta.topicId ? `· 话题线程: ${meta.topicId}` : '',
    `· scope: ${scope.key}`,
  ].filter(Boolean)
  parts.push('## Context')
  parts.push(contextLines.join('\n'))
  if (ctx.instructions.trim()) {
    parts.push('## Scope instructions')
    parts.push(ctx.instructions.trim())
  }
  if (ctx.memory.trim() && ctx.memory.split('\n').filter(l => l.startsWith('- ')).length > 0) {
    parts.push('## Memory')
    parts.push(ctx.memory.trim())
  }
  if (ctx.history.length > 0) {
    parts.push('## Recent conversation')
    for (const t of ctx.history) {
      const who = t.role === 'user'
        ? (t.senderName ? t.senderName : '用户')
        : '沃嫩蝶'
      parts.push(`**${who}**: ${t.text.trim()}`)
    }
  }
  parts.push('## Current message')
  parts.push(currentMessage.trim())
  return parts.join('\n\n')
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

function makeWSClient(): lark.WSClient {
  return new lark.WSClient({
    appId: APP_ID!,
    appSecret: APP_SECRET!,
    domain: DOMAIN === 'lark' ? lark.Domain.Lark : lark.Domain.Feishu,
  })
}
let wsClient: lark.WSClient = makeWSClient()

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
// Name resolution — turn raw open_id / chat_id into human-readable names.
// Results cached in-process; TTL effectively "until restart" (fine for a bot
// that restarts on every plugin reload).
// ---------------------------------------------------------------------------
const senderNameCache = new Map<string, string>() // open_id → display name
const chatNameCache = new Map<string, string>()   // chat_id → chat name

async function resolveSenderName(openId: string): Promise<string> {
  if (!openId) return ''
  const cached = senderNameCache.get(openId)
  if (cached) return cached
  try {
    const res: any = await (client as any).contact.v3.user.get({
      path: { user_id: openId },
      params: { user_id_type: 'open_id' },
    })
    const name = res?.data?.user?.name ?? openId
    senderNameCache.set(openId, name)
    return name
  } catch (err) {
    dlog('resolveSenderName failed', { openId, err: String(err) })
    senderNameCache.set(openId, openId) // cache the failure so we don't retry
    return openId
  }
}

async function resolveChatName(chatId: string): Promise<string> {
  if (!chatId) return ''
  const cached = chatNameCache.get(chatId)
  if (cached) return cached
  try {
    const res: any = await (client as any).im.v1.chat.get({
      path: { chat_id: chatId },
    })
    const name = res?.data?.name ?? chatId
    chatNameCache.set(chatId, name)
    return name
  } catch (err) {
    dlog('resolveChatName failed', { chatId, err: String(err) })
    chatNameCache.set(chatId, chatId)
    return chatId
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
  outputSummary?: string // short result summary (set on PostToolUse)
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
  scopeDir?: string           // scope folder to write history back on reply
  scopeKey?: string           // conversation_id
  userText?: string           // inbound message text (for history)
  senderName?: string         // for history formatting
  userActions?: ReplyAction[] // Claude-provided buttons to render on finalize
  lastSent?: Record<string, string> // element_id → last content; used to skip no-op stream updates
}

type ReplyAction = {
  label: string
  value: string
  style?: 'primary' | 'danger' | 'default'
}
const activeCards = new Map<string, CardState>() // chatId → state
const sessionChatMap = new Map<string, string>() // sessionId → chatId cache

/**
 * Snapshot of a finalized card that still has live buttons.
 * Kept so we can rebuild the card (minus buttons, plus a "已选择" line) when
 * the user taps one.
 */
type FinalizedCardSnapshot = {
  cardId: string
  sequence: number
  answer: string
  timeline: string
  elapsedMs: number
  state: 'done' | 'error'
  tokens: TokenUsage | null
  toolCount: number
  chatId: string
}
const lastFinalizedCard = new Map<string, FinalizedCardSnapshot>() // chatId → snapshot

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

/** Bucket a tool into a display category (icon + short chinese label). */
function toolCategory(tool: string): { key: string; icon: string } {
  if (tool === 'Read' || tool === 'Grep' || tool === 'Glob') return { key: 'explore', icon: '📖' }
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit' || tool === 'NotebookEdit') return { key: 'edit', icon: '✏️' }
  if (tool === 'Bash') return { key: 'shell', icon: '🔧' }
  if (tool === 'WebFetch' || tool === 'WebSearch') return { key: 'web', icon: '🌐' }
  if (tool === 'Task') return { key: 'task', icon: '🤖' }
  if (tool === 'TodoWrite') return { key: 'todo', icon: '📋' }
  if (tool.startsWith('mcp__lark__') || tool.startsWith('mcp__feishu__')) return { key: 'lark', icon: '📡' }
  if (tool.startsWith('mcp__')) return { key: 'mcp', icon: '🔌' }
  return { key: 'other', icon: '⚙️' }
}

/** Category display order — keep consistent across rerenders. */
const CATEGORY_ORDER = ['explore', 'edit', 'shell', 'web', 'lark', 'task', 'todo', 'mcp', 'other']

/** Compute a short, one-line summary of a tool_response for timeline display. */
function summarizeToolOutput(tool: string, response: any): string {
  if (!response) return ''
  const clip = (s: any, n = 36) => {
    const str = String(s ?? '').replace(/\s+/g, ' ').replace(/[`*_#>\[\]|~]/g, '').trim()
    return str.length > n ? str.slice(0, n) + '…' : str
  }
  // Normalize various shapes: raw string, { content: [...] }, { output, stdout }, etc.
  const asText = (v: any): string => {
    if (typeof v === 'string') return v
    if (Array.isArray(v)) return v.map(x => x?.text ?? x).filter(Boolean).join(' ')
    if (v?.content) return asText(v.content)
    if (v?.text) return String(v.text)
    if (v?.stdout) return String(v.stdout)
    if (v?.output) return String(v.output)
    return ''
  }
  const text = asText(response)
  if (tool === 'Read') {
    // Read output usually includes "     1→..." line numbers. Show byte estimate.
    return text ? `${Math.round(text.length / 1024)}KB` : ''
  }
  if (tool === 'Grep') {
    // Output often looks like "path:line:match" or pure counts.
    const lines = text.split('\n').filter(Boolean)
    return lines.length ? `${lines.length} 命中` : '无命中'
  }
  if (tool === 'Glob') {
    const lines = text.split('\n').filter(Boolean)
    return `${lines.length} 文件`
  }
  if (tool === 'Bash') {
    // First non-empty line of stdout
    const first = text.split('\n').find(l => l.trim())
    return clip(first ?? '✓', 36)
  }
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') return '✓'
  if (tool === 'WebFetch' || tool === 'WebSearch') return clip(text, 36)
  if (tool === 'Task') return clip(text, 36)
  if (tool === 'TodoWrite') return '✓'
  if (tool.startsWith('mcp__')) return clip(text, 36)
  return clip(text, 28)
}

/**
 * Render the timeline as:
 *   [completed clusters one-liner]
 *   → <latest step detail>
 * Keeps the card calm when dozens of tools ran.
 */
function renderTimeline(entries: TimelineEntry[]): string {
  if (entries.length === 0) return '_等待工具调用…_'
  // Cluster completed entries (not the last in-flight one).
  const completed = entries.filter(e => e.finishedAt)
  const running = entries.find(e => !e.finishedAt)
  const last = entries[entries.length - 1]

  // Tally by category for the summary line.
  const tally: Record<string, { icon: string; count: number; errors: number }> = {}
  for (const e of completed) {
    const c = toolCategory(e.tool)
    const t = tally[c.key] ?? (tally[c.key] = { icon: c.icon, count: 0, errors: 0 })
    t.count++
    if (e.error) t.errors++
  }
  const summaryParts = CATEGORY_ORDER
    .map(k => tally[k])
    .filter(Boolean)
    .map(t => (t.errors ? `${t.icon} ${t.count}(❌${t.errors})` : `${t.icon} ${t.count}`))

  // Latest entry detail — show tool + preview + result or running state.
  const { icon } = toolCategory(last.tool)
  const prev = last.preview ? ` ${last.preview}` : ''
  let tail: string
  if (last.finishedAt) {
    const dur = ((last.finishedAt - last.startedAt) / 1000).toFixed(1)
    const out = last.outputSummary ? ` · ${last.outputSummary}` : ''
    tail = last.error ? ` · ❌ ${dur}s${out}` : ` · ${dur}s${out}`
  } else {
    tail = ' · _running…_'
  }
  const latestLine = `→ ${icon}${prev}${tail}`

  // Compose. Summary appears only if there's anything besides the latest.
  const summaryLine = summaryParts.length && (completed.length > 1 || running)
    ? `_${summaryParts.join(' · ')}_`
    : ''
  return [summaryLine, latestLine].filter(Boolean).join('\n')
}

function placeholderCardJSON(): any {
  return {
    schema: '2.0',
    config: {
      streaming_mode: true, // KEY: enables cardElement.content streaming
      summary: { content: '沃嫩蝶正在处理中…' },
    },
    header: {
      title: { tag: 'plain_text', content: '🧐 思考中' },
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
          header: {
            title: { tag: 'plain_text', content: '💭 过程' },
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
          content: `— ⏱ 0.0s`,
        },
        // 停止显示 button disabled — semantics unclear (soft cancel vs real
        // interrupt) until SIGINT behavior is verified. Re-enable once the
        // interrupt design is finalized.
        // {
        //   tag: 'button',
        //   text: { tag: 'plain_text', content: '🛑 停止显示' },
        //   type: 'text',
        //   behaviors: [
        //     { type: 'callback', value: { action: 'cancel_card' } },
        //   ],
        // },
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
  actions?: ReplyAction[]
  chatId?: string
}): any {
  const { answer, timeline, elapsedMs, state, tokens, toolCount, actions, chatId } = params
  const template = state === 'done' ? 'green' : 'red'
  const headerTitle = state === 'done' ? '✨ 完成' : '😵 失败'
  // In final state the status moves UP into the header; no body status element.
  const elements: any[] = [
    {
      tag: 'markdown',
      element_id: 'answer',
      content: answer || '（无输出）',
    },
  ]
  // Claude-provided action buttons (from reply tool's `actions` param).
  // Rendered right after the answer so the user sees the choices clearly.
  if (actions && actions.length > 0) {
    const styleMap: Record<string, string> = {
      primary: 'primary_filled',
      danger: 'danger_filled',
      default: 'default',
    }
    for (const a of actions) {
      elements.push({
        tag: 'button',
        text: { tag: 'plain_text', content: a.label },
        type: styleMap[a.style ?? 'default'] ?? 'default',
        behaviors: [
          {
            type: 'callback',
            value: {
              user_action: a.value,
              chat_id: chatId ?? '',
              label: a.label,
            },
          },
        ],
      })
    }
  }
  if (toolCount > 0 && timeline && timeline !== '_等待工具调用…_') {
    elements.push({
      tag: 'collapsible_panel',
      expanded: false, // collapsed by default in final state
      header: {
        title: { tag: 'plain_text', content: `💭 过程 · ${toolCount} 步` },
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
  // Visual separation: hr before the footer line so it reads as a footer,
  // not as another body paragraph.
  elements.push({ tag: 'hr' })
  elements.push({
    tag: 'markdown',
    element_id: 'footer',
    content: `⏱ ${(elapsedMs / 1000).toFixed(1)}s${tokens ? '  ·  📊 in ' + formatTokens(tokens.input) + ' · out ' + formatTokens(tokens.output) + (tokens.cacheRead + tokens.cacheWrite ? ' · cache ' + formatTokens(tokens.cacheRead + tokens.cacheWrite) : '') : ''}`,
  })
  return {
    schema: '2.0',
    config: {
      streaming_mode: false, // stop streaming on final state
      summary: { content: state === 'done' ? '已完成' : '失败' },
    },
    header: {
      title: { tag: 'plain_text', content: headerTitle },
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
    dlog('cardkit card.create', { cardId, code: res?.code, msg: res?.msg })
    return cardId
  } catch (err) {
    dlog('cardkit card.create FAILED', String(err))
    return null
  }
}

/** Send the card as an IM message — binds cardId to a chat. Returns im message_id.
 *  When parentMessageId is provided, uses im.v1.message.reply so the card shows
 *  as a native reply to the user's triggering message. */
async function sendCardToChat(
  chatId: string,
  cardId: string,
  parentMessageId?: string
): Promise<string> {
  const content = JSON.stringify({ type: 'card', data: { card_id: cardId } })
  try {
    if (parentMessageId) {
      const res: any = await (client.im.message as any).reply({
        path: { message_id: parentMessageId },
        data: { content, msg_type: 'interactive' },
      })
      return res?.data?.message_id ?? ''
    }
  } catch (err) {
    dlog('im.message.reply failed, falling back to create', String(err))
  }
  const res: any = await client.im.message.create({
    params: { receive_id_type: 'chat_id' },
    data: {
      receive_id: chatId,
      msg_type: 'interactive',
      content,
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
  userMessageId: string,
  scopeInfo?: { dir: string; key: string; userText: string; senderName: string }
): Promise<CardState | null> {
  const existing = activeCards.get(chatId)
  if (existing && !existing.finalized) return existing

  const cardId = await createStreamingCard()
  if (!cardId) return null
  await sendCardToChat(chatId, cardId, userMessageId || undefined)
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
    scopeDir: scopeInfo?.dir,
    scopeKey: scopeInfo?.key,
    userText: scopeInfo?.userText,
    senderName: scopeInfo?.senderName,
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
  const footerText = `— ⏱ ${elapsed}s`

  // Build update list. SKIP EMPTY content — Feishu cardElement.content
  // returns 400 on empty strings during streaming. Also skip values that
  // haven't changed since last flush to avoid burning API calls.
  state.lastSent = state.lastSent ?? {}
  const updates: Array<[string, string]> = []
  if (statusText && statusText !== state.lastSent.status) updates.push(['status', statusText])
  if (state.timelineBuffer && state.timelineBuffer !== state.lastSent.timeline) updates.push(['timeline', state.timelineBuffer])
  const ans = state.answerBuffer || ''
  if (ans && ans !== state.lastSent.answer) updates.push(['answer', ans])
  if (footerText && footerText !== state.lastSent.footer) updates.push(['footer', footerText])

  for (const [id, content] of updates) {
    const seq = state.sequence++
    await streamToElement(state.cardId, id, content, seq)
    state.lastSent[id] = content
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
    actions: state.userActions,
    chatId,
  })
  await replaceCard(state.cardId, cardJson, state.sequence++)
  // If this card carried user-actionable buttons, snapshot the state so we
  // can rebuild the card (minus buttons, plus a "已选择" line) on tap.
  if (state.userActions && state.userActions.length > 0) {
    lastFinalizedCard.set(chatId, {
      cardId: state.cardId,
      sequence: state.sequence,
      answer: state.answerBuffer,
      timeline: renderTimeline(state.timelineEntries),
      elapsedMs: Date.now() - state.startedAt,
      state: status,
      tokens: state.tokens,
      toolCount: state.timelineEntries.length,
      chatId,
    })
    dlog('finalized card snapshot saved', { chatId, cardId: state.cardId, actions: state.userActions.length })
  } else {
    dlog('finalize: no userActions, no snapshot', { chatId, hasActions: !!state.userActions })
  }
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
  // V2 schema, visually consistent with the streaming card. Threaded as a
  // reply to the streaming card's message when possible so the permission
  // prompt visually "belongs" to the conversation.
  const card = {
    schema: '2.0',
    config: {
      streaming_mode: false,
      summary: { content: `🔐 请求执行 ${tool}` },
    },
    header: {
      title: { tag: 'plain_text', content: '🔐 沃嫩蝶 · 需要批准' },
      template: 'orange',
    },
    body: {
      elements: [
        {
          tag: 'markdown',
          content: `**${tool}** — ${description}`,
        },
        {
          tag: 'collapsible_panel',
          expanded: false,
          header: {
            title: { tag: 'plain_text', content: '参数预览' },
          },
          elements: [
            {
              tag: 'markdown',
              content: '```\n' + inputPreview.slice(0, 800).replace(/```/g, '`\u200b``') + '\n```',
            },
          ],
        },
        // V2 schema: buttons are direct elements, no `action` wrapper.
        {
          tag: 'button',
          text: { tag: 'plain_text', content: '✅ 批准' },
          type: 'primary_filled',
          behaviors: [
            { type: 'callback', value: { verdict: 'allow', request_id: requestId } },
          ],
        },
        {
          tag: 'button',
          text: { tag: 'plain_text', content: '❌ 拒绝' },
          type: 'danger_filled',
          behaviors: [
            { type: 'callback', value: { verdict: 'deny', request_id: requestId } },
          ],
        },
        {
          tag: 'markdown',
          content: `_或在对话中回复 \`y ${requestId}\` / \`n ${requestId}\`_`,
        },
      ],
    },
  }
  // Thread the permission card under the current streaming card (if any) so
  // it visually belongs to the running turn.
  const activeState = activeCards.get(chatId)
  const parent = activeState ? undefined : undefined
  // NB: Feishu currently doesn't let us reply to a card-type message in a way
  // that groups threading with the user's source message — we skip parenting
  // and rely on the same chat to cluster messages.
  void parent
  try {
    const res: any = await client.im.message.create({
      params: { receive_id_type: 'chat_id' },
      data: {
        receive_id: chatId,
        msg_type: 'interactive',
        content: JSON.stringify(card),
      },
    })
    const messageId = res?.data?.message_id ?? ''
    if (messageId) {
      pendingPermissionMessages.set(requestId, { messageId, chatId })
    }
  } catch (err) {
    dlog('permission card send failed', String(err))
    await sendText(
      chatId,
      `🔐 Claude 想执行 ${tool}: ${description}\n回复 y ${requestId} 或 n ${requestId}`
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
      'sender_name="..." message_type="dm|group" conversation_id="..." [thread_id="..."]>. ' +
      'The message body is a structured prefix: "## Scope instructions" (per-scope ' +
      'CLAUDE.md), "## Memory" (accumulated facts from prior sessions), "## Recent ' +
      'conversation" (last N turns), then "## Current message" — the actual new input. ' +
      'Use conversation_id to understand which scope you are in.\n\n' +
      'Tools:\n' +
      '  • reply — ALWAYS use this (not lark_mcp) to respond. chat_id from the tag. ' +
      'Optionally pass `actions: [{label, value, style?}]` (0-4 buttons) to render ' +
      'tappable choices under your reply. When the user taps a button, you will ' +
      'receive a follow-up channel notification with `meta.message_type="button_click"` ' +
      'and `meta.button_value=<the value>`. Use that to continue the flow.\n' +
      '  • remember — persist a one-line fact into the current scope memory.md. ' +
      'Use when you learn something durable (user preference, project detail, ' +
      'decision) that would be useful in future turns of this same scope.\n' +
      '  • forget — clear scope history and/or memory when user explicitly asks ' +
      '("clear", "reset", "清空记忆", "forget everything"). Targets: history | memory | all.',
  }
)

// reply tool — Claude → Feishu outbound
// remember tool — Claude → scope memory.md (persist facts across sessions)
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
        'Supports lark_md markdown (headings, bold, italic, code blocks, lists, links). ' +
        'Optionally attach `actions` — tappable buttons shown under your reply. When the ' +
        'user taps one, you will receive a channel notification with the button\'s value, ' +
        'so you can follow up. Use actions for short choices (2-4 buttons) like "标 done / ' +
        '跳过 / 重试". Do NOT use actions for free-form input; use plain markdown reply then.',
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
          actions: {
            type: 'array',
            description:
              'Optional tappable buttons (0-4). Each button becomes a Feishu card ' +
              'button; clicking it sends you a follow-up channel notification with ' +
              'the button\'s `value` so you can continue the flow.',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string', description: 'Button text the user sees.' },
                value: { type: 'string', description: 'Opaque identifier sent back on click.' },
                style: {
                  type: 'string',
                  enum: ['primary', 'danger', 'default'],
                  description: 'Visual style. primary=blue, danger=red, default=plain.',
                },
              },
              required: ['label', 'value'],
            },
          },
        },
        required: ['chat_id', 'text'],
      },
    },
    {
      name: 'remember',
      description:
        'Persist a durable fact into the current scope\'s memory.md. Use this to ' +
        'remember things that will be useful in FUTURE turns of the same conversation ' +
        'scope (DM, group, or group-topic) — user preferences, project details, ' +
        'previously resolved decisions, etc. Do NOT use this for transient state; it ' +
        'becomes a permanent bullet in a scoped memory file that prefixes every message.',
      inputSchema: {
        type: 'object',
        properties: {
          chat_id: {
            type: 'string',
            description: 'The chat_id from the inbound <channel> tag (required).',
          },
          note: {
            type: 'string',
            description:
              'One-line fact to remember. Will be timestamped and appended to the ' +
              'scope\'s memory.md as a markdown bullet.',
          },
        },
        required: ['chat_id', 'note'],
      },
    },
    {
      name: 'forget',
      description:
        'Clear persistent state of the current scope. Use when the user explicitly ' +
        'asks to "forget", "reset", "清空记忆", "start over", "clear history" or similar. ' +
        'target="history" wipes recent-turn cache only; target="memory" wipes learned ' +
        'facts; target="all" wipes both (CLAUDE.md is never touched). After calling ' +
        'forget, you should acknowledge to the user what was cleared.',
      inputSchema: {
        type: 'object',
        properties: {
          chat_id: {
            type: 'string',
            description: 'The chat_id from the inbound <channel> tag (required).',
          },
          target: {
            type: 'string',
            enum: ['history', 'memory', 'all'],
            description: 'Which slice of scope state to clear.',
          },
        },
        required: ['chat_id', 'target'],
      },
    },
  ],
}))

mcp.setRequestHandler(CallToolRequestSchema, async req => {
  if (req.params.name === 'remember') {
    const { chat_id, note } = req.params.arguments as { chat_id: string; note: string }
    const state = activeCards.get(chat_id)
    if (!state?.scopeDir) {
      return {
        content: [{ type: 'text', text: 'no active scope for this chat_id' }],
        isError: true,
      }
    }
    appendScopeMemory(
      { key: state.scopeKey ?? '', dir: state.scopeDir, effectiveScope: 'dm', parentDirs: [] },
      note
    )
    dlog('remember appended', { scope: state.scopeKey, bytes: note.length })
    return { content: [{ type: 'text', text: 'remembered' }] }
  }
  if (req.params.name === 'forget') {
    const { chat_id, target } = req.params.arguments as { chat_id: string; target: 'history' | 'memory' | 'all' }
    const state = activeCards.get(chat_id)
    if (!state?.scopeDir) {
      return {
        content: [{ type: 'text', text: 'no active scope for this chat_id' }],
        isError: true,
      }
    }
    const cleared: string[] = []
    try {
      if (target === 'history' || target === 'all') {
        writeFileSync(join(state.scopeDir, 'history.jsonl'), '')
        cleared.push('history')
      }
      if (target === 'memory' || target === 'all') {
        writeFileSync(
          join(state.scopeDir, 'memory.md'),
          `# Memory — ${state.scopeKey}\n\n<!-- cleared ${new Date().toISOString()} -->\n`
        )
        cleared.push('memory')
      }
      dlog('forget', { scope: state.scopeKey, target, cleared })
      return { content: [{ type: 'text', text: `cleared: ${cleared.join(' + ')}` }] }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `forget failed: ${String(err)}` }],
        isError: true,
      }
    }
  }
  if (req.params.name === 'reply') {
    const { chat_id, text, actions } = req.params.arguments as {
      chat_id: string
      text: string
      actions?: ReplyAction[]
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
        if (actions && Array.isArray(actions) && actions.length > 0) {
          state.userActions = actions.slice(0, 4) // hard cap at 4 buttons
        }
        // Persist this turn (user → assistant) into the scope's history.jsonl.
        if (state.scopeDir && state.userText) {
          const now = Date.now()
          const scopeRef: ResolvedScope = { key: state.scopeKey ?? '', dir: state.scopeDir, effectiveScope: 'dm', parentDirs: [] }
          appendScopeHistory(scopeRef, { role: 'user', text: state.userText, ts: now, senderName: state.senderName })
          appendScopeHistory(scopeRef, { role: 'assistant', text, ts: now })
        }
        await flushCard(chat_id)
        // Remove typing reaction now — answer is visible.
        const reactionId = typingReactionsByChat.get(chat_id) ?? null
        if (reactionId && state.userMessageId) {
          await removeTypingReaction(state.userMessageId, reactionId)
          typingReactionsByChat.delete(chat_id)
        }
        if (state.pendingFinalizeTimer) clearTimeout(state.pendingFinalizeTimer)
        state.pendingFinalizeTimer = setTimeout(() => {
          dlog('reply: fallback finalize (no Stop hook in 6s)')
          finalizeCard(chat_id, 'done').catch(err => dlog('fallback finalize err', String(err)))
        }, 6000)
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
/** requestId → {messageId, chatId} so we can delete the permission card on resolution. */
const pendingPermissionMessages = new Map<string, { messageId: string; chatId: string }>()
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
        const mentions: any[] = msg.mentions ?? []
        // Broader mention match: handle multiple Feishu payload shapes.
        const mentionsBot = mentions.some(m => {
          const ids = [m?.id?.open_id, m?.id, m?.open_id].filter(Boolean)
          if (botOpenId && ids.includes(botOpenId)) return true
          const keyStr = String(m?.key ?? '')
          if (botAppName && keyStr.includes(botAppName)) return true
          const nameStr = String(m?.name ?? '')
          if (botAppName && nameStr.includes(botAppName)) return true
          return false
        })
        dlog('group mention check', {
          chatId,
          senderId,
          botOpenId,
          botAppName,
          mentionsCount: mentions.length,
          mentionsSample: mentions.slice(0, 3),
          mentionsBot,
          requireMention: access.requireMention,
        })
        if (access.requireMention && !mentionsBot) {
          dlog('group drop: requireMention but no bot mention')
          return
        }
        text = text.replace(/@_user_\d+\s*/g, '').replace(/@\S+\s*/g, '').trim()
        const groupAllowed = checkGroupAllowed(chatId)
        dlog('group allowed check', { chatId, groupAllowed, groupPolicy: access.groupPolicy })
        if (!groupAllowed) {
          dlog('group drop: chat not in allowlist / policy disabled')
          return
        }
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
        // Also clean up the permission card message if there was one.
        const pc = pendingPermissionMessages.get(requestId)
        if (pc?.messageId) {
          try {
            await (client.im.message as any).delete({ path: { message_id: pc.messageId } })
          } catch {}
          pendingPermissionMessages.delete(requestId)
        }
        return
      }

      // ---- Remember this chat for future permission prompts ----
      defaultHomeChat = chatId
      // Any outstanding permission_request without a mapped chat: assign this one.
      // Best-effort; permission_request arrives asynchronously from Claude Code.

      // ---- Resolve scope + load its workspace (CLAUDE.md / memory.md / history) ----
      const topicId: string | undefined = msg.thread_id ?? undefined
      // Resolve display names in parallel (chat name only for groups).
      const [senderName, chatName] = await Promise.all([
        resolveSenderName(senderId),
        chatType === 'group' ? resolveChatName(chatId) : Promise.resolve(''),
      ])
      dlog('names resolved', { senderName, chatName })
      const scopeMeta: ScopeMeta = {
        chatType: (chatType === 'p2p' ? 'p2p' : 'group'),
        chatId,
        chatName,
        senderId,
        senderName,
        topicId,
      }
      const scope = resolveScope(scopeMeta)
      ensureScopeDir(scope, scopeMeta)
      const ctx = readScopeContext(scope, access.historyPerScope)
      dlog('scope resolved', { key: scope.key, effective: scope.effectiveScope, historyTurns: ctx.history.length })

      // Invalidate stale session→chat cache entries. One Claude Code session
      // can serve multiple chats in sequence; without this, hooks fired for
      // *this* inbound would resolve to the PREVIOUS chat_id via stale cache.
      for (const [sid, cid] of sessionChatMap.entries()) {
        if (cid !== chatId) sessionChatMap.delete(sid)
      }

      // ---- UX: acknowledge with typing reaction + placeholder card ----
      const userMsgId: string = msg.message_id ?? ''
      if (userMsgId) {
        // Handle concurrent: a previous card still in-flight.
        const prev = activeCards.get(chatId)
        if (prev && !prev.finalized) {
          if (prev.answered) {
            // Reply already landed; just finalize it normally.
            await finalizeCard(chatId, 'done')
          } else {
            // In-flight but never answered — don't fake a green tick.
            // Mark it interrupted and drop state so the new card starts clean.
            prev.answerBuffer = '_🚫 被下一条消息打断_'
            await finalizeCard(chatId, 'error')
          }
        }
        // Typing emoji reaction on user's msg (visual ACK).
        const reactionId = await addTypingReaction(userMsgId)
        if (reactionId) typingReactionsByChat.set(chatId, reactionId)
        // Create streaming placeholder card — answer element will typewriter in.
        await ensureCard(chatId, userMsgId, {
          dir: scope.dir,
          key: scope.key,
          userText: text,
          senderName,
        })
      }

      // ---- Forward to Claude as channel event with full scope context ----
      const enrichedContent = buildScopedContent(scope, scopeMeta, text, ctx)
      dlog('>>> emitting notifications/claude/channel', {
        chatId,
        scope: scope.key,
        text_prefix: text.slice(0, 40),
        prefix_bytes: enrichedContent.length,
      })
      const metaOut: Record<string, string> = {
        chat_id: chatId,
        sender_id: senderId,
        sender_name: senderName,
        message_type: chatType === 'p2p' ? 'dm' : 'group',
        chat_type: chatType,
        conversation_id: scope.key,
      }
      if (chatName) metaOut.chat_name = chatName
      if (topicId) metaOut.thread_id = topicId
      await mcp.notification({
        method: 'notifications/claude/channel',
        params: { content: enrichedContent, meta: metaOut },
      })
      dlog('<<< notification emitted ok')
    } catch (err) {
      dlog('inbound handler error', String(err))
    }
  },
  // Card button callback → permission verdict OR cancel
  'card.action.trigger': async (event: any) => {
    try {
      // V2 callbacks put value under different paths depending on schema /
      // SDK version. Try them all.
      const value =
        event?.action?.value ??
        event?.action?.form_value ??
        event?.action?.behaviors?.[0]?.value ??
        event?.event?.action?.value ??
        {}
      dlog('card.action.trigger', {
        value,
        raw_event_keys: event ? Object.keys(event) : [],
        action_keys: event?.action ? Object.keys(event.action) : [],
      })
      if (value?.verdict && value?.request_id) {
        const requestId = String(value.request_id)
        const verdict = value.verdict === 'allow' ? 'allow' : 'deny'
        await mcp.notification({
          method: 'notifications/claude/channel/permission',
          params: { request_id: requestId, behavior: verdict },
        })
        pendingPermissionChat.delete(requestId)
        // Delete the permission card message so chat stays clean — like a
        // tool-timeline entry getting compressed after its work is done.
        const pc = pendingPermissionMessages.get(requestId)
        if (pc?.messageId) {
          try {
            await (client.im.message as any).delete({
              path: { message_id: pc.messageId },
            })
            dlog('permission card deleted', { requestId, messageId: pc.messageId })
          } catch (err) {
            dlog('permission card delete failed', { requestId, err: String(err) })
          }
          pendingPermissionMessages.delete(requestId)
        }
        return {
          toast: {
            type: 'success',
            content: verdict === 'allow' ? '已批准' : '已拒绝',
          },
        }
      }
      if (value?.user_action && value?.chat_id) {
        const clickedChatId = String(value.chat_id)
        const userActionValue = String(value.user_action)
        const clickedLabel = String(value.label ?? userActionValue)
        dlog('user action clicked', { chatId: clickedChatId, value: userActionValue, label: clickedLabel })

        // Build the "post-click" card (no buttons + 已选择 line). We return
        // this INSIDE the callback response's `card` field — Feishu uses
        // that as the authoritative post-click card. A separate card.update
        // gets rolled back by Feishu's own post-callback sync.
        let updatedCard: any = null
        const snap = lastFinalizedCard.get(clickedChatId)
        dlog('snap lookup', { chatId: clickedChatId, hasSnap: !!snap })
        if (snap) {
          updatedCard = finalCardJSON({
            answer: snap.answer + `\n\n✅ _已选择：${clickedLabel}_`,
            timeline: snap.timeline,
            elapsedMs: snap.elapsedMs,
            state: snap.state,
            tokens: snap.tokens,
            toolCount: snap.toolCount,
            // actions intentionally omitted — strips buttons
            chatId: snap.chatId,
          })
          lastFinalizedCard.delete(clickedChatId)
        }

        // Emit channel notification so Claude gets another turn.
        await mcp.notification({
          method: 'notifications/claude/channel',
          params: {
            content: `用户在上一条回复的卡片上点击了按钮 "${clickedLabel}"。button_value: "${userActionValue}"`,
            meta: {
              chat_id: clickedChatId,
              message_type: 'button_click',
              button_value: userActionValue,
              button_label: clickedLabel,
            },
          },
        })

        const response: any = {
          toast: { type: 'success', content: `已选择：${clickedLabel}` },
        }
        if (updatedCard) {
          response.card = { type: 'raw', data: updatedCard }
        }
        return response
      }
      if (value?.action === 'cancel_card') {
        // Soft cancel: we can't preempt Claude Code itself, but we can stop
        // updating this card and tell the user honestly.
        const chatId = event?.event?.context?.open_chat_id
          ?? event?.open_chat_id
          ?? ''
        const state = chatId ? activeCards.get(chatId) : null
        if (state && !state.finalized) {
          state.answerBuffer = '_🛑 已停止显示此次输出。Claude 可能仍在后台运行，但结果不会再更新到这里。_'
          await finalizeCard(chatId, 'done')
        }
        return { toast: { type: 'info', content: '已停止显示' } }
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
  if (tool_name === 'mcp__feishu__reply' || tool_name === 'mcp__plugin_feishu_feishu__reply') return
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
  // Our reply tool shows up as mcp__plugin_feishu_feishu__reply in the new
  // plugin packaging, or mcp__feishu__reply in legacy form. Treat both as ours.
  const isOurReply =
    tool_name === 'mcp__feishu__reply' ||
    tool_name === 'mcp__plugin_feishu_feishu__reply'
  const chatId = await correlateSession(session_id, transcript_path)
  if (!chatId) return
  if (isOurReply) {
    // Parse final token usage eagerly — it's already in the transcript by now,
    // even though Stop hook hasn't fired yet. This beats the 6s fallback race.
    const state = activeCards.get(chatId)
    if (state && !state.finalized) {
      const tokens = await parseTokenUsage(transcript_path)
      if (tokens) {
        state.tokens = tokens
        dlog('tokens parsed early (from reply PostToolUse)', tokens)
      }
    }
    return
  }
  const state = activeCards.get(chatId)
  if (!state || state.finalized) return
  const entry = state.timelineEntries.find(e => e.id === tool_use_id)
  if (entry) {
    entry.finishedAt = Date.now()
    entry.error = Boolean(tool_response?.isError ?? tool_response?.is_error)
    entry.outputSummary = summarizeToolOutput(entry.tool, tool_response)
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
/**
 * Tear down the old WS client and start a fresh one. The Feishu node-sdk
 * sometimes silently loses its WebSocket without the "stop" event firing —
 * we proactively recycle to recover.
 */
async function restartWSClient(reason: string): Promise<void> {
  dlog(`restarting WS client: ${reason}`)
  try {
    if (typeof (wsClient as any).stop === 'function') {
      await (wsClient as any).stop()
    }
  } catch (err) {
    dlog('old wsClient.stop() error (ignored)', String(err))
  }
  wsClient = makeWSClient()
  try {
    wsClient.start({ eventDispatcher })
    dlog('=== ws client re-started ok ===')
  } catch (err) {
    dlog('ws client re-start FAILED', String(err))
  }
}

/**
 * Watchdogs: the WS goes silent in the wild without surfacing an error. Two
 * defenses:
 *   1) API heartbeat every 60s — catches Feishu/network outages. 3 fails →
 *      tear down and recreate the WS client.
 *   2) Scheduled rotation every 3h — defeats silent connection rot even when
 *      the API is responsive.
 */
function startWatchdogs(): void {
  let apiFailures = 0
  setInterval(async () => {
    try {
      await client.request({ url: '/open-apis/bot/v3/info', method: 'GET' })
      if (apiFailures > 0) dlog('api heartbeat recovered')
      apiFailures = 0
    } catch (err) {
      apiFailures++
      dlog(`api heartbeat fail ${apiFailures}/3`, String(err).slice(0, 100))
      if (apiFailures >= 3) {
        apiFailures = 0
        await restartWSClient('api heartbeat exhausted')
      }
    }
  }, 60_000)

  setInterval(() => {
    restartWSClient('scheduled rotation (3h)').catch(err =>
      dlog('rotation restart failed', String(err))
    )
  }, 3 * 60 * 60 * 1000)
}

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
  startWatchdogs()
  process.stderr.write(`feishu channel: watchdogs armed (60s heartbeat, 3h rotation)\n`)
}

main().catch(err => {
  process.stderr.write(`feishu channel: fatal: ${String(err)}\n`)
  process.exit(1)
})
