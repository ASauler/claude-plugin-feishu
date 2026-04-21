# Feishu channel for Claude Code

A Claude Code [channel plugin](https://code.claude.com/docs/en/channels-reference)
that bridges Feishu/Lark messages into a running Claude Code session.

Messages arrive as `<channel source="feishu" chat_id="...">` events. Claude replies
through the `reply` tool, which sends text messages via the Feishu Open API.

> **Research preview.** Custom channels require
> `--dangerously-load-development-channels` during the research preview.
> See Claude Code's [Channels reference](https://code.claude.com/docs/en/channels-reference).

## Features

- **WebSocket long connection** — no public IP / ngrok / webhook server
- **Bot-identity messaging** — uses `tenant_access_token`, no user OAuth dance
- **Sender gating via pairing** — DM the bot → bot replies with pairing code → you approve in Claude Code
- **Permission relay** (v2.1.81+) — approve/deny tool prompts from your phone
- **Group chat support** — require `@mention`, per-group allowlists

## Requirements

- Claude Code ≥ 2.1.80 (permission relay needs ≥ 2.1.81)
- Bun runtime (`bun --version` ≥ 1.0)
- A Feishu self-built app with Bot capability + WebSocket event subscription

## Quickstart

1. **Create a Feishu app** at <https://open.feishu.cn/app>
   - Enable Bot capability
   - Add permissions: `im:message`, `im:message:send_as_bot`, `im:chat`, `im:resource`
   - Event subscription: switch to **WebSocket mode**, subscribe `im.message.receive_v1`
   - Publish (self-approve in personal tenant)

2. **Install the plugin** in Claude Code:
   ```
   /plugin marketplace add <your-marketplace-or-local-path>
   /plugin install feishu@<marketplace>
   /reload-plugins
   ```

3. **Configure your credentials**:
   ```
   /feishu:configure <app_id> <app_secret>
   ```

4. **Start Claude Code with the channel loaded**:
   ```bash
   # During research preview (plugin not on allowlist):
   claude --dangerously-load-development-channels plugin:feishu@<marketplace>
   ```

5. **Pair your account**: DM your bot. It replies with a pairing code. In Claude Code:
   ```
   /feishu:access pair <code>
   ```

## State layout

```
~/.claude/channels/feishu/
├── .env           # FEISHU_APP_ID, FEISHU_APP_SECRET (chmod 600)
├── access.json    # allowlist, pending pairings, group policy
├── server.log     # dlog() debug output (event flow, allowed-checks, emits)
└── bot.pid        # stale-poller detection
```

## Troubleshooting

### `Channels are not currently available` — and there is no org blocking it

If you're on a personal Pro/Max plan and see this at startup, the most likely
cause is a **telemetry opt-out in your Claude Code settings**. Channels are
gated by a GrowthBook feature flag (`tengu_harbor`), and GrowthBook can only
evaluate flags when the telemetry pipe is open. Setting either of the
following in `~/.claude/settings.json` or project settings disables the
flag fetch and makes Channels permanently unavailable:

```jsonc
{
  "env": {
    "DISABLE_TELEMETRY": "1",                   // <- breaks Channels
    "DISABLE_ERROR_REPORTING": "1",             // <- breaks Channels
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"  // <- also breaks Channels
  }
}
```

**Fix:** *delete* the keys (setting to `"0"` is not enough — the key's
presence alone is what trips the gate). Reported upstream in
[anthropics/claude-code#45918](https://github.com/anthropics/claude-code/issues/45918)
and [#38450](https://github.com/anthropics/claude-code/issues/38450).

### `plugin id mismatch (config uses "...", export uses "...")`

Caused by a mismatch between the plugin's declared `id` in `.claude-plugin/plugin.json`
(or in the marketplace entry) and the `id` string exported from the plugin's
JS entry. Keep them aligned. This plugin's external id is `feishu-openclaw-plugin`
historically — that's an unrelated official plugin. For this plugin, both
sides use `feishu` consistently.

### `TypeError: normalizeAccountId is not a function`

OpenClaw-specific. Does not apply to this plugin.

### `Plugin ... contains dangerous code patterns` during install

Not from this plugin — it's a warning triggered by OpenClaw's static analyzer
when plugins use `child_process` / env-var + network. Irrelevant here.

## Debugging

Tail the local server log while sending test messages:

```bash
tail -f ~/.claude/channels/feishu/server.log
```

You should see:

```
[2026-04-21T…Z] === server boot ===
[2026-04-21T…Z] <<< im.message.receive_v1 {"chat_id":"oc_…","chat_type":"p2p","msg_type":"text","sender_open_id":"ou_…"}
[2026-04-21T…Z] p2p allowed check {"senderId":"ou_…","allowed":true,"dmPolicy":"pairing"}
[2026-04-21T…Z] >>> emitting notifications/claude/channel {"chatId":"oc_…","text_prefix":"hi"}
[2026-04-21T…Z] <<< notification emitted ok
```

If notifications emit but don't reach Claude Code, check the Troubleshooting
section above — most commonly a telemetry opt-out.

## License

Apache-2.0
