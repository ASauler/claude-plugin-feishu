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
└── bot.pid        # stale-poller detection
```

## License

Apache-2.0
