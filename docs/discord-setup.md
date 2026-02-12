# Discord Setup Guide

How to connect Spacebot to Discord so it can receive messages and respond through the Discord adapter.

## Discord Developer Portal

### 1. Create an Application

Go to https://discord.com/developers/applications and create a new application. Name it whatever you want — this is the internal name, not the bot's display name.

### 2. Create a Bot

Under the "Bot" section:

- Click "Add Bot"
- Copy the **bot token** — you'll need this for the config
- Under "Privileged Gateway Intents", enable:
  - **Message Content Intent** (required — without this, message bodies arrive empty)
  - **Server Members Intent** is NOT needed
  - **Presence Intent** is NOT needed

### 3. Generate an Invite URL

Under "OAuth2" > "URL Generator":

- Scopes: `bot`
- Bot Permissions:
  - Send Messages
  - Read Message History
  - Embed Links (for future media support)
  - Attach Files (for future media support)

Copy the generated URL and open it in your browser to invite the bot to your server.

### 4. Get Your Guild ID

In Discord, enable Developer Mode (User Settings > Advanced > Developer Mode). Right-click your server name and "Copy Server ID". This is your `guild_id`.

## Spacebot Configuration

Add the following to your `config.toml`:

```toml
[llm]
anthropic_key = "env:ANTHROPIC_API_KEY"

[messaging.discord]
enabled = true
token = "env:DISCORD_BOT_TOKEN"

[[agents]]
id = "main"
default = true

# Route this Discord server to the "main" agent
[[bindings]]
agent_id = "main"
channel = "discord"
guild_id = "YOUR_GUILD_ID_HERE"
```

Set the environment variable:

```bash
export DISCORD_BOT_TOKEN="your-bot-token-here"
export ANTHROPIC_API_KEY="your-api-key-here"
```

The `token` field supports `env:` prefix to read from environment variables at startup — tokens are never stored in plaintext in config.

### Multiple Servers

Route different Discord servers to different agents:

```toml
[[agents]]
id = "main"
default = true

[[agents]]
id = "dev-bot"
channel_model = "anthropic/claude-sonnet-4-20250514"

[[bindings]]
agent_id = "main"
channel = "discord"
guild_id = "123456789"

[[bindings]]
agent_id = "dev-bot"
channel = "discord"
guild_id = "987654321"
```

Each agent has its own memory, identity, and conversation history. Messages from guild `123456789` go to the "main" agent, messages from `987654321` go to "dev-bot".

### Guild Filtering

When bindings specify guild IDs, the adapter only processes messages from those guilds. If no Discord bindings exist, the adapter accepts messages from all guilds the bot is in (routed to the default agent).

## How Messages Flow

```
User types in #general on Discord
    |
    v
Serenity gateway receives Message event
    |
    v
Handler.message() builds InboundMessage:
    - id: Discord message snowflake
    - source: "discord"
    - conversation_id: "discord:GUILD_ID:CHANNEL_ID"
    - sender_id: Discord user ID
    - agent_id: None (set by router later)
    - metadata: { discord_channel_id, discord_guild_id, ... }
    |
    v
mpsc channel -> InboundStream -> MessagingManager
    |
    v
Router resolves binding -> sets agent_id
    |
    v
Agent creates or reuses a Channel for this conversation_id
    |
    v
Channel processes the message (branch -> think -> reply)
    |
    v
ReplyTool -> OutboundResponse -> MessagingManager.respond()
    |
    v
DiscordAdapter.respond() -> Discord API -> User sees reply
```

### Conversation Mapping

Each Discord channel/thread maps to one Spacebot conversation:

| Discord Context | conversation_id | Spacebot Behavior |
|----------------|----------------|-------------------|
| Server channel `#general` | `discord:GUILD:CHANNEL` | One conversation per channel |
| Thread in `#general` | `discord:GUILD:THREAD` | One conversation per thread |
| DM with bot | `discord:dm:USER` | One conversation per DM |

Threads are the natural fit for isolated conversations. In a busy server channel, all messages in that channel share one conversation context. Threads give each interaction its own history.

### Typing Indicators

When the agent is thinking, Discord shows the "Spacebot is typing..." indicator. This auto-repeats until a response is sent. Typing stops when:
- The agent sends a response
- A non-Thinking status update arrives (tool execution, worker spawn, etc.)

### Message Length

Discord caps messages at 2000 characters. Long responses are automatically split at newlines (preferred), then spaces, then hard-cut at 2000 chars.

### Streaming

When streaming is enabled, the adapter sends an initial placeholder message on `StreamStart`, then edits it in-place as `StreamChunk` text accumulates. On `StreamEnd`, the placeholder is cleaned up. If accumulated text exceeds 2000 chars during streaming, it truncates with "..." (a future improvement would split into a new message).

## What's Not Built Yet

The Discord adapter itself is complete, but the orchestration layer that ties it to the agent system has gaps. These are tracked on the roadmap (Phases 4, 7, 8):

**Binding resolution / Router** — When an `InboundMessage` arrives, something needs to match its `source` + `guild_id` against the configured `[[bindings]]` to determine which agent handles it. The `InboundMessage.agent_id` field exists for this (set to `None` by the adapter, intended to be filled by the router). The binding data is loaded from config. The matching logic doesn't exist yet.

**Channel lifecycle management** — When a message arrives for a conversation_id that hasn't been seen before, a new `Channel` needs to be created (with the agent's deps, prompts, and identity) and its `run()` loop spawned. Subsequent messages for the same conversation_id route to the existing channel. This resolve-or-create pattern isn't wired yet. The `Channel::new()` and `Channel::run()` methods exist but nothing calls them.

**Main event loop** — `main.rs` registers adapters but never calls `messaging_manager.start()`. There's no loop consuming the `InboundStream`. The program currently just waits for ctrl+c after init.

**Reply path** — The `ReplyTool` sends `OutboundResponse` on an mpsc channel, but that channel isn't connected back to `MessagingManager.respond()`. The original `InboundMessage` (with its source + metadata) needs to be available so responses route back through the correct adapter to the correct Discord channel.

**Agent LLM calls** — Channel/Branch/Worker `run()` methods use placeholder `sleep()` instead of real Rig agent calls. This is the Phase 4 work (model routing + wiring `agent.prompt().with_history()`).

### In short

The Discord adapter handles the I/O layer — receiving messages from Discord and sending responses back. The gap is the middle: routing messages to the right agent, managing channel lifecycles, and connecting the reply path. Once those pieces are built (Phases 4, 7, 8), running `spacebot` with a Discord token will give you a working bot.
