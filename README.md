# Telegram Session Control Plane

This repository exposes a single Cloudflare Worker that handles both administrative session management and the interactive Telegram login flow. The worker stores Telegram session strings in KV, offers admin APIs to manage accounts/webhooks, serves sharded session lists for listener workers, and performs the GramJS-powered login process end-to-end.

## Features

- REST API for upserting, enabling/disabling, deleting, and updating Telegram account metadata.
- Sharded session listing endpoint used by the Railway listener manager.
- Global version counter so consumers can detect configuration changes.
- Lightweight KV index of account IDs for debugging.
- Ready-to-use Wrangler configuration and automated tests.
- Built-in GramJS-powered interactive login flow with ephemeral in-memory state (10 minute TTL by default) and automatic persistence to KV.
- Route configuration APIs with per-route “humanize” options exposed to the frontend.

## Router/Listener responsibilities

- The Router no longer connects directly to Telegram; it focuses on admin APIs and receiving webhooks.
- Outgoing Telegram messages must be forwarded to the Listener's internal endpoint (`POST /internal/tg/send`) using the configured `LISTENER_SEND_URL` instead of any direct Telegram credentials.
- Per-account `webhook_url` values should still target the Router's ingest handler (for example, `/tg/ingest`) so updates are persisted for listeners.

## Getting started

### Prerequisites

- Node.js 18+
- `npm`
- Cloudflare account with Workers & KV access
- Telegram API credentials (API ID/HASH) for GramJS

### Install dependencies

```bash
npm install
```

### Configure the Cloudflare Worker

Set the following bindings in the Cloudflare dashboard or using `wrangler secret put`:

- `SESSIONS_API_TOKEN` – static bearer token used by all admin/listener calls.
- `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` – default Telegram credentials returned to listener workers.
- `LOGIN_TTL_MS` – optional TTL override (in milliseconds) for interactive logins (defaults to 600000).
- `LISTENER_SEND_URL` – internal URL for posting outgoing messages to the listener (`/internal/tg/send`), used by the Router instead of connecting directly to Telegram.

Bind your KV namespace as `SESSIONS_KV` in `wrangler.toml` (replace the placeholder `id`).

### Worker development & deployment

```bash
# Run the unit test suite
npm test

# Optional: type-check
npm run typecheck

# Dry-run deployment (verifies worker builds)
npm run build
```

To deploy:

```bash
npx wrangler deploy
```

### Worker API reference

All requests must include `Authorization: Bearer <SESSIONS_API_TOKEN>`.

Account payloads returned by the admin APIs use `id` as the canonical internal account identifier (also returned as `canonical_account_id`) to avoid legacy `account_id` mismatches.

#### Upsert session

```bash
curl -X POST "$SESSIONS_API_BASE/v1/telegram/sessions" \
  -H "Authorization: Bearer $SESSIONS_API_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "id": "acct_123",
    "phone": "+98912xxxxxxx",
    "session_string": "1BAA...",
    "webhook_url": "https://router.example.com/tg/ingest",
    "webhook_enabled": true,
    "enabled": true
  }'

The worker automatically fills in `telegram_api_id` / `telegram_api_hash` using the environment defaults unless you supply
overrides in the request body.
```

#### Enable/disable session

```bash
curl -X POST "$SESSIONS_API_BASE/v1/telegram/sessions/acct_123/disable" \
  -H "Authorization: Bearer $SESSIONS_API_TOKEN" \
  -H "content-type: application/json" \
  -d '{"reason":"billing"}'
```

#### Toggle webhook

```bash
curl -X POST "$SESSIONS_API_BASE/v1/telegram/sessions/acct_123/webhook" \
  -H "Authorization: Bearer $SESSIONS_API_TOKEN" \
  -H "content-type: application/json" \
  -d '{"webhook_enabled": false}'
```

#### Update metadata

```bash
curl -X PATCH "$SESSIONS_API_BASE/v1/telegram/sessions/acct_123" \
  -H "Authorization: Bearer $SESSIONS_API_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "webhook_url": "https://router.example.com/tg/new",
    "group_allowlist": "12345,67890",
    "participants_limit": 300,
    "cache_ttl_ms": 900000
  }'
```

#### Delete session

```bash
curl -X DELETE "$SESSIONS_API_BASE/v1/telegram/sessions/acct_123" \
  -H "Authorization: Bearer $SESSIONS_API_TOKEN"
```

#### Fetch sharded sessions

```bash
curl -H "Authorization: Bearer $SESSIONS_API_TOKEN" \
  "$SESSIONS_API_BASE/v1/telegram/sessions?shard=0&total=1&enabled=true"
```

The response contains the global `version` and stored `session_string` values for the accounts assigned to that shard.

### Interactive auth endpoints

The worker also exposes a GramJS-backed interactive login flow. Each request uses the same bearer authentication as the admin APIs and shares the same KV-backed persistence.

1. **Start login** – `POST /v1/auth/start`

   ```json
   {
     "phone": "+98912…",
     "account_id": "acct_123",
     "webhook_url": "https://router…/tg/ingest"
   }
   ```

   Telegram API credentials are automatically taken from `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` unless you override them in the payload. Successful responses include the generated `login_id` and expiry window.

2. **Submit code** – `POST /v1/auth/code`

   ```json
   { "login_id": "lg_…", "code": "12345" }
   ```

   - success: `{"status": "SIGNED_IN", "stored": true, "id": "acct_123", "version": 47, "preview_user": {...}}`
   - 2FA required: `{"status": "PASSWORD_REQUIRED", "hint": "••••@gmail.com"}`

3. **Submit 2FA password** – `POST /v1/auth/password`

   ```json
   { "login_id": "lg_…", "password": "your-2fa-password" }
   ```

4. **Cancel login** – `POST /v1/auth/cancel`

   ```json
   { "login_id": "lg_…" }
   ```

When the login completes the worker automatically encrypts and stores the session string via the same `/v1/telegram/sessions` upsert logic, keeping session metadata in sync for listener workers.

### Routes configuration & humanize options

Routes are stored under the `routes_config_v1` KV key. The admin API exposes GET/PUT/PATCH helpers so the frontend can manage per-route “humanize” behaviour.

- **List routes** – `GET /v1/routes`
- **Replace all routes** – `PUT /v1/routes` (body: `{ "routes": { ... } }`)
- **Update a single route** – `PATCH /v1/routes/:key` (body: the partial route object)
- **Recommended defaults** – `GET /v1/routes/humanize-defaults`

> Backward compatibility: configs that never set `humanize` will still work. `GET /v1/routes` always injects a normalized `humanize` object for every route without rewriting KV.

#### Example payload

```json
{
  "routes": {
    "BUY": {
      "some_other_field": "value",
      "humanize": {
        "enabled": true,
        "reply_probability": 0.65,
        "delay_min_ms": 10000,
        "delay_max_ms": 60000,
        "typing_min_ms": 800,
        "typing_max_ms": 2500,
        "cooldown_sender_sec": 900,
        "cooldown_chat_sec": 180,
        "require_question_or_keywords": true,
        "keywords": ["خرید", "قیمت", "بخر"],
        "ignore_short_messages_lt": 3,
        "max_replies_per_chat_per_hour": 25,
        "max_replies_per_account_per_day": 250,
        "variation_openers": ["ببین", "راستش"],
        "variation_closers": ["اگه سوال داری بپرس"],
        "emoji_pool": ["🙂", "😅", "👌"],
        "emoji_probability": 0.25,
        "max_emojis": 1
      }
    }
  }
}
```

#### Humanize fields

- `enabled` (boolean): master toggle.
- `reply_probability` (number 0–1): chance of replying.
- `delay_min_ms` / `delay_max_ms` (number ms 0–600000): post-delay window; min/max are swapped if inverted.
- `typing_min_ms` / `typing_max_ms` (number ms 0–10000): typing indicator window; min/max are swapped if inverted.
- `cooldown_sender_sec` / `cooldown_chat_sec` (number seconds 0–86400): rate-limit cooldowns.
- `require_question_or_keywords` (boolean): whether to require a question or keyword hit.
- `keywords` (string[], max 50): trimmed, lowercased, unique keywords.
- `ignore_short_messages_lt` (number 0–50): skip messages shorter than this length.
- `max_replies_per_chat_per_hour` (number 0–1000): per-chat cap.
- `max_replies_per_account_per_day` (number 0–100000): per-account cap.
- `variation_openers` / `variation_closers` (string[], max 20): optional response fragments, trimmed.
- `emoji_pool` (string[], max 20): candidate emojis.
- `emoji_probability` (number 0–1): chance to append emojis.
- `max_emojis` (number 0–2): upper bound for emoji count.

Invalid humanize payloads return HTTP 400 with the offending field in the error code. All numeric fields are clamped to their allowed ranges, and defaults are automatically applied so every route returned by `GET /v1/routes` always includes a fully-populated `humanize` object.

## Testing

The test suite covers AES-GCM encryption round-trips, enable/disable flows, deterministic sharding behaviour, and the login-state lifecycle helpers.

```bash
npm test
```

## License

MIT
