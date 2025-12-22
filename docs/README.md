# Router/Listener architecture notes

- The Router no longer maintains any Telegram client connections. It focuses on ingesting webhooks and exposing the admin API. Telegram connectivity now lives entirely in the Listener service.
- All outgoing message sends must be forwarded to the Listener via its internal endpoint: `POST /internal/tg/send`. Configure the Router with `LISTENER_SEND_URL` to point at that endpoint instead of using any direct Telegram credentials.
- Ingest still uses the per-account `webhook_url` field. Point it at the Router's webhook handler (for example, `/tg/ingest`) so updates flow into the Listener/KV pipeline without altering the payload contract.
- Admin responses that include accounts keep the canonical internal ID in the `id` field (identical to `canonical_account_id`) to avoid legacy `account_id` mismatches.

With cooldown/handled flags removed from the flow, ensure any downstream references are cleaned up and rely on the Listener send path outlined above.
