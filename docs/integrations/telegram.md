# Telegram daily digest

Telegram is disabled by default. The scheduler persists `notification_mode=daily_digest`
and a `daily:<YYYY-MM-DD>` slot; API and manual runs always persist `none`.

For an opt-in deployment, store the following only in the protected systemd
environment file (never in the database or logs):

```dotenv
ROLE_RADAR_TELEGRAM_PROVIDER=http
ROLE_RADAR_TELEGRAM_BOT_TOKEN=...
ROLE_RADAR_TELEGRAM_CHAT_ID=...
```

The worker sends one HTML message of at most 4096 UTF-16 units. A prepared
outbox batch is reserved before network I/O. `unknown` means that Telegram's
acceptance could not be determined; it is terminal for automation and is not
automatically resent. `sent` means Bot API acceptance with a message id, not
that a user read the message.

No `getUpdates`, webhook, feedback, inline action, or public resend endpoint is
provided in Phase 7. Before enabling the provider, run the migration separately
and use the scheduler's explicit `America/Argentina/Buenos_Aires` timezone.
