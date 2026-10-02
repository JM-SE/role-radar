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

## Operator-only canary preparation

Preparation does not enable delivery. A dedicated `role-radar-runtime` client
token is stored in the protected Role Radar environment file. Native desired and
effective checks pass for both required capabilities with zero findings.
The protected configuration now selects Broker for both providers and the verified
Broker URL; running processes have not been restarted or reloaded. Telegram remains
disabled. A configured HTTP timeout is not yet propagated to the Broker client,
so the live canary is blocked pending that correction. Inference and destination
confirmation remain unverified. Keep those approvals and checks separate. Never show tokens, profile UUIDs,
client credential IDs, or digests.

1. In BotFather, create an owned dedicated bot, or select a known existing bot
   with no webhook. Keep `ROLE_RADAR_TELEGRAM_PROVIDER=disabled` throughout.
2. Save its token only with `sudoedit /etc/role-radar/role-radar.env`. Never put
   tokens in chat, argv, browser URLs, shell history, or logs.
3. In the intended **private** bot chat, send exactly `/start role-radar-setup`.
4. Review and run the snippet below yourself to discover the private chat ID.
   It makes one official `getUpdates` request. The token-bearing URL exists only
   in process memory; redirects and proxies are disabled. It prints only the
   numeric matching chat ID. This live read is operator-executed, not agent-run.
   The parser accepts only blank/comment lines and unique `KEY=value` assignments
   with single-line, unescaped literal values (quoted or bare); shell syntax,
   continuations, escapes, and duplicate assignments stop before token extraction.
5. Save `ROLE_RADAR_TELEGRAM_CHAT_ID` with `sudoedit` in that same protected
   file; leave the provider disabled. Do not start workers/timers, restart APIs,
   send messages, or edit the database. Return only the nonsecret client name
   and “private destination confirmed/secrets saved”; never share tokens, chat
   IDs, or profile UUIDs.

```sh
sudo /usr/bin/python3 -I -B - <<'PY'
import json, os, re, stat, urllib.error, urllib.parse, urllib.request

MARKER = "/start role-radar-setup"
ENV = "/etc/role-radar/role-radar.env"

def chat_ids(updates):
    return [m["chat"]["id"] for u in updates
            if isinstance(u, dict) and isinstance((m := u.get("message")), dict)
            and isinstance(m.get("chat"), dict) and m["chat"].get("type") == "private"
            and m.get("text") == MARKER and type(m["chat"].get("id")) is int]

# Deterministic filter check; synthetic data only, no credentials or network.
assert chat_ids([{"message":{"chat":{"type":"private","id":7},"text":MARKER}}]) == [7]
assert chat_ids([{"message":{"chat":{"type":"group","id":8},"text":MARKER}},
                 {"message":{"chat":{"type":"private","id":9},"text":"other"}}]) == []

def stop(reason):
    raise RuntimeError(reason)


def token_from_env(text):
    # Only blank/comments and plain KEY=literal lines; no shell, escapes, or continuations.
    assignment = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^'\\$`]*)'|\"([^\"\\$`]*)\"|([^\s'\"\\$`#;&|<>()[\]{}]*))\s*$"
    )
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = assignment.fullmatch(line)
        if not match:
            stop("unsupported environment syntax")
        key = match.group(1)
        if key in values:
            stop("duplicate environment assignment")
        values[key] = next((value for value in match.groups()[1:] if value is not None), "")
    if "ROLE_RADAR_TELEGRAM_BOT_TOKEN" not in values:
        stop("expected exactly one bot-token assignment")
    return values["ROLE_RADAR_TELEGRAM_BOT_TOKEN"]


def error_message(exc):
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 409:
        return "Telegram HTTP 409; stop, do not delete webhook"
    return "safe lookup failed"

try:
    fd = os.open(ENV, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            stop("env file must be a root-owned regular mode-0600 file")
        text = f.read(65537)
    if len(text) > 65536:
        stop("env file too large")
    token = token_from_env(text)
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{35}", token):
        stop("bot token format is invalid")

    query = urllib.parse.urlencode({"timeout": "5", "limit": "10",
                                    "allowed_updates": '["message"]'})
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/getUpdates?" + query)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                stop("Telegram returned non-OK HTTP status")
            body = response.read(65537)
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print("Stopped: " + error_message(e))
            raise SystemExit(1)
        stop("Telegram returned non-OK HTTP status")
    if len(body) > 65536:
        stop("Telegram response too large")
    data = json.loads(body)
    if not isinstance(data, dict) or data.get("ok") is not True:
        stop("Telegram response was not OK")
    matches = chat_ids(data.get("result", []))
    if len(matches) != 1:
        stop("expected exactly one matching private message; stop without choosing or deleting")
    print(matches[0])
except Exception as e:
    # Never expose exception text, token, URL, response body, names, or messages.
    print("Stopped: " + error_message(e))
    raise SystemExit(1)
PY
```

A group destination is out of scope: stop and discuss; never select a public
target automatically. Preparation is not a canary. Get separate, exact bounded-
canary approval before enabling live providers or sending anything.
