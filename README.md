# pgp-proxy

A self-hosted, standalone email server with transparent PGP encryption/decryption, written in Rust. No Postfix, Exim, or any external MTA required.

It runs four services in a single binary:

| Service | Default port | Purpose |
|---|---|---|
| Outbound SMTP | 2587 | Accepts mail from apps/clients, encrypts, queues for delivery |
| Inbound SMTP | 2525 | Accepts mail from the internet, decrypts PGP, stores |
| POP3 | 1100 | Serves stored mail to clients (Thunderbird, etc.) |
| Web UI | 8080 | Admin interface for keys, policies, users, queue, logs |

---

## How it works

### Sending (outbound)

```
Your app / mail client
        │  SMTP → port 2587
        ▼
┌──────────────────────┐
│   Outbound SMTP      │  1. Receives message
│   (port 2587)        │  2. Looks up policy for sender → recipient
│                      │  3. Fetches recipient's public key from DB
│   Policy engine      │  4. Encrypts body with OpenPGP (AES-256)
│   PGP engine         │  5. Enqueues for delivery (status: pending)
└──────────┬───────────┘
           │
   ┌───────────────┐
   │ Delivery Queue│  Retries with exponential backoff:
   │ (SQLite)      │  5 min → 30 min → 2 h → 8 h → permanent failure
   └───────┬───────┘
           │
   delivery.mode = "direct"         delivery.mode = "relay"
           │                                │
           ▼                                ▼
   DNS MX lookup                    Upstream SMTP server
   → connect to recipient's         (localhost:25 or any
     mail server on port 25           configured relay)
   → deliver encrypted message
```

### Receiving (inbound)

```
Internet sender
        │  SMTP → port 2525  (point your MX DNS record here)
        ▼
┌──────────────────────┐
│   Inbound SMTP       │  1. Checks recipient domain is local
│   (port 2525)        │  2. Detects PGP-encrypted payload
│                      │  3. Looks up recipient's private key
│   PGP engine         │  4. Decrypts (if encrypted + key exists)
│   Mailbox storage    │  5. Stores in SQLite mailbox
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│   POP3 server        │  Client connects, authenticates,
│   (port 1100)        │  fetches messages (Thunderbird, etc.)
└──────────────────────┘
```

---

## Architecture

```
src/
├── main.rs            — spawns all server tasks + queue processor
├── config.rs          — config loading (file + env vars)
├── db.rs              — SQLite init, schema creation
├── error.rs           — AppError type
├── pgp_engine.rs      — encrypt_message / decrypt_message (rpgp 0.14)
├── keys.rs            — recipient public key CRUD
├── private_keys.rs    — local user private key CRUD
├── users.rs           — local user accounts (POP3 auth, Argon2id hashing)
├── mailbox.rs         — inbound message storage and retrieval
├── policy.rs          — encryption policy rules + evaluation
├── queue.rs           — delivery queue: enqueue, retry, backoff, status
├── smtp/
│   ├── server.rs      — outbound SMTP state machine (port 2587)
│   │                    + inbound SMTP state machine (port 2525)
│   └── client.rs      — relay via lettre  OR  direct MX delivery
│                        (DNS lookup via hickory-resolver)
├── pop3/
│   └── server.rs      — RFC 1939 POP3: USER/PASS/STAT/LIST/RETR/
│                        DELE/UIDL/RSET/NOOP/QUIT + dot-stuffing
└── web/
    ├── mod.rs         — axum router
    ├── routes.rs      — all HTTP handlers
    └── templates.rs   — Maud templates (dark theme + htmx, no template files)
```

### Database (SQLite)

| Table | Purpose |
|---|---|
| `pgp_keys` | Recipient public keys for outbound encryption |
| `private_keys` | Local user private keys for inbound decryption |
| `users` | Local user accounts (email + Argon2id password hash) for POP3 |
| `mailbox` | Stored inbound messages per recipient |
| `policies` | Encryption rules (sender/recipient pattern → action) |
| `smtp_logs` | Outbound SMTP transaction log |
| `delivery_queue` | Outbound delivery queue with retry state |

---

## Building

Requires Rust 1.80+ (edition 2024).

```bash
git clone https://github.com/yourname/pgp-proxy
cd pgp-proxy
cargo build --release
```

Binary: `target/release/pgp-proxy`

---

## Running

```bash
./target/release/pgp-proxy
```

On first run, `pgp_proxy.db` is created in the working directory. Open `http://localhost:8080` for the admin UI.

---

## Configuration

Configuration is loaded from (later sources override earlier ones):

1. `config.toml` in the working directory (optional)
2. Environment variables prefixed `PGP_PROXY__` (double underscore separator)

### config.toml example

```toml
[smtp]
listen_addr      = "0.0.0.0:2587"   # outbound submission port
hostname         = "mail.example.com"
max_message_size = 26214400          # 25 MB

[inbound]
listen_addr    = "0.0.0.0:2525"     # set to 0.0.0.0:25 in production
local_domains  = ["example.com", "myotherdomain.com"]

[delivery]
mode = "direct"   # "direct" (DNS MX) or "relay" (forward to another SMTP server)

[relay]           # only used when delivery.mode = "relay"
host     = "smtp.gmail.com"
port     = 587
tls      = true
username = "you@gmail.com"
password = "app-password"

[pop3]
listen_addr = "0.0.0.0:1100"   # set to 0.0.0.0:110 in production (needs root/CAP_NET_BIND_SERVICE)
enabled     = true

[web]
listen_addr = "0.0.0.0:8080"

[database]
url = "sqlite://pgp_proxy.db"
```

### Environment variable overrides

```bash
PGP_PROXY__SMTP__HOSTNAME=mail.example.com
PGP_PROXY__INBOUND__LOCAL_DOMAINS=example.com,example.net
PGP_PROXY__DELIVERY__MODE=direct
PGP_PROXY__RELAY__HOST=smtp.sendgrid.net
PGP_PROXY__RELAY__PORT=587
PGP_PROXY__RELAY__TLS=true
PGP_PROXY__RELAY__USERNAME=apikey
PGP_PROXY__RELAY__PASSWORD=SG.xxxxx
PGP_PROXY__POP3__ENABLED=false
PGP_PROXY__DATABASE__URL=sqlite:///var/lib/pgp-proxy/pgp_proxy.db
```

---

## Setup guide

### Step 1 — DNS

Point your domain's MX record at the machine running pgp-proxy:

```
example.com.   MX   10   mail.example.com.
mail.example.com.  A   1.2.3.4
```

Set `inbound.local_domains = ["example.com"]` in config.

### Step 2 — Create a local user

Open `http://localhost:8080/users`. Enter an email (`alice@example.com`) and password. This creates the account used for POP3 login. Passwords are hashed with Argon2id.

### Step 3 — Upload a private key (for inbound decryption)

Open `http://localhost:8080/private-keys`. Paste the ASCII-armored private key and passphrase for `alice@example.com`. When an encrypted inbound message arrives for Alice, the proxy decrypts it before storing.

Export from GPG:

```bash
gpg --armor --export-secret-keys alice@example.com
```

### Step 4 — Add recipient public keys (for outbound encryption)

Open `http://localhost:8080/keys`. Upload the public key for each external recipient you want to encrypt to.

```bash
gpg --armor --export bob@partner.com
```

### Step 5 — Create an encryption policy

Open `http://localhost:8080/policies`. Example rules:

| Priority | Sender | Recipient | Action | On missing key |
|---|---|---|---|---|
| 10 | `*` | `*@partner.com` | `encrypt` | `reject` |
| 20 | `*` | `*` | `none` | `send_plain` |

**Pattern syntax:**
- `*` — match anything
- `*@example.com` — any address at a domain
- `alice@*` — a user at any domain
- `alice@example.com` — exact match

**Actions:** `encrypt` · `sign` · `encrypt_sign` · `none`

**On missing key:** `reject` (bounce) · `send_plain` (deliver unencrypted)

### Step 6 — Configure your mail client

Point Thunderbird (or any POP3 client) at pgp-proxy:

| Setting | Value |
|---|---|
| Incoming type | POP3 |
| Incoming server | your-server-ip |
| Incoming port | 1100 (or 110 in production) |
| Username | alice@example.com |
| Password | (set in Step 2) |
| Outgoing server | your-server-ip |
| Outgoing port | 2587 |
| Outgoing auth | none |

### Step 7 — Test

Send a test message:

```bash
swaks --to bob@partner.com \
      --from alice@example.com \
      --server localhost:2587 \
      --body "This will be encrypted before delivery"
```

Check `http://localhost:8080/logs` to confirm the policy was applied and `http://localhost:8080/queue` to monitor delivery status.

Simulate inbound delivery:

```bash
swaks --to alice@example.com \
      --from sender@internet.com \
      --server localhost:2525
```

Then check `http://localhost:8080/mailbox` or fetch via POP3.

---

## Web UI

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Counts + recent activity |
| Public Keys | `/keys` | Recipient public keys for outbound encryption |
| Private Keys | `/private-keys` | Local user private keys for inbound decryption |
| Policies | `/policies` | Encryption rules |
| Users | `/users` | Local user accounts (POP3 login) |
| Mailbox | `/mailbox` | Admin view of all stored messages |
| Queue | `/queue` | Delivery queue: pending, delivered, and failed entries |
| Logs | `/logs` | Outbound SMTP transaction log (auto-refreshes every 5 s) |
| Config | `/config` | Current configuration (read-only) |

---

## Delivery queue

Every outbound message is stored in `delivery_queue` immediately on SMTP acceptance, so clients always get a fast `250 OK`. A background processor polls every 30 seconds and retries failed deliveries with exponential backoff:

| Attempt | Retry delay |
|---|---|
| 1 | 5 minutes |
| 2 | 30 minutes |
| 3 | 2 hours |
| 4 | 8 hours |
| 5 | permanent failure |

Queue entries are visible at `/queue` in the admin UI. Failed entries can be manually deleted.

---

## Delivery modes

### `direct` — no external MTA needed

pgp-proxy looks up the recipient domain's MX records via DNS and connects directly on port 25:

1. DNS MX lookup for recipient domain (via hickory-resolver)
2. Sort MX records by preference (lowest first)
3. Fall back to A record if no MX records found
4. Connect to each host in order until one accepts the message
5. Deliver raw SMTP (EHLO → MAIL FROM → RCPT TO → DATA → QUIT)

**Note:** STARTTLS is detected from EHLO but full TLS negotiation is not yet implemented in direct mode. If a receiving server requires STARTTLS, use relay mode through a smarthost that handles TLS.

### `relay` — forward to a smarthost

All outbound messages are forwarded to the configured relay server using `lettre`. Supports STARTTLS and SMTP AUTH. Use this when:

- Your server's port 25 is blocked by your ISP (common on home/VPS networks)
- You want to use a transactional email provider (SendGrid, Postmark, etc.) for deliverability
- Destination servers require STARTTLS

---

## Limitations

- STARTTLS on the **outbound submission port** (2587) is not implemented — use a local loopback or VPN to protect submission traffic
- No SASL authentication on the submission port — restrict access with firewall rules
- Direct delivery does not perform a full TLS handshake after STARTTLS; servers that mandate TLS will reject the connection — use relay mode in that case

---

## Logging

```bash
RUST_LOG=pgp_proxy=debug ./target/release/pgp-proxy   # verbose
RUST_LOG=info            ./target/release/pgp-proxy   # standard
```

All outbound SMTP transactions are stored in `smtp_logs` and visible at `/logs`.

---

## License

MIT
