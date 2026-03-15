#!/usr/bin/env bash
# Integration tests for pgp-proxy using swaks.
# Requires: swaks, the project to be built with `cargo build`.
#
# Usage:
#   bash tests/integration.sh
set -euo pipefail

BINARY="./target/debug/pgp-proxy"
DB_FILE="./test_pgp_proxy.db"
WEB_PORT=18080
SMTP_PORT=12587
INBOUND_PORT=12525
POP3_PORT=11100

PASS=0
FAIL=0

# ── helpers ───────────────────────────────────────────────────────────────────

pass() { echo "  ✓ $1"; ((PASS++)) || true; }
fail() { echo "  ✗ $1"; ((FAIL++)) || true; }

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        pass "$label"
    else
        fail "$label — expected to find: $needle"
        echo "    Got: $haystack"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    if ! echo "$haystack" | grep -qF -- "$needle"; then
        pass "$label"
    else
        fail "$label — expected NOT to find: $needle"
    fi
}

# Send lines to host:port over a plain TCP connection and capture the response.
# \r and \n in input are interpreted as CR and LF (printf %b semantics).
# Works on Linux and macOS via bash /dev/tcp (no external nc dependency).
# Uses bash's built-in read -t to avoid a dependency on GNU coreutils timeout.
tcp_dialog() {
    local host="$1" port="$2" input="$3" timeout_s="${4:-3}"
    (
        exec 3<>/dev/tcp/"$host"/"$port" 2>/dev/null || exit 0
        printf '%b' "$input" >&3
        local line
        while IFS= read -r -t "$timeout_s" line <&3 2>/dev/null; do
            printf '%s\n' "$line"
        done
        exec 3>&-
    ) 2>/dev/null || true
}

wait_for_port() {
    local host="$1" port="$2" retries=40
    while ! bash -c "exec 3<>/dev/tcp/$host/$port; exec 3>&-" 2>/dev/null; do
        ((retries--))
        [[ $retries -le 0 ]] && { echo "Timed out waiting for $host:$port"; exit 1; }
        sleep 0.25
    done
}

# ── setup ─────────────────────────────────────────────────────────────────────

[[ -f "$BINARY" ]] || { echo "Binary not found: $BINARY  (run cargo build first)"; exit 1; }
command -v swaks >/dev/null 2>&1 || { echo "swaks not installed"; exit 1; }

rm -f "$DB_FILE"
trap 'kill "$PID" 2>/dev/null; rm -f "$DB_FILE"' EXIT

export PGP_PROXY__SMTP__LISTEN_ADDR="127.0.0.1:$SMTP_PORT"
export PGP_PROXY__SMTP__HOSTNAME="test.local"
export PGP_PROXY__INBOUND__LISTEN_ADDR="127.0.0.1:$INBOUND_PORT"
export PGP_PROXY__INBOUND__LOCAL_DOMAINS="test.local"
export PGP_PROXY__POP3__LISTEN_ADDR="127.0.0.1:$POP3_PORT"
export PGP_PROXY__POP3__ENABLED="true"
export PGP_PROXY__WEB__LISTEN_ADDR="127.0.0.1:$WEB_PORT"
export PGP_PROXY__DATABASE__URL="sqlite://$DB_FILE"
export PGP_PROXY__DELIVERY__MODE="relay"
export PGP_PROXY__RELAY__HOST="127.0.0.1"
export PGP_PROXY__RELAY__PORT="9999"   # intentionally unreachable; messages are queued

"$BINARY" 2>/dev/null &
PID=$!

echo "Waiting for servers to start..."
wait_for_port 127.0.0.1 "$SMTP_PORT"
wait_for_port 127.0.0.1 "$INBOUND_PORT"
wait_for_port 127.0.0.1 "$WEB_PORT"
wait_for_port 127.0.0.1 "$POP3_PORT"
echo "Servers up (pid=$PID)"
# Give the tokio event loops a moment to spin up before first connection
sleep 0.5
echo

# ── test: outbound SMTP greeting ──────────────────────────────────────────────
echo "=== Outbound SMTP ==="

BANNER=$(tcp_dialog 127.0.0.1 "$SMTP_PORT" "QUIT\r\n" 5)
assert_contains "greeting contains 220"   "220"   "$BANNER"
assert_contains "greeting mentions ESMTP" "ESMTP" "$BANNER"

# ── test: EHLO capabilities ───────────────────────────────────────────────────

EHLO_RESP=$(tcp_dialog 127.0.0.1 "$SMTP_PORT" "EHLO test.client\r\nQUIT\r\n" 5)
assert_contains "EHLO 250 OK"            "250"  "$EHLO_RESP"
assert_contains "EHLO advertises AUTH"   "AUTH" "$EHLO_RESP"
assert_contains "EHLO advertises SIZE"   "SIZE" "$EHLO_RESP"

# ── test: send mail via swaks (no policy; relay unreachable → queued) ─────────

SWAKS_OUT=$(swaks \
    --to "bob@example.com" \
    --from "alice@test.local" \
    --server "127.0.0.1:$SMTP_PORT" \
    --body "Hello Bob, this is a test." \
    --timeout 10 \
    2>&1 || true)

assert_contains "swaks gets 250 queued" "queued" "$SWAKS_OUT"

# ── test: delivery queue visible via web UI ───────────────────────────────────

echo ""
echo "=== Web UI ==="

sleep 0.3

QUEUE_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/queue" 2>/dev/null || true)
assert_contains "queue page loads" "bob@example.com" "$QUEUE_HTML"

DASH_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/" 2>/dev/null || true)
assert_contains "dashboard loads" "Dashboard" "$DASH_HTML"

LOGS_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/logs" 2>/dev/null || true)
assert_contains "logs page loads" "alice@test.local" "$LOGS_HTML"

# ── test: add a user via web UI ───────────────────────────────────────────────

echo ""
echo "=== User management ==="

ADD_USER=$(curl -sf -X POST "http://127.0.0.1:$WEB_PORT/users" \
    -d "email=alice%40test.local&password=secret123" 2>/dev/null || true)
assert_contains "add user succeeds" "alice@test.local" "$ADD_USER"

USERS_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/users" 2>/dev/null || true)
assert_contains "user appears in list" "alice@test.local" "$USERS_HTML"

# ── test: SMTP AUTH PLAIN ─────────────────────────────────────────────────────

echo ""
echo "=== AUTH PLAIN ==="

# Build AUTH PLAIN payload: \0username\0password
AUTH_B64=$(printf '\0alice@test.local\0secret123' | base64 | tr -d '\n')

AUTH_RESP=$(tcp_dialog 127.0.0.1 "$SMTP_PORT" \
    "EHLO test\r\nAUTH PLAIN ${AUTH_B64}\r\nQUIT\r\n" 5)
assert_contains "AUTH PLAIN succeeds"        "235"                    "$AUTH_RESP"
assert_contains "AUTH PLAIN success message" "Authentication successful" "$AUTH_RESP"

# Wrong password should be rejected
WRONG_B64=$(printf '\0alice@test.local\0wrongpassword' | base64 | tr -d '\n')
WRONG_RESP=$(tcp_dialog 127.0.0.1 "$SMTP_PORT" \
    "EHLO test\r\nAUTH PLAIN ${WRONG_B64}\r\nQUIT\r\n" 5)
assert_contains "AUTH PLAIN rejects wrong password" "535" "$WRONG_RESP"

# ── test: AUTH LOGIN ──────────────────────────────────────────────────────────

echo ""
echo "=== AUTH LOGIN ==="

# AUTH LOGIN: server prompts for username (base64), then password (base64)
U_B64=$(printf 'alice@test.local' | base64 | tr -d '\n')
P_B64=$(printf 'secret123' | base64 | tr -d '\n')

LOGIN_RESP=$(tcp_dialog 127.0.0.1 "$SMTP_PORT" \
    "EHLO test\r\nAUTH LOGIN\r\n${U_B64}\r\n${P_B64}\r\nQUIT\r\n" 5)
assert_contains "AUTH LOGIN succeeds" "235" "$LOGIN_RESP"

# ── test: send authenticated mail via swaks ───────────────────────────────────

AUTH_SWAKS_OUT=$(swaks \
    --auth PLAIN \
    --auth-user "alice@test.local" \
    --auth-password "secret123" \
    --to "bob@example.com" \
    --from "alice@test.local" \
    --server "127.0.0.1:$SMTP_PORT" \
    --body "Authenticated message." \
    --timeout 10 \
    2>&1 || true)
assert_contains "authenticated swaks queued" "queued" "$AUTH_SWAKS_OUT"

# ── test: inbound SMTP ────────────────────────────────────────────────────────

echo ""
echo "=== Inbound SMTP ==="

INBOUND_BANNER=$(tcp_dialog 127.0.0.1 "$INBOUND_PORT" "QUIT\r\n")
assert_contains "inbound greeting 220" "220" "$INBOUND_BANNER"

INBOUND_OUT=$(swaks \
    --to "alice@test.local" \
    --from "sender@internet.example" \
    --server "127.0.0.1:$INBOUND_PORT" \
    --body "Inbound test message." \
    --timeout 10 \
    2>&1 || true)
assert_contains "inbound mail accepted" "250" "$INBOUND_OUT"

sleep 0.3

MAILBOX_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/mailbox" 2>/dev/null || true)
assert_contains "inbound message in mailbox" "alice@test.local" "$MAILBOX_HTML"

# ── test: wrong domain rejected on inbound ────────────────────────────────────

REJECT_OUT=$(swaks \
    --to "nobody@other-domain.com" \
    --from "sender@internet.example" \
    --server "127.0.0.1:$INBOUND_PORT" \
    --timeout 10 \
    2>&1 || true)
assert_contains "wrong domain rejected" "550" "$REJECT_OUT"

# ── test: POP3 ────────────────────────────────────────────────────────────────

echo ""
echo "=== POP3 ==="

POP3_BANNER=$(tcp_dialog 127.0.0.1 "$POP3_PORT" "QUIT\r\n")
assert_contains "POP3 greeting +OK" "+OK" "$POP3_BANNER"

POP3_AUTH=$(tcp_dialog 127.0.0.1 "$POP3_PORT" \
    "USER alice@test.local\r\nPASS secret123\r\nSTAT\r\nLIST\r\nQUIT\r\n" 5)
assert_contains "POP3 USER accepted"       "+OK"      "$POP3_AUTH"
assert_contains "POP3 PASS accepted"       "+OK"      "$POP3_AUTH"
assert_contains "POP3 STAT returns +OK"    "+OK 1"    "$POP3_AUTH"

# Wrong password should be rejected
POP3_FAIL=$(tcp_dialog 127.0.0.1 "$POP3_PORT" \
    "USER alice@test.local\r\nPASS wrongpass\r\nQUIT\r\n" 5)
assert_contains "POP3 wrong password rejected" "-ERR" "$POP3_FAIL"

# ── test: keys and policies via web UI ───────────────────────────────────────

echo ""
echo "=== Keys and policies ==="

KEYS_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/keys" 2>/dev/null || true)
assert_contains "keys page loads" "Public Keys" "$KEYS_HTML"

POL_RESP=$(curl -sf -X POST "http://127.0.0.1:$WEB_PORT/policies" \
    -d "priority=10&sender_pattern=*&recipient_pattern=*%40example.com&action=encrypt&on_missing_key=send_plain" \
    2>/dev/null || true)
assert_not_contains "add policy no error" "error" "$POL_RESP"

CONFIG_HTML=$(curl -sf "http://127.0.0.1:$WEB_PORT/config" 2>/dev/null || true)
assert_contains "config page loads" "Configuration" "$CONFIG_HTML"

# ── summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════"

[[ $FAIL -eq 0 ]] || exit 1
