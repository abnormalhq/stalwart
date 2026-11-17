#!/usr/bin/env bash
set -euo pipefail

FDB_VERSION=7.4.10
CLIENT_SHA256=0ea71ffd3da3a346dd8a7efc71b729ea36a2b9a6e8ae2bac97f6684211009ac9
SERVER_SHA256=6ef9c593ca9ff8ba4e74bc6ebbb38f05b0e4b7d499ec98a7dfefda9907d32341
FDB_RELEASE_URL="https://github.com/apple/foundationdb/releases/download/$FDB_VERSION"
CLIENT_ASSET="foundationdb-clients_${FDB_VERSION}-1_amd64.deb"
SERVER_ASSET="foundationdb-server_${FDB_VERSION}-1_amd64.deb"

TMP_ROOT="${TMPDIR:-${RUNNER_TEMP:-/tmp}}"
if [[ ! -d "$TMP_ROOT" ]]; then
    echo "Temporary directory does not exist: $TMP_ROOT" >&2
    exit 1
fi
TMP_ROOT="$(cd "$TMP_ROOT" && pwd -P)"
RUN_DIR="$(mktemp -d "$TMP_ROOT/stalwart-recovery-fdb-test-XXXXXXXX")"
CLUSTER_FILE="$RUN_DIR/fdb.cluster"
SERVER_PID=""

cleanup() {
    local status=$?
    local process_args=""
    local process_state=""

    trap - EXIT INT TERM
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        process_args="$(ps -p "$SERVER_PID" -o args= 2>/dev/null || true)"
        if [[ "$process_args" == *"$CLUSTER_FILE"* && "$process_args" == *"$RUN_DIR/data"* ]]; then
            kill -INT "$SERVER_PID" 2>/dev/null || true
            for _ in {1..50}; do
                process_state="$(ps -p "$SERVER_PID" -o stat= 2>/dev/null || true)"
                if [[ -z "$process_state" || "$process_state" == Z* ]]; then
                    break
                fi
                sleep 0.2
            done
            if kill -0 "$SERVER_PID" 2>/dev/null; then
                process_state="$(ps -p "$SERVER_PID" -o stat= 2>/dev/null || true)"
                if [[ -n "$process_state" && "$process_state" != Z* ]]; then
                    kill -TERM "$SERVER_PID" 2>/dev/null || true
                fi
            fi
            wait "$SERVER_PID" 2>/dev/null || true
        else
            echo "Refusing to signal unexpected process with PID $SERVER_PID" >&2
            status=1
        fi
    fi

    case "$RUN_DIR" in
        "$TMP_ROOT"/stalwart-recovery-fdb-test-*) rm -rf -- "$RUN_DIR" ;;
        *)
            echo "Refusing to remove unexpected temporary directory: $RUN_DIR" >&2
            status=1
            ;;
    esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in curl dpkg-deb python3 sha256sum; do
    command -v "$command" >/dev/null || {
        echo "Required command is missing: $command" >&2
        exit 1
    }
done

mkdir -p "$RUN_DIR/client-root" "$RUN_DIR/server-root" "$RUN_DIR/data" "$RUN_DIR/log"
CLIENT_DEB="$RUN_DIR/$CLIENT_ASSET"
SERVER_DEB="$RUN_DIR/$SERVER_ASSET"

curl --fail --location --silent --show-error --retry 3 \
    --output "$CLIENT_DEB" "$FDB_RELEASE_URL/$CLIENT_ASSET"
curl --fail --location --silent --show-error --retry 3 \
    --output "$SERVER_DEB" "$FDB_RELEASE_URL/$SERVER_ASSET"
printf '%s  %s\n' "$CLIENT_SHA256" "$CLIENT_DEB" | sha256sum --check --status
printf '%s  %s\n' "$SERVER_SHA256" "$SERVER_DEB" | sha256sum --check --status
echo "Verified official FoundationDB $FDB_VERSION client/server asset SHA-256 digests."

dpkg-deb -x "$CLIENT_DEB" "$RUN_DIR/client-root"
dpkg-deb -x "$SERVER_DEB" "$RUN_DIR/server-root"
FDB_CLI="$RUN_DIR/client-root/usr/bin/fdbcli"
FDB_SERVER="$RUN_DIR/server-root/usr/sbin/fdbserver"
FDB_C_LIBRARY="$(find "$RUN_DIR/client-root" \( -type f -o -type l \) -name 'libfdb_c.so*' -print -quit)"
if [[ ! -x "$FDB_CLI" || ! -x "$FDB_SERVER" || -z "$FDB_C_LIBRARY" ]]; then
    echo "FoundationDB $FDB_VERSION package extraction is incomplete" >&2
    exit 1
fi
FDB_LIB_DIR="$(dirname "$FDB_C_LIBRARY")"
export LD_LIBRARY_PATH="$FDB_LIB_DIR:$RUN_DIR/server-root/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBRARY_PATH="$FDB_LIB_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"

SERVER_VERSION="$("$FDB_SERVER" --version)"
CLIENT_VERSION="$("$FDB_CLI" --version)"
printf '%s\n%s\n' "$SERVER_VERSION" "$CLIENT_VERSION"
if [[ "$SERVER_VERSION" != *"v$FDB_VERSION"* || "$CLIENT_VERSION" != *"v$FDB_VERSION"* ]]; then
    echo "FoundationDB client/server version mismatch" >&2
    exit 1
fi

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
if ((PORT < 30000)); then
    echo "Selected test port is not a high port: $PORT" >&2
    exit 1
fi
CLUSTER_ID="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
printf 'stalwart_recovery_test:%s@127.0.0.1:%s\n' "$CLUSTER_ID" "$PORT" > "$CLUSTER_FILE"
chmod 600 "$CLUSTER_FILE"

"$FDB_SERVER" \
    --public-address "127.0.0.1:$PORT" \
    --listen-address "127.0.0.1:$PORT" \
    --cluster-file "$CLUSTER_FILE" \
    --datadir "$RUN_DIR/data" \
    --logdir "$RUN_DIR/log" \
    --memory 512 --storage-memory 256 --cache-memory 128 \
    >"$RUN_DIR/server.stdout" 2>&1 &
SERVER_PID=$!

LISTENING=0
for _ in {1..100}; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$RUN_DIR/server.stdout" >&2
        echo "FoundationDB server exited before listening" >&2
        exit 1
    fi
    if python3 -c 'import socket,sys; s=socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5); s.close()' "$PORT" 2>/dev/null; then
        LISTENING=1
        break
    fi
    sleep 0.1
done
if [[ "$LISTENING" -ne 1 ]]; then
    cat "$RUN_DIR/server.stdout" >&2
    echo "FoundationDB server did not bind its loopback port" >&2
    exit 1
fi

"$FDB_CLI" -C "$CLUSTER_FILE" --exec "configure new single memory"
READY=0
for _ in {1..60}; do
    if "$FDB_CLI" -C "$CLUSTER_FILE" --exec "status" > "$RUN_DIR/status.log" 2>&1 \
        && grep -Fq 'FoundationDB processes - 1' "$RUN_DIR/status.log"; then
        READY=1
        break
    fi
    sleep 1
done
if [[ "$READY" -ne 1 ]]; then
    cat "$RUN_DIR/status.log" >&2
    cat "$RUN_DIR/server.stdout" >&2
    echo "FoundationDB cluster did not become ready" >&2
    exit 1
fi
cat "$RUN_DIR/status.log"

export STALWART_FDB_TEST_ALLOW_LOOPBACK=1
export STALWART_FDB_TEST_CLUSTER_FILE="$CLUSTER_FILE"
export TMPDIR="$RUN_DIR"
export CARGO_INCREMENTAL=0
export CARGO_TERM_COLOR=never

TEST_LOG="$RUN_DIR/test.log"
cargo test --locked -p common --no-default-features \
    --features recovery-test-foundationdb \
    message_recovery::tests::foundationdb_recovery_metadata_chunk_lifecycle \
    -- --ignored --exact --nocapture 2>&1 | tee "$TEST_LOG"

if ! grep -Fqx 'test message_recovery::tests::foundationdb_recovery_metadata_chunk_lifecycle ... ok' "$TEST_LOG" \
    || ! grep -Eq '^test result: ok\. 1 passed; 0 failed;' "$TEST_LOG"; then
    echo "FoundationDB recovery regression was not selected and passed" >&2
    exit 1
fi
