# go-kms (Rust port)

KMS server / client emulator written in Rust. Functional and byte-level wire-format compatible with the original Go implementation (now kept under `reference/` for parity testing).

Originally ported from [py-kms](https://github.com/SystemRage/py-kms).

## Build

```bash
cargo build --release
# binary at target/release/go-kms
```

## Usage

### Start the server

```bash
go-kms server -ip 0.0.0.0 -port 1688
```

### Run the client

```bash
go-kms client -ip 127.0.0.1 -port 1688 -mode Windows8.1
```

List available product modes:

```bash
go-kms client -mode list
```

### Server options

| Option | Default | Description |
|--------|---------|-------------|
| `-ip` | 0.0.0.0 | Listen address |
| `-port` | 1688 | Listen port |
| `-epid` | Auto-generated | ePID |
| `-lcid` | 1033 | Locale ID for ePID generation |
| `-count` | 0 | Client count (0 = auto) |
| `-activation` | 120 | Activation interval (minutes) |
| `-renewal` | 10080 | Renewal interval (minutes) |
| `-hwid` | 364F463A8863D35F | Hardware ID (16 hex chars; `RANDOM` for random) |

### Client options

| Option | Default | Description |
|--------|---------|-------------|
| `-ip` | 127.0.0.1 | Server address |
| `-port` | 1688 | Server port |
| `-mode` | Windows8.1 | Product mode (use `list` to enumerate) |
| `-cmid` | Auto-generated | Client Machine ID |
| `-name` | Auto-generated | Machine name |

## Repository layout

```
.
├── Cargo.toml         Rust package
├── src/               Rust sources
│   ├── crypto/        AES (V4 160-bit, V5 standard, V6 round-patched), PKCS7, V4Hash, V6 HMAC
│   ├── kms/           UUID, FileTime, UTF-16LE, KMS request/response, V4/V5/V6 protocol handlers
│   ├── rpc.rs         MS-RPC bind / request / response framing
│   ├── server.rs      tokio TCP server
│   ├── client.rs      tokio TCP client + product table
│   ├── logger.rs      Minimal structured stderr logger
│   └── main.rs        CLI entry point
├── tests/             cargo tests (crypto / kms / rpc unit, parity, end-to-end)
├── reference/         Original Go implementation, kept for cross-language parity
│   ├── cmd/genvectors Emits tests/vectors.json — byte-level test fixtures
│   └── ...            kms/, crypto/, rpc/, server/, client/, logger/, main.go
└── .github/workflows/ci.yml   CI pipeline (Linux x86_64)
```

## Testing strategy

- **Rust unit tests** (`tests/crypto_unit.rs`, `tests/kms_unit.rs`, `tests/rpc_unit.rs`) verify each module in isolation, with the same fixed vectors used by the Go test suite.
- **Parity tests** (`tests/parity.rs`) load `tests/vectors.json` (produced by `reference/cmd/genvectors`) and assert every Rust output matches Go byte-for-byte: PKCS7, AES blocks, AES-CBC, V4Hash, V6 MAC key / HMAC, UUID, FileTime, UTF-16LE, KMS request/response wire formats, MS-RPC bind/bind-ack/request/response framing, `handle_v4_request` end-to-end, `server_logic`, and deterministic V5/V6 envelope construction.
- **End-to-end tests** (`tests/e2e.rs`) start the Rust server on an ephemeral port and run the Rust client against it for V4 / V5 / V6 protocol versions.
- **Go reference tests** (`reference/...`) continue to pass under `cd reference && go test ./...`.

CI (`.github/workflows/ci.yml`) regenerates `tests/vectors.json`, runs both Go and Rust test suites, and uploads the release binary.

## Local development

Without Go installed, you can still run the Rust unit tests and end-to-end tests (skip parity tests):

```bash
cargo test --test crypto_unit --test kms_unit --test rpc_unit --test e2e
```

If you have both Go and Rust:

```bash
( cd reference && go run ./cmd/genvectors ../tests/vectors.json )
cargo test --all-targets
```
