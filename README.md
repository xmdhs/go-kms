# go-kms

KMS server/client simulator implemented in Go.

port of [py-kms](https://github.com/SystemRage/py-kms) by Claude Opus 4.6 & Qwen3.5-Plus

## Usage

### Start Server

```bash
go-kms server -ip 0.0.0.0 -port 1688
```

### Run Client

```bash
go-kms client -ip 127.0.0.1 -port 1688
```

## Options

### Server Options

| Option | Default | Description |
|--------|---------|-------------|
| `-ip` | 0.0.0.0 | Listen address |
| `-port` | 1688 | Listen port |
| `-epid` | Auto-generated | ePID |
| `-count` | 0 | Client count (0=auto) |
| `-hwid` | 364F463A8863D35F | Hardware ID |
| `-db` | - | Path to KmsDataBase.xml |

### Client Options

| Option | Default | Description |
|--------|---------|-------------|
| `-ip` | 127.0.0.1 | Server address |
| `-port` | 1688 | Server port |
| `-mode` | Windows8.1 | Product mode |
| `-name` | Auto-generated | Machine name |

## Build

```bash
go build -o go-kms.exe
```
