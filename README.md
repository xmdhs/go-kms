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

## Android APK

本仓库包含 `android/` Android 包装器。App 提供 `server` 和 `client` 命令行参数界面，以子进程方式运行 Go 二进制，并通过 Android 前台服务保活服务端。

Android 10+ 会限制执行复制到 app 私有可写目录中的文件。为规避该限制，GitHub Actions 会把 Android ELF 可执行文件命名为 `libgo_kms.so`，打包到 `jniLibs/<abi>/`，App 再从 `applicationInfo.nativeLibraryDir` 执行该二进制。

通过 GitHub Actions 构建 APK：

1. 打开 **Android APK** workflow。
2. 手动运行 `workflow_dispatch`，或推送到 `master` / `v*` tag。
3. 下载 `go-kms-android-debug-apk` artifact。

workflow 使用 Android NDK 构建 `arm64-v8a`、`armeabi-v7a` 和 `x86_64` 二进制，然后在 CI 中运行 Gradle APK 构建。
