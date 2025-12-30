# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Go言語向けゼロアロケーションソケット型とアドレス処理ライブラリ（Unixシステム）。

言語: [English](./README.md) | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | **日本語** | [Français](./README.fr.md)

## このパッケージを使用するタイミング

標準`net`パッケージの代わりに`sock`を使用するケース：

- **ゼロアロケーションホットパス** — Sockaddr型はヒープ割り当てなしで直接カーネル形式にエンコード
- **ノンブロッキングI/O** — ゴルーチンをブロックする代わりに即座に`iox.ErrWouldBlock`を返す
- **直接カーネル制御** — ソケットオプション、TCP_INFO、その他の低レベル機能
- **io_uring統合** — すべてのソケットが非同期I/O用に`iofd.FD`を公開

レイテンシが重要でない一般的なアプリケーションでは、標準`net`パッケージがよりシンプルで移植性の高いAPIを提供します。

## 特徴

- **ゼロアロケーションアドレス** — Sockaddr型はヒープ割り当てなしで直接カーネル形式にエンコード
- **プロトコルサポート** — TCP、UDP、SCTP、Unix（ストリーム/データグラム/シーケンスパケット）、Raw IP
- **io_uring対応** — すべてのソケットが非同期I/O統合用に`iofd.FD`を公開
- **ゼロオーバーヘッドシステムコール** — `zcall`アセンブリによる直接カーネル操作

## アーキテクチャ

### Sockaddrインターフェース

`Sockaddr`インターフェースはゼロアロケーションアドレス処理の基盤です：

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // カーネル形式を直接返す
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

アドレス型（`SockaddrInet4`、`SockaddrInet6`、`SockaddrUnix`）は生のカーネル構造体を埋め込み、ポインタを直接返します——マーシャリングなし、アロケーションなし。

### ソケット型階層

```
NetSocket（基底）
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (CAP_NET_RAW)
```

すべてのソケットは`FD() *iofd.FD`を公開し、io_uringや他の非同期I/Oメカニズムとの統合を可能にします。

### カーネル統合

```
アプリケーション
    ↓
sock.TCPConn.Write(data)
    ↓
iofd.FD.Write()
    ↓
zcall.Write() ← アセンブリエントリポイント（Goランタイムをバイパス）
    ↓
Linuxカーネル
```

`zcall`パッケージはGoランタイムのフックをバイパスする生のシステムコールエントリポイントを提供し、レイテンシクリティカルなパスのスケジューラオーバーヘッドを排除します。

### 適応型I/Oセマンティクス

本パッケージはノンブロッキングI/O向けの**Strike-Spin-Adapt**モデルを実装しています：

1. **Strike**: 直接システムコール実行（ノンブロッキング）
2. **Spin**: ハードウェアレベル同期（必要に応じて`sox`が処理）
3. **Adapt**: デッドライン設定時の`iox.Backoff`によるソフトウェアバックオフ

**主な動作：**

- **デフォルトでノンブロッキング**: `Read`、`Write`、`Accept`、`Dial`操作はカーネルが準備できていない場合、即座に`iox.ErrWouldBlock`を返します。
- **デッドライン駆動の適応**: デッドラインが明示的に設定された場合（`SetDeadline`、`SetReadDeadline`、`SetWriteDeadline`経由）のみ、操作は漸進的バックオフ付きのリトライループに入ります。
- **ノンブロッキングDial**: `net.Dial`と異なり、`DialTCP4`などの関数は接続試行開始後すぐに戻ります。TCPハンドシェイクはまだ進行中の場合があります（`ErrInProgress`は暗黙的に無視されます）。ブロッキング動作にはタイムアウト付きの`TCPDialer`を使用してください：

```go
// ノンブロッキング（即座に戻る、ハンドシェイクは進行中の可能性あり）
conn, _ := sock.DialTCP4(nil, raddr)

// タイムアウト付きブロッキング（接続完了またはタイムアウトまで待機）
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, raddr)
```

## インストール

```bash
go get code.hybscloud.com/sock
```

## 使用方法

### TCP

```go
// サーバー
ln, _ := sock.ListenTCP4(&sock.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
conn, _ := ln.Accept()
conn.Read(buf)
conn.Close()

// クライアント
conn, _ := sock.DialTCP4(nil, &sock.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
conn.SetNoDelay(true)
conn.Write(data)
```

### UDP

```go
// サーバー
conn, _ := sock.ListenUDP4(&sock.UDPAddr{Port: 5353})
n, addr, _ := conn.ReadFrom(buf)
conn.WriteTo(response, addr)

// クライアント
conn, _ := sock.DialUDP4(nil, &sock.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
conn.Write(query)
conn.Read(response)
```

### SCTP（Linuxのみ）

```go
// サーバー
ln, _ := sock.ListenSCTP4(&sock.SCTPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9000})
conn, _ := ln.Accept()
conn.Read(buf)

// タイムアウト付きクライアント
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Unixドメインソケット

```go
// ストリーム
ln, _ := sock.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/app.sock"})
conn, _ := ln.Accept()

// データグラム
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// ソケットペア
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Rawソケット（CAP_NET_RAW必要）

```go
// ICMP ping
sock, _ := sock.NewICMPSocket4()
sock.SendTo(icmpPacket, &net.IPAddr{IP: net.ParseIP("8.8.8.8")})
n, addr, _ := sock.RecvFrom(buf)
```

### ソケットオプション

```go
// TCPチューニング
conn.SetNoDelay(true)              // Nagleアルゴリズム無効化
conn.SetKeepAlive(true)            // キープアライブプローブ有効化
conn.SetKeepAlivePeriod(30 * time.Second)

// バッファサイズ
sock.SetSendBuffer(conn.FD(), 256*1024)
sock.SetRecvBuffer(conn.FD(), 256*1024)

// クローズ時に即座にRSTを送信するSO_LINGER
sock.SetLinger(conn.FD(), true, 0)
```

### エラー処理

```go
// iox.ErrWouldBlockを使用したノンブロッキング読み取り
n, err := conn.Read(buf)
if err == iox.ErrWouldBlock {
    // カーネル準備未完了、イベントループと統合するか後でリトライ
    return
}
if err != nil {
    // 実際のエラー（接続リセット、クローズなど）
    return
}

// デッドライン付きブロッキング読み取り
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err = conn.Read(buf)
if err == sock.ErrTimedOut {
    // デッドライン超過
}
```

### netパッケージとの互換性

本パッケージはGo標準の`net`型とシームレスに変換できます：

```go
// net.TCPAddrをSockaddrに変換（ゼロアロケーション）
netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
sockaddr := sock.TCPAddrToSockaddr(netAddr)

// net.TCPAddrに戻す
tcpAddr := sock.SockaddrToTCPAddr(sockaddr)

// 互換性のための型エイリアス
var _ sock.Conn = conn      // net.Conn互換
var _ sock.Addr = addr      // net.Addr互換

// 注意：リスナーはゼロアロケーション性能のため、net.Listenerが要求する
// net.Connではなく、具体的な型（*TCPConn, *UnixConn）を返します。
```

## サポートプラットフォーム

| プラットフォーム | 状態 |
|-----------------|------|
| linux/amd64 | フル |
| linux/arm64 | フル |
| linux/riscv64 | フル |
| linux/loong64 | フル |
| darwin/arm64 | 部分的（SCTP、TCPInfo、マルチキャスト、SCM_RIGHTSなし）|
| freebsd/amd64 | クロスコンパイルのみ |

## ライセンス

MIT — [LICENSE](./LICENSE)を参照。

©2025 Hayabusa Cloud Co., Ltd.
