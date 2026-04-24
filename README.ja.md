# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Go言語向けゼロアロケーションソケット型とアドレス処理ライブラリ（Unixシステム）。

言語: [English](./README.md) | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | **日本語** | [Français](./README.fr.md)

## 概要

`sock` は、ゼロアロケーションの sockaddr エンコード、ノンブロッキングなソケット操作、ソケットオプション制御、および非同期 I/O ランタイムと統合するための `iofd.FD` アクセスを提供します。

## 操作

- **ゼロアロケーションアドレス** — Sockaddr 型はカーネル向け構造体へ直接エンコード；`Raw()` はマーシャリングなし・ヒープ確保なしで `unsafe.Pointer` を返します。
- **ゼロオーバーヘッドシステムコール** — すべての I/O パスは `zcall` アセンブリエントリポイントを通じてカーネルを直接呼び出し、Go ランタイムスケジューラを経由しません。
- **プロトコルサポート** — TCP、UDP、SCTP、Unix ドメイン（stream/dgram/seqpacket）、および raw IP ソケット；各プロトコルで IPv4・IPv6 に対応。
- **適応型 I/O** — 三層プログレスモデル（Strike-Spin-Adapt）：デフォルトで操作は即座に `iox.ErrWouldBlock` を返し、デッドラインが設定された場合のみバックオフリトライを有効化します
- **io_uring 対応** — すべてのソケットは `FD() *iofd.FD` でファイルディスクリプタを公開し、`uring`・`takt` などの非同期 I/O ランタイムと直接統合できます。
- **UDP バッチ I/O** — `SendMessages`/`RecvMessages` は `sendmmsg(2)`/`recvmmsg(2)` を使用し、1 回のシステムコールで複数のデータグラムを処理；適応型バリアントはデッドラインに対応。
- **ネットワークリンク照会** — `Links`・`LinkByName`・`LinkByIndex` は `zcall` を通じた Linux ネイティブのリンク列挙を提供；内部で IPv6 ゾーン ID 解決に使用。
- **ソケットオプション制御** — SO_KEEPALIVE・TCP_NODELAY・SO_LINGER・TCP_USER_TIMEOUT・TCP_NOTSENT_LOWAT・SO_BUSY_POLL・UDP_SEGMENT・UDP_GRO など向けの型安全なヘルパー。

## アーキテクチャ

### Sockaddrインターフェース

`Sockaddr`インターフェースはゼロアロケーションアドレス処理の基盤です：

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // カーネル形式を直接返す
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

アドレス型（`SockaddrInet4`、`SockaddrInet6`、`SockaddrUnix`）は生のカーネル構造体を埋め込み、マーシャリングやアロケーションなしでポインタを直接返します。

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

`zcall`パッケージは、`sock` からカーネルへ直接アクセスするための生のシステムコールエントリポイントを提供します。

### 適応型I/Oセマンティクス

本パッケージはノンブロッキングI/O向けの**三層プログレスモデル**（Strike-Spin-Adapt）に従います：

1. **Strike**: システムコール — `zcall`経由でカーネルへ直接呼び出し
2. **Spin**: ハードウェアイールド — ローカルアトミック同期（`spin.Pause`）
3. **Adapt**: ソフトウェアバックオフ — 外部I/O準備待ち（漸進的スリープ）

sockは**Strike**と**Adapt**を実装します。ソケット操作はカーネルやネットワークピアを待機するため、ローカルアトミックスではなく、Spinは使用しません。

**主な動作：**

- **デフォルトでノンブロッキング**: `Read`、`Write`、`Accept`、`Dial`操作はカーネルが準備できていない場合、即座に`iox.ErrWouldBlock`を返します。
- **デッドライン駆動の適応**: デッドラインが明示的に設定された場合（`SetDeadline`、`SetReadDeadline`、`SetWriteDeadline`経由）のみ、操作は漸進的バックオフ付きのリトライループに入ります。
- **結果分類**: 進捗はバイト数や戻り値の側に載り、制御はセマンティックエラーの側に載ります。`sock` の直接呼び出しは、未準備時には主に
  `iox.ErrWouldBlock`、接続保留中には `ErrInProgress` を返します。`iox.ErrMore`、`Classify`、`IsSemantic`、`IsProgress` は、
  `sock` の上に積まれたヘルパー層でも使う共有の分類語彙です。
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

// TCP_USER_TIMEOUT 死んだ接続を検出（Linux）
sock.SetTCPUserTimeout(conn.FD(), 30000)  // 30秒（ミリ秒）

// TCP_NOTSENT_LOWAT メモリとレイテンシを削減（Linux）
sock.SetTCPNotsentLowat(conn.FD(), 16384)

// SO_BUSY_POLL 低レイテンシポーリング（Linux）
sock.SetBusyPoll(conn.FD(), 50)  // 50マイクロ秒
```

### UDPバッチ操作（Linux）

```go
// 単一のシステムコールで複数メッセージを送信
msgs := []sock.UDPMessage{
    {Addr: addr1, Buffers: [][]byte{data1}},
    {Addr: addr2, Buffers: [][]byte{data2}},
}
n, _ := conn.SendMessages(msgs)

// 複数メッセージを受信
recvMsgs := []sock.UDPMessage{
    {Buffers: [][]byte{make([]byte, 1500)}},
    {Buffers: [][]byte{make([]byte, 1500)}},
}
n, _ = conn.RecvMessages(recvMsgs)

// UDP GSO（汎用セグメンテーションオフロード）
sock.SetUDPSegment(conn.FD(), 1400)  // セグメントサイズ

// UDP GRO（汎用受信オフロード）
sock.SetUDPGRO(conn.FD(), true)
```

### Linux ネットワークリンク

```go
links, _ := sock.Links()
lo, _ := sock.LinkByName("lo")
byIndex, _ := sock.LinkByIndex(lo.Index)
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

## プラットフォームサポート

| プラットフォーム | 状態 |
|-----------------|------|
| linux/amd64 | フル |
| linux/arm64 | フル |
| linux/riscv64 | フル |
| linux/loong64 | フル |
| darwin/arm64 | 部分的 |
| freebsd/amd64 | クロスコンパイルのみ |

## ライセンス

MIT。[LICENSE](./LICENSE)を参照。

©2025 [Hayabusa Cloud Co., Ltd.](https://code.hybscloud.com)
