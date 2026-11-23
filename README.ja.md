# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Benchmarks](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml)
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
- **適応型 I/O** — 読み取り、書き込み、接続の受け付けはデフォルトでノンブロッキングです。デッドラインを設定すると、ソケットの準備ができていない間は待ち時間を延ばしながら再試行します。
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
└── RawSocket → RawConn (-tags rawsock, CAP_NET_RAW)
```

io_uring などの非同期 I/O では、`FD()` でソケットが所有する `*iofd.FD` を借用できます。この記述子を使う操作と、`SyscallConn` が返すハンドルに対する呼び出しがすべて終わってから、ソケットを閉じます。個別に閉じられる記述子が必要な場合は `s.FD().Dup()` を使います。

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

- **デフォルトはノンブロッキング** — ソケットの準備ができていない場合、`Read`、`Write`、`Accept` は `iox.ErrWouldBlock` を返します。準備完了の通知を受けてから再試行します。ループでポーリングする場合は `iox.Backoff` を使います。
- **デッドライン付きの再試行** — 接続またはリスナーで `SetDeadline` を呼ぶと、`sock` が再試行の間隔を調整します。接続では `SetReadDeadline` と `SetWriteDeadline` も使えます。
- **結果の分類** — バイト数と戻り値は処理がどこまで進んだかを示し、セマンティックエラーは呼び出し側が次の操作を選ぶ手がかりになります。接続処理が進行中の場合、`NetSocket.Connect` は `sock.ErrInProgress` を返します。上位のヘルパーは `iox.ErrMore`、`iox.Classify`、`iox.IsSemantic`、`iox.IsProgress` も使います。
- **TCP と SCTP の接続** — ハンドシェイクが進行中でも、`DialTCP`、`DialSCTP` およびそれぞれの IPv4・IPv6 版は接続と `nil` エラーを返します。同じ状況で `Timeout == 0` の `TCPDialer` と `SCTPDialer` は `(nil, sock.ErrInProgress)` を返します。

```go
conn, err := sock.DialTCP4(nil, raddr)
if err != nil {
	return err
}
defer conn.Close()
```

タイムアウトに正の値を指定すると、ダイヤラーはハンドシェイクの完了を待ちます。この例では最大 5 秒間待ちます。

```go
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, err := dialer.Dial4(nil, raddr)
if err != nil {
	return err
}
defer conn.Close()
```

## インストール

```bash
go get code.hybscloud.com/sock
```

## 使用方法

### TCP

接続待ちのキューが空の場合、`Accept` はデフォルトで `iox.ErrWouldBlock` を返します。この例ではリスナーと受け付けた接続に同じ期限を設定し、接続を待って最初のデータを読み取るまでを合計 5 秒に制限します。

```go
ln, err := sock.ListenTCP4(&sock.TCPAddr{Port: 8080})
if err != nil {
	return 0, err
}
defer ln.Close()

deadline := time.Now().Add(5 * time.Second)
ln.SetDeadline(deadline)
conn, err := ln.Accept()
if err != nil {
	return 0, err
}
defer conn.Close()

conn.SetReadDeadline(deadline)
return conn.Read(buf)
```

```go
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

SCTP アソシエーションを受け付けるには、[TCP サーバーの例](#tcp)で `sock.ListenSCTP4(&sock.SCTPAddr{Port: 9000})` を使います。

```go
// タイムアウト付きクライアント
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Unixドメインソケット

Unix ドメインのストリーム接続を受け付けるには、[TCP サーバーの例](#tcp)で `sock.ListenUnix("unix", &sock.UnixAddr{Name: "/tmp/app.sock"})` を使います。

```go
// データグラム
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// ソケットペア
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Rawソケット（-tags rawsock と CAP_NET_RAW が必要）

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
// net.TCPAddrを互換性のためにSockaddrに変換
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

## ベンチマーク

Linux で `make bench` を実行すると、`-cpu=1 -benchtime=200ms` で各ケースの処理時間とメモリ割り当てを 10 回ずつ計測します。個別に実行するには、`make bench BENCH=UDPDelivery` の `BENCH` に表の名前を指定します。

| ベンチマーク | 1 回の操作で測るもの |
|---|---|
| `UnixSocketPair_ReadWrite` | 接続済みの Unix ソケットペアの一方に 5 バイトを書き込み、もう一方で読み取ります。 |
| `UDPDelivery` | `sock` または Go の `net` で、IPv4 ループバックに 64 バイトまたは 1,200 バイトのデータグラムを 1 個送ります。受信側で検証を終えたものを `datagrams/s` とペイロードの `MB/s` に数えます。 |
| `UDPBatch` | `SendMessages` と `RecvMessages` による一括処理を、`WriteMsgUDP` と `ReadMsgUDP` による個別処理と比較します。1 回に送るのは 64 バイトのデータグラム 1 個、8 個、32 個、または 1,200 バイトのもの 8 個です。`ns/datagram` は受信 1 個あたりの時間、`datagrams/send-call` と `datagrams/recv-call` は各呼び出しあたりの個数、`allocs/op` は一連の送受信のメモリ割り当て回数です。 |
| `StreamDelivery` | 接続済みの IPv4 TCP ストリームと Unix ドメインストリームで `sock` と `net` を比較します。64 バイトの `ns/op` は受信側が内容を検証して完了を通知するまでの時間です。1 MiB では 4 KiB ずつ書く場合と 64 KiB ずつ書く場合のペイロードの `MB/s` を比較します。1 回に最大 64 KiB を読み取り、各バイトを一度だけ数えます。 |
| `WouldBlock` | 空の Unix ストリームからの読み取り、または満杯の Unix データグラムキューへの書き込みを行います。`ns/op` は `sock.UnixConn` またはそこから借用した `iofd.FD` の呼び出しが `iox.ErrWouldBlock` を返すまでの時間です。 |
| `TCPLifecycle` | IPv4 ループバックで `sock` と `net` を比較します。`listen` はソケットの作成、バインド、待ち受け、クローズを測ります。`connect` はリスナーを再利用し、接続、受け入れ、両端のアドレスの照合、両端のクローズまで終えた接続を `connections/s` に数えます。 |

リビジョンを比較するには、同じマシンでカーネルと Go のバージョンをそろえてそれぞれの出力を保存し、`benchstat before.txt after.txt` を実行します。Benchmarks ワークフローは各回の測定結果をジョブのサマリーに掲載し、ダウンロード用のファイルにも保存します。

## ライセンス

MIT。[LICENSE](./LICENSE)を参照。

©2025 [Hayabusa Cloud Co., Ltd.](https://code.hybscloud.com)
