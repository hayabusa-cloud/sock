# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Types de socket sans allocation et machinerie d'adresses pour systèmes Unix en Go.

Langue: [English](./README.md) | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | [日本語](./README.ja.md) | **Français**

## Quand Utiliser Ce Package

Utilisez `sock` au lieu du package standard `net` quand vous avez besoin de :

- **Chemins chauds sans allocation** — Les types Sockaddr encodent directement au format noyau sans allocation sur le tas
- **I/O non bloquante** — Les opérations retournent `iox.ErrWouldBlock` immédiatement au lieu de bloquer les goroutines
- **Contrôle direct du noyau** — Options de socket, TCP_INFO et autres fonctionnalités bas niveau
- **Intégration io_uring** — Tous les sockets exposent `iofd.FD` pour l'I/O asynchrone

Pour les applications typiques où la latence n'est pas critique, le package standard `net` fournit une API plus simple et plus portable.

## Caractéristiques

- **Adresses Sans Allocation** — Les types Sockaddr encodent directement au format noyau sans allocation sur le tas
- **Support des Protocoles** — TCP, UDP, SCTP, Unix (stream/dgram/seqpacket), Raw IP
- **Prêt pour io_uring** — Tous les sockets exposent `iofd.FD` pour l'intégration I/O asynchrone
- **Appels Système Sans Overhead** — Interaction directe avec le noyau via assembleur `zcall`

## Architecture

### Interface Sockaddr

L'interface `Sockaddr` est la base du traitement d'adresses sans allocation :

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Format noyau direct
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Les types d'adresse (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embarquent les structures noyau brutes et retournent des pointeurs directement—pas de marshaling, pas d'allocation.

### Hiérarchie des Types de Socket

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (CAP_NET_RAW)
```

Tous les sockets exposent `FD() *iofd.FD` pour l'intégration avec io_uring et autres mécanismes d'I/O asynchrone.

### Intégration Noyau

```
Application
    ↓
sock.TCPConn.Write(data)
    ↓
iofd.FD.Write()
    ↓
zcall.Write() ← Point d'entrée assembleur (sans runtime Go)
    ↓
Noyau Linux
```

Le package `zcall` fournit des points d'entrée syscall bruts qui contournent les hooks du runtime Go, éliminant l'overhead du scheduler pour les chemins critiques en latence.

### Sémantiques d'I/O Adaptative

Le package implémente le modèle **Strike-Spin-Adapt** pour l'I/O non bloquante :

1. **Strike** : Exécution directe de syscall (non bloquante)
2. **Spin** : Synchronisation au niveau matériel (gérée par `sox` si nécessaire)
3. **Adapt** : Backoff logiciel ajusté pour le réseau lorsque des deadlines sont définis

**Comportements clés :**

- **Non bloquant par défaut** : Les opérations `Read`, `Write`, `Accept` et `Dial` retournent immédiatement avec `iox.ErrWouldBlock` si le noyau n'est pas prêt.
- **Adaptation pilotée par deadline** : Ce n'est que lorsqu'un deadline est explicitement défini (via `SetDeadline`, `SetReadDeadline` ou `SetWriteDeadline`) que l'opération entre dans une boucle de réessai avec backoff progressif.
- **Dial non bloquant** : Contrairement à `net.Dial`, les fonctions comme `DialTCP4` retournent immédiatement une fois la tentative de connexion lancée. Le handshake TCP peut encore être en cours (`ErrInProgress` est ignoré silencieusement). Utilisez `TCPDialer` avec un timeout pour un comportement bloquant :

```go
// Non bloquant (retourne immédiatement, handshake peut être en cours)
conn, _ := sock.DialTCP4(nil, raddr)

// Bloquant avec timeout (attend la connexion ou le timeout)
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, raddr)
```

## Installation

```bash
go get code.hybscloud.com/sock
```

## Utilisation

### TCP

```go
// Serveur
ln, _ := sock.ListenTCP4(&sock.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
conn, _ := ln.Accept()
conn.Read(buf)
conn.Close()

// Client
conn, _ := sock.DialTCP4(nil, &sock.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
conn.SetNoDelay(true)
conn.Write(data)
```

### UDP

```go
// Serveur
conn, _ := sock.ListenUDP4(&sock.UDPAddr{Port: 5353})
n, addr, _ := conn.ReadFrom(buf)
conn.WriteTo(response, addr)

// Client
conn, _ := sock.DialUDP4(nil, &sock.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
conn.Write(query)
conn.Read(response)
```

### SCTP (Linux uniquement)

```go
// Serveur
ln, _ := sock.ListenSCTP4(&sock.SCTPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9000})
conn, _ := ln.Accept()
conn.Read(buf)

// Client avec timeout
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Sockets de Domaine Unix

```go
// Stream
ln, _ := sock.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/app.sock"})
conn, _ := ln.Accept()

// Datagramme
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// Paire de sockets
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Sockets Raw (nécessite CAP_NET_RAW)

```go
// ICMP ping
sock, _ := sock.NewICMPSocket4()
sock.SendTo(icmpPacket, &net.IPAddr{IP: net.ParseIP("8.8.8.8")})
n, addr, _ := sock.RecvFrom(buf)
```

### Options de Socket

```go
// Réglage TCP
conn.SetNoDelay(true)              // Désactiver l'algorithme de Nagle
conn.SetKeepAlive(true)            // Activer les sondes keepalive
conn.SetKeepAlivePeriod(30 * time.Second)

// Tailles de buffer
sock.SetSendBuffer(conn.FD(), 256*1024)
sock.SetRecvBuffer(conn.FD(), 256*1024)

// SO_LINGER pour RST immédiat à la fermeture
sock.SetLinger(conn.FD(), true, 0)

// TCP_USER_TIMEOUT pour détection de connexions mortes (Linux)
sock.SetTCPUserTimeout(conn.FD(), 30000)  // 30 secondes en millisecondes

// TCP_NOTSENT_LOWAT pour réduire la mémoire et la latence (Linux)
sock.SetTCPNotsentLowat(conn.FD(), 16384)

// SO_BUSY_POLL pour polling basse latence (Linux)
sock.SetBusyPoll(conn.FD(), 50)  // 50 microsecondes
```

### Opérations UDP par Lots (Linux)

```go
// Envoyer plusieurs messages en un seul appel système
msgs := []sock.UDPMessage{
    {Addr: addr1, Buffers: [][]byte{data1}},
    {Addr: addr2, Buffers: [][]byte{data2}},
}
n, _ := conn.SendMessages(msgs)

// Recevoir plusieurs messages
recvMsgs := []sock.UDPMessage{
    {Buffers: [][]byte{make([]byte, 1500)}},
    {Buffers: [][]byte{make([]byte, 1500)}},
}
n, _ = conn.RecvMessages(recvMsgs)

// UDP GSO (Generic Segmentation Offload)
sock.SetUDPSegment(conn.FD(), 1400)  // Taille de segment

// UDP GRO (Generic Receive Offload)
sock.SetUDPGRO(conn.FD(), true)
```

### Gestion des Erreurs

```go
// Lecture non bloquante avec iox.ErrWouldBlock
n, err := conn.Read(buf)
if err == iox.ErrWouldBlock {
    // Noyau pas prêt, intégrer avec event loop ou réessayer plus tard
    return
}
if err != nil {
    // Erreur réelle (connexion réinitialisée, fermée, etc.)
    return
}

// Lecture bloquante avec deadline
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err = conn.Read(buf)
if err == sock.ErrTimedOut {
    // Deadline dépassé
}
```

### Compatibilité avec le Package net

Le package fournit une conversion transparente avec les types standard Go `net` :

```go
// Convertir net.TCPAddr en Sockaddr (sans allocation)
netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
sockaddr := sock.TCPAddrToSockaddr(netAddr)

// Reconvertir en net.TCPAddr
tcpAddr := sock.SockaddrToTCPAddr(sockaddr)

// Alias de types pour la compatibilité
var _ sock.Conn = conn      // Compatible net.Conn
var _ sock.Addr = addr      // Compatible net.Addr

// Note : Les listeners retournent des types concrets (*TCPConn, *UnixConn) pour
// des performances sans allocation, pas net.Conn comme requis par net.Listener.
```

## Plateformes Supportées

| Plateforme | Statut |
|------------|--------|
| linux/amd64 | Complet |
| linux/arm64 | Complet |
| linux/riscv64 | Complet |
| linux/loong64 | Complet |
| darwin/arm64 | Partiel (sans SCTP, TCPInfo, multicast, SCM_RIGHTS) |
| freebsd/amd64 | Cross-compile uniquement |

## Licence

MIT — voir [LICENSE](./LICENSE).

©2025 Hayabusa Cloud Co., Ltd.
