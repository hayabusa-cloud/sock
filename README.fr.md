# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Benchmarks](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Types de socket sans allocation et machinerie d'adresses pour systèmes Unix en Go.

Langue: [English](./README.md) | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | [日本語](./README.ja.md) | **Français**

## Vue d'ensemble

`sock` fournit un encodage sockaddr sans allocation, des opérations de socket non bloquantes, le contrôle des options de socket et l'accès à `iofd.FD` pour l'intégration avec des runtimes d'I/O asynchrone.

## Opérations

- **Adresses sans allocation** — Les types Sockaddr s'encodent directement en structures orientées noyau ; `Raw()` retourne un `unsafe.Pointer` sans marshaling ni allocation sur le tas.
- **Syscalls sans surcharge** — Tous les chemins d'I/O utilisent des points d'entrée assembleur `zcall` qui appellent le noyau directement, sans passer par l'ordonnanceur du runtime Go.
- **Support de protocoles** — TCP, UDP, SCTP, Unix domain (stream/dgram/seqpacket) et sockets IP bruts ; IPv4 et IPv6 pour chaque protocole.
- **E/S adaptatives** — Par défaut, la lecture, l’écriture et l’acceptation des connexions sont non bloquantes. Si le socket n’est pas prêt, définir une échéance permet de réessayer à intervalles croissants.
- **Prêt pour io_uring** — Chaque socket expose `FD() *iofd.FD` pour une intégration directe avec `uring`, `takt` et autres runtimes d'I/O asynchrone.
- **I/O UDP par lots** — `SendMessages`/`RecvMessages` utilisent `sendmmsg(2)`/`recvmmsg(2)` pour traiter plusieurs datagrammes par syscall ; les variantes adaptatives ajoutent le support des deadlines.
- **Requêtes de liens réseau** — `Links`, `LinkByName` et `LinkByIndex` fournissent une énumération Linux native des liens via `zcall` ; utilisés en interne pour la résolution des identifiants de zone IPv6.
- **Contrôle des options de socket** — Aides typées pour SO_KEEPALIVE, TCP_NODELAY, SO_LINGER, TCP_USER_TIMEOUT, TCP_NOTSENT_LOWAT, SO_BUSY_POLL, UDP_SEGMENT, UDP_GRO, et plus.

## Architecture

### Interface Sockaddr

L'interface `Sockaddr` est la base du traitement d'adresses sans allocation :

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Format noyau direct
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Les types d'adresse (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embarquent les structures noyau brutes et retournent des pointeurs directement, sans marshaling et sans allocation.

### Hiérarchie des Types de Socket

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (-tags rawsock, CAP_NET_RAW)
```

Pour utiliser io_uring ou d’autres mécanismes d’E/S asynchrones, `FD()` donne accès au `*iofd.FD` qui appartient au socket. Gardez le socket ouvert jusqu’à la fin des opérations utilisant ce descripteur ou l’interface renvoyée par `SyscallConn`. Utilisez `s.FD().Dup()` pour obtenir un descripteur que vous pouvez fermer séparément.

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

Le package `zcall` fournit des points d'entrée syscall bruts pour l'interaction directe avec le noyau depuis `sock`.

### Sémantiques d'I/O Adaptative

Le package suit le **Modèle de Progression à Trois Niveaux** (Strike-Spin-Adapt) pour l'I/O non bloquante :

1. **Strike** : Appel système — accès direct au noyau via `zcall`
2. **Spin** : Yield matériel — synchronisation atomique locale (`spin.Pause`)
3. **Adapt** : Backoff logiciel — attente de disponibilité I/O externe (sommeil progressif)

sock implémente **Strike** et **Adapt**. Spin n'est pas utilisé ici car les opérations socket attendent le noyau ou un pair réseau, pas des atomiques locaux.

**Comportements clés :**

- **Opérations non bloquantes par défaut** — `Read`, `Write` et `Accept` renvoient `iox.ErrWouldBlock` si le socket n’est pas prêt.
- **Adaptation pilotée par deadline** : Ce n'est que lorsqu'un deadline est explicitement défini (via `SetDeadline`, `SetReadDeadline` ou `SetWriteDeadline`) que l'opération entre dans une boucle de réessai avec backoff progressif.
- **Classification des résultats** — Le nombre d’octets et les valeurs renvoyées indiquent la progression. Les erreurs sémantiques guident la prochaine opération. `NetSocket.Connect` renvoie `sock.ErrInProgress` si la connexion est en cours d’établissement. Les fonctions de plus haut niveau utilisent aussi `iox.ErrMore`, `iox.Classify`, `iox.IsSemantic` et `iox.IsProgress`.
- **Connexions TCP et SCTP** — Pendant l’établissement de la connexion, `DialTCP`, `DialSCTP` et leurs variantes IPv4 et IPv6 renvoient une connexion et une erreur `nil`. Dans ce cas, `TCPDialer` et `SCTPDialer` renvoient `(nil, sock.ErrInProgress)` si `Timeout == 0`.

```go
conn, err := sock.DialTCP4(nil, raddr)
if err != nil {
	return err
}
defer conn.Close()
```

Avec un délai positif, le dialer attend que la connexion soit établie. Dans cet exemple, il attend jusqu’à cinq secondes.

```go
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, err := dialer.Dial4(nil, raddr)
if err != nil {
	return err
}
defer conn.Close()
```

## Installation

```bash
go get code.hybscloud.com/sock
```

## Utilisation

### TCP

En l’absence de connexion en attente, `Accept` renvoie `iox.ErrWouldBlock` par défaut. Le serveur fixe la même échéance sur la socket d’écoute et sur la connexion acceptée. Il dispose ainsi de cinq secondes au total pour accepter une connexion et lire les premiers octets.

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

Pour accepter une association SCTP, utilisez `sock.ListenSCTP4(&sock.SCTPAddr{Port: 9000})` dans l’[exemple de serveur TCP](#tcp).

```go
// Client avec timeout
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Sockets de Domaine Unix

Pour accepter une connexion Unix de type flux, utilisez `sock.ListenUnix("unix", &sock.UnixAddr{Name: "/tmp/app.sock"})` dans l’[exemple de serveur TCP](#tcp).

```go
// Datagramme
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// Paire de sockets
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Sockets Raw (nécessite -tags rawsock et CAP_NET_RAW)

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

### Liens Réseau Linux

```go
links, _ := sock.Links()
lo, _ := sock.LinkByName("lo")
byIndex, _ := sock.LinkByIndex(lo.Index)
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
// Convertir net.TCPAddr en Sockaddr pour compatibilité
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

## Support de Plateforme

| Plateforme | Statut |
|------------|--------|
| linux/amd64 | Complet |
| linux/arm64 | Complet |
| linux/riscv64 | Complet |
| linux/loong64 | Complet |
| darwin/arm64 | Partiel |
| freebsd/amd64 | Cross-compile uniquement |

## Mesures de performance

Sous Linux, `make bench` exécute chaque test dix fois avec `-cpu=1 -benchtime=200ms` et relève le temps d’exécution et les allocations mémoire. Pour lancer un seul test, utilisez son nom dans `make bench BENCH=UDPDelivery`.

| Test | Ce que mesure une opération |
|---|---|
| `UnixSocketPair_ReadWrite` | Écrire cinq octets sur une paire de sockets Unix déjà connectée et les lire à l’autre extrémité. |
| `UDPDelivery` | Envoyer un datagramme de 64 ou 1 200 octets sur la boucle locale IPv4 avec `sock` ou le paquet `net` de Go. Chaque réception vérifiée compte dans les `datagrams/s` et le débit utile en `MB/s`. |
| `UDPBatch` | Comparer `SendMessages` et `RecvMessages` aux appels individuels à `WriteMsgUDP` et `ReadMsgUDP`. Une rafale comprend 1, 8 ou 32 datagrammes de 64 octets, ou 8 de 1 200 octets. `ns/datagram` donne le temps par datagramme livré, `datagrams/send-call` et `datagrams/recv-call` les livraisons par appel, et `allocs/op` les allocations pour toute la rafale. |
| `StreamDelivery` | Comparer `sock` et `net` sur des flux TCP/IPv4 et Unix déjà établis. Pour 64 octets, `ns/op` inclut la vérification du contenu et la confirmation du récepteur. Pour 1 MiB, comparer le débit utile en `MB/s` avec des écritures de 4 KiB et de 64 KiB. Chaque lecture porte sur 64 KiB au plus et chaque octet est compté une seule fois. |
| `WouldBlock` | Lire sur un flux Unix vide ou écrire dans une file de datagrammes Unix pleine. `ns/op` mesure un appel qui renvoie `iox.ErrWouldBlock`, via `sock.UnixConn` ou son descripteur emprunté `iofd.FD`. |
| `TCPLifecycle` | Comparer `sock` et `net` sur la boucle locale IPv4. `listen` ouvre un socket, le lie à une adresse, le met en écoute et le ferme. `connect` réutilise le socket d’écoute et compte les `connections/s` après la connexion, l’acceptation, la vérification des adresses et la fermeture des deux extrémités. |

Pour comparer deux révisions, enregistrez les résultats de chacune sur la même machine avec les mêmes versions du noyau et de Go, puis exécutez `benchstat before.txt after.txt`. Le workflow Benchmarks publie les mesures brutes dans le résumé du job et dans un fichier téléchargeable.

## Licence

MIT, voir [LICENSE](./LICENSE).

©2025 [Hayabusa Cloud Co., Ltd.](https://code.hybscloud.com)
