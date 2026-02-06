# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Tipos de socket sin asignaciones y maquinaria de direcciones para sistemas Unix en Go.

Idioma: [English](./README.md) | [简体中文](./README.zh-CN.md) | **Español** | [日本語](./README.ja.md) | [Français](./README.fr.md)

## Cuándo Usar Este Paquete

Use `sock` en lugar del paquete estándar `net` cuando necesite:

- **Rutas calientes sin asignaciones** — Los tipos Sockaddr codifican directamente al formato del kernel sin asignación de heap
- **I/O no bloqueante** — Las operaciones retornan `iox.ErrWouldBlock` inmediatamente en lugar de bloquear goroutines
- **Control directo del kernel** — Opciones de socket, TCP_INFO y otras características de bajo nivel
- **Integración con io_uring** — Todos los sockets exponen `iofd.FD` para I/O asíncrona

Para aplicaciones típicas donde la latencia no es crítica, el paquete estándar `net` proporciona una API más simple y portable.

## Características

- **Direcciones Sin Asignaciones** — Los tipos Sockaddr codifican directamente al formato del kernel sin asignación de heap
- **Soporte de Protocolos** — TCP, UDP, SCTP, Unix (stream/dgram/seqpacket), Raw IP
- **Listo para io_uring** — Todos los sockets exponen `iofd.FD` para integración de I/O asíncrona
- **Syscalls Sin Overhead** — Interacción directa con el kernel via ensamblador `zcall`

## Arquitectura

### Interfaz Sockaddr

La interfaz `Sockaddr` es la base del manejo de direcciones sin asignaciones:

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Formato kernel directo
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Los tipos de dirección (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embeben estructuras kernel crudas y devuelven punteros directamente—sin marshaling, sin asignación.

### Jerarquía de Tipos de Socket

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (CAP_NET_RAW)
```

Todos los sockets exponen `FD() *iofd.FD` para integración con io_uring y otros mecanismos de I/O asíncrona.

### Integración con el Kernel

```
Aplicación
    ↓
sock.TCPConn.Write(data)
    ↓
iofd.FD.Write()
    ↓
zcall.Write() ← Punto de entrada en ensamblador (sin runtime Go)
    ↓
Kernel Linux
```

El paquete `zcall` proporciona puntos de entrada de syscall crudos que evitan los hooks del runtime de Go, eliminando el overhead del scheduler para rutas críticas de latencia.

### Semánticas de I/O Adaptativa

El paquete implementa el modelo **Strike-Spin-Adapt** para I/O no bloqueante:

1. **Strike**: Ejecución directa de syscall (no bloqueante)
2. **Spin**: Sincronización a nivel de hardware (manejada por `sox` si es necesario)
3. **Adapt**: Backoff de software ajustado para red cuando se establecen deadlines

**Comportamientos clave:**

- **No bloqueante por defecto**: Las operaciones `Read`, `Write`, `Accept` y `Dial` retornan inmediatamente con `iox.ErrWouldBlock` si el kernel no está listo.
- **Adaptación dirigida por deadline**: Solo cuando se establece explícitamente un deadline (via `SetDeadline`, `SetReadDeadline` o `SetWriteDeadline`) la operación entra en un bucle de reintentos con backoff progresivo.
- **Dial no bloqueante**: A diferencia de `net.Dial`, funciones como `DialTCP4` retornan inmediatamente una vez que comienza el intento de conexión. El handshake TCP puede estar aún en progreso (`ErrInProgress` se ignora silenciosamente). Use `TCPDialer` con timeout para comportamiento bloqueante:

```go
// No bloqueante (retorna inmediatamente, handshake puede estar en progreso)
conn, _ := sock.DialTCP4(nil, raddr)

// Bloqueante con timeout (espera conexión o timeout)
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, raddr)
```

## Instalación

```bash
go get code.hybscloud.com/sock
```

## Uso

### TCP

```go
// Servidor
ln, _ := sock.ListenTCP4(&sock.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
conn, _ := ln.Accept()
conn.Read(buf)
conn.Close()

// Cliente
conn, _ := sock.DialTCP4(nil, &sock.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
conn.SetNoDelay(true)
conn.Write(data)
```

### UDP

```go
// Servidor
conn, _ := sock.ListenUDP4(&sock.UDPAddr{Port: 5353})
n, addr, _ := conn.ReadFrom(buf)
conn.WriteTo(response, addr)

// Cliente
conn, _ := sock.DialUDP4(nil, &sock.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
conn.Write(query)
conn.Read(response)
```

### SCTP (Solo Linux)

```go
// Servidor
ln, _ := sock.ListenSCTP4(&sock.SCTPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9000})
conn, _ := ln.Accept()
conn.Read(buf)

// Cliente con timeout
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Sockets de Dominio Unix

```go
// Stream
ln, _ := sock.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/app.sock"})
conn, _ := ln.Accept()

// Datagrama
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// Par de sockets
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Sockets Raw (requiere CAP_NET_RAW)

```go
// ICMP ping
sock, _ := sock.NewICMPSocket4()
sock.SendTo(icmpPacket, &net.IPAddr{IP: net.ParseIP("8.8.8.8")})
n, addr, _ := sock.RecvFrom(buf)
```

### Opciones de Socket

```go
// Ajuste TCP
conn.SetNoDelay(true)              // Deshabilitar algoritmo de Nagle
conn.SetKeepAlive(true)            // Habilitar sondas keepalive
conn.SetKeepAlivePeriod(30 * time.Second)

// Tamaños de buffer
sock.SetSendBuffer(conn.FD(), 256*1024)
sock.SetRecvBuffer(conn.FD(), 256*1024)

// SO_LINGER para RST inmediato al cerrar
sock.SetLinger(conn.FD(), true, 0)

// TCP_USER_TIMEOUT para detección de conexiones muertas (Linux)
sock.SetTCPUserTimeout(conn.FD(), 30000)  // 30 segundos en milisegundos

// TCP_NOTSENT_LOWAT para reducir memoria y latencia (Linux)
sock.SetTCPNotsentLowat(conn.FD(), 16384)

// SO_BUSY_POLL para polling de baja latencia (Linux)
sock.SetBusyPoll(conn.FD(), 50)  // 50 microsegundos
```

### Operaciones UDP por Lotes (Linux)

```go
// Enviar múltiples mensajes en una sola llamada al sistema
msgs := []sock.UDPMessage{
    {Addr: addr1, Buffers: [][]byte{data1}},
    {Addr: addr2, Buffers: [][]byte{data2}},
}
n, _ := conn.SendMessages(msgs)

// Recibir múltiples mensajes
recvMsgs := []sock.UDPMessage{
    {Buffers: [][]byte{make([]byte, 1500)}},
    {Buffers: [][]byte{make([]byte, 1500)}},
}
n, _ = conn.RecvMessages(recvMsgs)

// UDP GSO (Descarga de Segmentación Genérica)
sock.SetUDPSegment(conn.FD(), 1400)  // Tamaño de segmento

// UDP GRO (Descarga de Recepción Genérica)
sock.SetUDPGRO(conn.FD(), true)
```

### Manejo de Errores

```go
// Lectura no bloqueante con iox.ErrWouldBlock
n, err := conn.Read(buf)
if err == iox.ErrWouldBlock {
    // Kernel no listo, integrar con event loop o reintentar después
    return
}
if err != nil {
    // Error real (conexión reseteada, cerrada, etc.)
    return
}

// Lectura bloqueante con deadline
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err = conn.Read(buf)
if err == sock.ErrTimedOut {
    // Deadline excedido
}
```

### Compatibilidad con el Paquete net

El paquete proporciona conversión transparente con los tipos estándar de Go `net`:

```go
// Convertir net.TCPAddr a Sockaddr (sin asignación)
netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
sockaddr := sock.TCPAddrToSockaddr(netAddr)

// Convertir de vuelta a net.TCPAddr
tcpAddr := sock.SockaddrToTCPAddr(sockaddr)

// Alias de tipos para compatibilidad
var _ sock.Conn = conn      // Compatible con net.Conn
var _ sock.Addr = addr      // Compatible con net.Addr

// Nota: Los listeners devuelven tipos concretos (*TCPConn, *UnixConn) para
// rendimiento sin asignaciones, no net.Conn como requiere net.Listener.
```

## Plataformas Soportadas

| Plataforma | Estado |
|------------|--------|
| linux/amd64 | Completo |
| linux/arm64 | Completo |
| linux/riscv64 | Completo |
| linux/loong64 | Completo |
| darwin/arm64 | Parcial (sin SCTP, TCPInfo, multicast, SCM_RIGHTS) |
| freebsd/amd64 | Solo cross-compile |

## Licencia

MIT — ver [LICENSE](./LICENSE).

©2025 Hayabusa Cloud Co., Ltd.
