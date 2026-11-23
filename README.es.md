# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Benchmarks](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/hayabusa-cloud/sock/actions/workflows/benchmarks.yml)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Tipos de socket sin asignaciones y maquinaria de direcciones para sistemas Unix en Go.

Idioma: [English](./README.md) | [简体中文](./README.zh-CN.md) | **Español** | [日本語](./README.ja.md) | [Français](./README.fr.md)

## Resumen

`sock` proporciona codificación sockaddr sin asignaciones, operaciones de socket no bloqueantes, control de opciones de socket y acceso a `iofd.FD` para integrarse con runtimes de I/O asíncrona.

## Operaciones

- **Direcciones sin asignación** — Los tipos Sockaddr se codifican directamente en estructuras orientadas al kernel; `Raw()` devuelve un `unsafe.Pointer` sin marshaling ni asignación en el heap.
- **Syscalls sin sobrecarga** — Todos los caminos de I/O usan puntos de entrada de ensamblador `zcall` que llaman al kernel directamente, sin pasar por el planificador del runtime de Go.
- **Soporte de protocolos** — TCP, UDP, SCTP, Unix domain (stream/dgram/seqpacket) y sockets IP raw; IPv4 e IPv6 para cada protocolo.
- **I/O adaptativa** — Modelo de Progreso de Tres Niveles (Strike-Spin-Adapt): las operaciones devuelven `iox.ErrWouldBlock` inmediatamente por defecto; el backoff con deadline se activa solo cuando se configura explícitamente
- **Listo para io_uring** — Cada socket expone `FD() *iofd.FD` para integración directa con `uring`, `takt` y otros runtimes de I/O asíncrona.
- **I/O UDP por lotes** — `SendMessages`/`RecvMessages` usan `sendmmsg(2)`/`recvmmsg(2)` para procesar múltiples datagramas por syscall; las variantes adaptativas añaden soporte de deadlines.
- **Consultas de enlaces de red** — `Links`, `LinkByName` y `LinkByIndex` proveen enumeración de enlaces Linux nativa via `zcall`; usados internamente para resolución de IDs de zona IPv6.
- **Control de opciones de socket** — Helpers tipados para SO_KEEPALIVE, TCP_NODELAY, SO_LINGER, TCP_USER_TIMEOUT, TCP_NOTSENT_LOWAT, SO_BUSY_POLL, UDP_SEGMENT, UDP_GRO, y más.

## Arquitectura

### Interfaz Sockaddr

La interfaz `Sockaddr` es la base del manejo de direcciones sin asignaciones:

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Formato kernel directo
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Los tipos de dirección (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embeben estructuras kernel crudas y devuelven punteros directamente, sin marshaling y sin asignación.

### Jerarquía de Tipos de Socket

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (-tags rawsock, CAP_NET_RAW)
```

Para usar io_uring u otros mecanismos de E/S asíncrona, `FD()` devuelve el `*iofd.FD` que pertenece al socket. Mantén el socket abierto hasta que terminen las operaciones que usan ese descriptor o la interfaz devuelta por `SyscallConn`. Usa `s.FD().Dup()` si necesitas un descriptor que puedas cerrar por separado.

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

El paquete `zcall` proporciona puntos de entrada de syscall crudos para interacción directa con el kernel desde `sock`.

### Semánticas de I/O Adaptativa

El paquete sigue el **Modelo de Progreso de Tres Niveles** (Strike-Spin-Adapt) para I/O no bloqueante:

1. **Strike**: Llamada al sistema — acceso directo al kernel vía `zcall`
2. **Spin**: Yield de hardware — sincronización atómica local (`spin.Pause`)
3. **Adapt**: Backoff de software — espera de disponibilidad de I/O externa (sleep progresivo)

sock implementa **Strike** y **Adapt**. Spin no se utiliza aquí porque las operaciones de socket esperan al kernel o a un peer de red, no a atómicas locales.

**Comportamientos clave:**

- **No bloqueante por defecto**: Las operaciones `Read`, `Write`, `Accept` y `Dial` retornan inmediatamente con `iox.ErrWouldBlock` si el kernel no está listo.
- **Adaptación dirigida por deadline**: Solo cuando se establece explícitamente un deadline (via `SetDeadline`, `SetReadDeadline` o `SetWriteDeadline`) la operación entra en un bucle de reintentos con backoff progresivo.
- **Clasificación de resultados**: los conteos y valores de retorno llevan el progreso, mientras que los errores
  semánticos llevan el control. Las llamadas directas de `sock` suelen exponer `iox.ErrWouldBlock` cuando no hay
  readiness y `sock.ErrInProgress` durante un connect pendiente; `iox.ErrMore`, `iox.Classify`, `iox.IsSemantic` e
  `iox.IsProgress` siguen siendo el vocabulario compartido para helpers por encima de `sock`.
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

Si no hay conexiones pendientes, `Accept` devuelve `iox.ErrWouldBlock` por defecto. El servidor fija el mismo plazo en el socket de escucha y en la conexión aceptada para esperar la conexión y leer los primeros bytes en un total de cinco segundos.

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

Para aceptar una asociación SCTP, usa `sock.ListenSCTP4(&sock.SCTPAddr{Port: 9000})` en el [ejemplo de servidor TCP](#tcp).

```go
// Cliente con timeout
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Sockets de Dominio Unix

Para aceptar una conexión de flujo Unix, usa `sock.ListenUnix("unix", &sock.UnixAddr{Name: "/tmp/app.sock"})` en el [ejemplo de servidor TCP](#tcp).

```go
// Datagrama
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// Par de sockets
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Sockets Raw (requiere -tags rawsock y CAP_NET_RAW)

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

### Enlaces de Red en Linux

```go
links, _ := sock.Links()
lo, _ := sock.LinkByName("lo")
byIndex, _ := sock.LinkByIndex(lo.Index)
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
// Convertir net.TCPAddr a Sockaddr para compatibilidad
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

## Soporte de Plataforma

| Plataforma | Estado |
|------------|--------|
| linux/amd64 | Completo |
| linux/arm64 | Completo |
| linux/riscv64 | Completo |
| linux/loong64 | Completo |
| darwin/arm64 | Parcial |
| freebsd/amd64 | Solo cross-compile |

## Pruebas de rendimiento

En Linux, `make bench` ejecuta cada prueba diez veces con `-cpu=1 -benchtime=200ms` y registra el tiempo y las asignaciones de memoria. Para ejecutar una sola prueba, usa su nombre en `make bench BENCH=UDPDelivery`.

| Prueba | Qué mide una operación |
|---|---|
| `UnixSocketPair_ReadWrite` | Escribe cinco bytes en un par de sockets Unix ya conectado y léelos desde el otro extremo. |
| `UDPDelivery` | Envía un datagrama de 64 o 1200 bytes por la interfaz de loopback IPv4 con `sock` o con `net` de Go. Cada recepción verificada cuenta para `datagrams/s` y para los `MB/s` de carga útil. |
| `UDPBatch` | Compara `SendMessages` y `RecvMessages` con llamadas individuales a `WriteMsgUDP` y `ReadMsgUDP`. Cada ráfaga contiene 1, 8 o 32 datagramas de 64 bytes, u 8 de 1200 bytes. `ns/datagram` mide el tiempo por entrega, `datagrams/send-call` y `datagrams/recv-call` cuentan las entregas por llamada y `allocs/op` cubre la ráfaga completa. |
| `StreamDelivery` | Compara `sock` y `net` en conexiones TCP sobre IPv4 y en flujos Unix ya establecidos. Para 64 bytes, `ns/op` incluye la verificación del contenido y la confirmación del receptor. Para 1 MiB, compara los `MB/s` de carga útil con escrituras de 4 KiB y 64 KiB. Cada lectura abarca hasta 64 KiB y cada byte se cuenta una vez. |
| `WouldBlock` | Lee de un flujo Unix vacío o escribe en una cola de datagramas Unix llena. `ns/op` mide una llamada que devuelve `iox.ErrWouldBlock`, mediante `sock.UnixConn` o su descriptor prestado `iofd.FD`. |
| `TCPLifecycle` | Compara `sock` y `net` en loopback IPv4. `listen` abre un socket, lo vincula, lo pone en escucha y lo cierra. `connect` reutiliza un socket de escucha y cuenta `connections/s` tras conectar, aceptar, verificar las direcciones de ambos extremos y cerrarlos. |

Para comparar revisiones, guarda la salida de cada una en la misma máquina con las mismas versiones del kernel y de Go. Luego ejecuta `benchstat before.txt after.txt`. El flujo de trabajo Benchmarks publica las muestras en el resumen de la ejecución y en un archivo descargable.

## Licencia

MIT, ver [LICENSE](./LICENSE).

©2025 [Hayabusa Cloud Co., Ltd.](https://code.hybscloud.com)
