# srt-core / srt-mio design

Pure Rust SRT live mode (HSv5 caller and listener, no encryption) that
interoperates with libsrt 1.5.7. Wire rules: `transport-bench-srt/docs/rs2/srt-spec.md`
(section numbers below refer to it).

## Split

- **srt-core**: the protocol engine, sans-IO. No sockets, no threads, no
  clock reads: every entry point takes `now: Instant`. It turns datagrams in
  into datagrams out and messages in/out.
- **srt-mio**: one UDP socket per caller or per listener, driven on the
  caller's thread with mio; `recvmmsg`/`sendmmsg` batches; a `timerfd` for
  sub-millisecond wake-ups.

## srt-core modules

| Module | What |
| --- | --- |
| `seq` | 31-bit sequence arithmetic (`seq_cmp`, `seq_off`, `seq_add`), 26-bit message numbers, ACK numbers |
| `packet` | header + control codec: data header, HANDSHAKE, KEEPALIVE, ACK (light/small/full), NAK (loss list), CGWARNING, SHUTDOWN, ACKACK, DROPREQ, PEERERROR, EXT/unknown. Decoding borrows the datagram; encoding writes into a caller buffer |
| `handshake` | the 48-byte handshake CIF, extension blocks (HSREQ/HSRSP, SID, CONGESTION, FILTER, KMREQ/KMRSP, GROUP), word-swapped strings, request and rejection codes |
| `filter` | packet-filter config parse / merge / compare (section 8.3); FEC itself is a later stage |
| `config` | `Config`: latency (rcv/peer), payload size, flow window, buffer sizes, max bandwidth, stream id, filter, timeouts |
| `time` | local clock (`epoch`, µs since it), TSBPD time base with 32-bit wrap and drift tracer (6.7, 6.8) |
| `sndbuf` | sender ring indexed by `seq & mask`: one contiguous preallocated byte area (header + payload per slot) plus per-slot metadata; pacing token bucket (7.4) |
| `rcvbuf` | receiver ring indexed by `seq & mask`, same layout; contiguous-ACK point, cached "first present after the head" for O(1) TSBPD head/drop decisions |
| `conn` | `Connection`: handshake state machine (caller), connected state, timers, ACK/ACKACK/RTT, keepalive, peer idle, shutdown, stats |
| `listener` | `Listener`: stateless induction with a keyed cookie, conclusion validation, HSREQ/filter/SID negotiation, rejections, dedupe of repeated conclusions; produces a `Connection` |
| `stats` | counters named after libsrt's `CBytePerfMon` fields |

## Sans-IO API

```rust
// caller
let mut c = Connection::connect(cfg, now, peer_addr, local_sid, isn);
// listener
let mut l = Listener::new(cfg, now);
match l.handle(now, from, datagram, &mut out) {
    ListenerAction::Reply(len) => send out[..len] to `from`,   // induction / reject
    ListenerAction::Accept(conn) => keep it (its response is in conn.poll_transmit),
    ListenerAction::Existing(sid) => conn[sid].handle_datagram(..), // repeated conclusion
    ListenerAction::Ignore => {}
}
// both
c.handle_datagram(now, from, bytes);
c.handle_timeout(now);                         // when now >= poll_timeout()
while let Some(t) = c.poll_transmit(now, &mut buf) { send buf[..t.len] to t.dst }
c.poll_timeout() -> Option<Instant>;           // earliest timer: ACK, pacing, TSBPD, keepalive, idle, handshake
c.send_message(now, &payload, origin) -> Result<seq, SendError>;  // WouldBlock when the ring is full
c.recv_message(now) -> Option<Delivered<'_>>;  // payload borrowed from the ring slot, TSBPD-due only
c.poll_event() -> Option<Event>;               // Connected, Rejected(code), Closed(reason)
c.stats() -> &Stats; c.close(now);
```

`poll_transmit` writes one datagram into the caller's buffer: pending control
packets first (handshake, ACKACK, ACK, keepalive, shutdown), then data as the
pacer allows. A data packet is the slot's stored 16-byte header + payload,
copied once into the I/O batch buffer.

## Buffers (no per-packet allocation)

- Sender: `cap = next_pow2(sndbuf packets)` slots of `16 + max_payload`
  bytes in one `Vec<u8>` allocated at connect (`vec![0; n]`, so pages are
  only touched as used), plus a metadata array. Indices `una <= next_send <=
  next_seq`; a slot is free once acknowledged or dropped too late.
- Receiver: same layout; state `base` (next to deliver), `ack` (first not
  received contiguously), `highest`; delivery is TSBPD (`base + ts + latency
  + drift`), too-late gaps are dropped when the next present packet is due
  (6.9); the earliest-due time is recomputed on every insertion at or before
  the head (fixes 6.10).
- ACK window: 1024-entry ring (ACK number -> seq, send time).
- Handshake, listener maps and stats may allocate (once per connection).

## srt-mio

- `SrtSocket::connect(local, remote, cfg)`: non-blocking; the handshake
  proceeds in `drive(now)`; `is_connected()`, `send(now, msg)`,
  `recv(now, |payload, info|)`, `poll_timeout()`, `close()`.
  `SrtSocket` is a `mio::event::Source` (its UDP socket).
- `SrtListener::bind(addr, cfg)`: one UDP socket, demux by destination socket
  ID (0 -> the core `Listener`), connections in a map; `accept()` yields new
  connection ids; `send/recv/stats/close` by id.
- I/O: `recvmmsg` up to 64 datagrams per call, `sendmmsg` up to 64 per call,
  buffers preallocated; unsent datagrams stay queued on `EAGAIN`.
- Timers: `poll_timeout()` from the core arms a `timerfd` (`SrtTimer`, a mio
  source) so TSBPD delivery and pacing wake within tens of microseconds
  instead of epoll's 1 ms.

## Interop rules kept in mind (spec)

Control CIF always >= 4 bytes; strings in handshake extensions 4-byte-swapped;
caller induction version 4 / type 2, conclusion version 5; both directions
start at the caller's ISN; listener commits on conclusion and dedupes repeats
on (addr, caller id, ISN); ACKs never beyond last received + 1, real
available-buffer and RTT; every full/small ACK answered by an ACKACK; FEC
packets (msgno 0) never enter the receive buffer; encrypted peers refused with
UNSECURE (1011).

## Stage plan

1. (this) codec, handshake, keepalive/shutdown/idle, TSBPD data path without
   loss recovery.
2. NAK (per-loss schedule), retransmission, sender drop, tail probe (spec 12).
3. FEC filter, GSO/GRO.
