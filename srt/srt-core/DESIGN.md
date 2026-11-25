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
| `losslist` | receiver holes with a NAK schedule each; sender runs to retransmit (both ordered rings, no per-packet allocation) |
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

## Loss recovery (stage 2; spec 6, 7, 12)

Receiver (`RcvLossList`, a `VecDeque` of holes in sequence order):

- A gap found on arrival (`seq > highest + 1`) is appended as one hole with
  its detection time and its deadline: the TSBPD time of the packet that
  revealed it (the receiver gives the gap up when that packet is due).
  A repaired sequence is found by binary search and cut out (split if
  inside a run). Holes before the delivery point leave on a TSBPD drop;
  a DROPREQ cuts its range out.
- NAK at once (LOSSMAXTTL 0), else after LOSSMAXTTL more packets or
  `reorder_window_us` (2 ms), whichever first (holes waiting for that are a
  suffix of the list, released in order, O(1) per packet).
- Re-NAK each hole `max(SRTT, NAK->repair time) + min(4 x var, RTT/2) + 2
  ms` (floor 5 ms) after its last NAK, never when the repair could not
  arrive before its deadline. The attempts a hole still has time for are
  spread evenly up to its deadline minus (the repair time + its variation
  + max(RTT/8, 10 ms)): as many attempts, but further apart, so a libsrt
  sender (RETRANSMITALGO=1 suppresses a request arriving within SRTT - 4
  RTTVar of its last copy, and it queues retransmissions behind new data)
  does not swallow one, and the last one lands well before libsrt's own
  drop at latency + 20 ms. The NAK->repair time is measured from holes
  NAKed once and repaired by a retransmission (Karn), so it includes the
  sender's queueing. Due holes go in one NAK as ranges (up to
  maxPayload/4 words; the rest in the next). The schedule is brought
  forward when the RTT estimate falls (first sample). libsrt instead
  re-sends its whole loss list every max(RTT/2 + 2 RTTVar, 20 ms), 300 ms
  before its first RTT sample.
- The re-NAK interval uses the measured repair time and its own variation
  once there are samples (one per repaired loss), not RTTVar: RTTVar comes
  from ACKACKs, which are rare while a hole holds the ACK value, and it
  starts at RTT/2. A full ACK also goes out every 50 ms while holes hold
  the ACK value (libsrt sends none then), so RTT samples keep coming.
- Late attempts go twice (`repair_copies`): a NAK for a hole NAKed before,
  or with no time for another round, is sent again max(RTT/8, 10 ms)
  later. With our sender the copy is suppressed unless the first was lost.
- ACKs report RTTVar >= SRTT/4 (`ack_rttvar_floor`; RTT unchanged): a
  libsrt sender (RETRANSMITALGO=1) then serves every request instead of
  dropping those within SRTT - 4 RTTVar of its last copy, so the delayed
  NAK copy of a late attempt yields a second repair. Our receiver paces
  its own NAKs, so this costs only those copies. Measured: libsrt sender
  to our receiver at RTT 250, 5 % loss, latency 1 s lost 1-8 frames per
  run before this, as many attempts as libsrt's own receiver but without
  its extra (duplicate) repairs.

Sender (`SndLossList`, merged runs in order):

- NAKed sequences we hold are queued; those already acknowledged or
  dropped get a DROPREQ (queued, merged); a NAK beyond what was sent is
  counted and ignored (libsrt would break the connection).
- `poll_transmit` order: shutdown, handshake, ACKACK, ACK, NAK (and its
  copy), DROPREQ, keepalive, retransmissions, new data. Retransmissions
  share the pacer but go before new data (their deadlines are earlier;
  libsrt sends new data first when TLPKTDROP is on).
- A request for a packet (re)sent less than `max(SRTT - RTTVar, SRTT/2)`
  ago is dropped: it was sent before the previous copy could arrive
  (libsrt's periodic NAK repeats every request every ~20 ms).
- The second retransmission of a packet on, or a repair with less than
  1.5 SRTT + min(4 RTTVar, SRTT/2) + 5 ms left before the receiver plays
  it, is sent twice.
- ACK-head retransmission: an ACK stopping at a packet last sent more
  than SRTT + 2 RTTVar + 1 ms earlier means that copy was lost: queue it
  without waiting for the next NAK.
- Tail probe: when nothing is unsent, packets are in flight and no data
  went out for SRTT + min(4 RTTVar, SRTT/2) + 10 ms + 1 ms, retransmit the
  newest packet once (a lost tail is otherwise only seen when the next
  frame arrives).
- Head probe: when the oldest unacknowledged packet was last sent that
  same probe delay ago and no ACK passed it, send it again (its last copy
  or the NAK for it was lost; a libsrt receiver re-NAKs only after 300 ms
  until it has an RTT, and libsrt does not repeat an unchanged ACK).
- Sender drop on a timer: packets older than latency + SNDDROPDELAY +
  max(latency/4, 20 ms) + 2 SRTT + 10 ms leave the buffer, announced by a
  DROPREQ (libsrt: max(latency, 1 s) + 20 ms, checked only on send).
- RTT before the first ACK/ACKACK sample: the caller seeds it from an
  unrepeated induction, the listener from the first packet after an
  unrepeated conclusion response (used by the timers above, not reported
  as a valid RTT).

TSBPD wake-up: `poll_timeout` is recomputed after every input, so a repair
that fills the head makes the head due at once or at its own time (the
libsrt "one frame late" defect, spec 6.10, cannot happen).

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
- Readiness: sockets are registered READABLE only (a UDP socket raises an
  EPOLLOUT edge for every packet the kernel frees, so WRITABLE interest
  means a wake-up per packet sent); `drive_io` skips `recvmmsg` unless the
  socket fired since it was last drained. Measured at 2160p160 over netns:
  2.4 -> 17.5 datagrams per `sendmmsg`, sender CPU 0.077 -> 0.041 cores.
- Pacing wakes `pace_quantum_us` (250 us) after the next packet is allowed,
  so each wake-up sends a batch; the pacer's 1 ms burst allowance keeps the
  configured rate.

## Interop rules kept in mind (spec)

Control CIF always >= 4 bytes; strings in handshake extensions 4-byte-swapped;
caller induction version 4 / type 2, conclusion version 5; both directions
start at the caller's ISN; listener commits on conclusion and dedupes repeats
on (addr, caller id, ISN); ACKs never beyond last received + 1, real
available-buffer and RTT; every full/small ACK answered by an ACKACK; FEC
packets (msgno 0) never enter the receive buffer; encrypted peers refused with
UNSECURE (1011).

## Stage plan

1. codec, handshake, keepalive/shutdown/idle, TSBPD data path without
   loss recovery.
2. (this) NAK (per-loss schedule), retransmission, sender drop, tail probe
   (spec 12).
3. FEC filter, GSO/GRO.
