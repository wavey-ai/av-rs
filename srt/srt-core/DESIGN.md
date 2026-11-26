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
| `filter` | packet-filter config parse / merge / compare (section 8.3) |
| `fec` | the libsrt `fec` filter (section 8): config, group geometry (even, staircase), sender accumulators and FEC packets, receiver group rings, iterative rebuild, "unrebuildable" decisions |
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
- Every NAK goes twice (`repair_copies`): at once for a first attempt (the
  sender sees both before repairing: one repair), and max(RTT/8, 10 ms)
  later for a late attempt (a hole NAKed before, or with no time for
  another round). Our sender suppresses the late copy unless the first
  was lost.
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
- Head probe: when the oldest unacknowledged packet, already retransmitted
  once (libsrt receivers ACK a frame's tail late; a never-lost packet is
  no reason), was last sent that
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

## Packet filter `fec` (stage 3; spec 8, 12 #9-#11)

Wire behaviour is libsrt 1.5.7's:

- Negotiation (8.3) in `filter`; only type `fec` is accepted (FILTER 1014
  otherwise, as libsrt). Both directions group from the caller's ISN:
  offset `k = seq - ISN` (64-bit, so groups survive the 31-bit wrap).
- Row r = packets `rC .. rC+C-1`. Column j's groups hold R packets C
  apart, the first starting `shift(j)` rows down (staircase: `j mod R`;
  even: 0), each next one R rows later. Packets above a column's first
  group are row-protected only (as libsrt).
- FEC packet: data packet, PP = 11, msgno 0, sequence of the group's last
  packet, timestamp = XOR of timestamps, payload `[index (0xFF = row, else
  column)] [KK XOR] [length XOR, BE u16] [payload XOR, P bytes]`, P = the
  sender's payload size (1316 in the bench; <= 1452 with a filter). Sent
  right after the data packet that completes its group, column first,
  then row (libsrt: in the next pacing slots, after retransmissions and
  before the next new packet). They share the pacer.
- Sender: one row accumulator and one per column, reset when a new group
  id arrives (a sender drop cannot misalign groups).
- Receiver: row and column groups in two rings indexed by group number
  (window: min(receive buffer, 4096) packets), with an XOR accumulator
  each, a member count, an XOR of member indices (the one missing member
  is found without a scan) and a FEC-seen flag. Accumulators remember how
  far they are non-zero, so a reused group is never cleared byte by byte;
  XOR runs over a packet's real length in 32-byte blocks (vectorised).
  Rebuilt packets go into the receive buffer as received ones (they fill
  holes; `pktRcvFilterSupplyTotal`) and into their crossing group, which
  may rebuild in turn (checked against a brute-force peeling decoder in
  the unit tests). FEC packets never enter the buffer or the loss list.

Where we differ from libsrt (wire-compatible: only *when* NAKs go):

- `arq:onreq` / `always`: a new loss's first NAK waits for the filter.
  A group is *closed* when its FEC packet arrived or new (not
  retransmitted) data past its last packet did (its FEC went out before
  that packet). A missing packet whose protecting groups are all closed
  and that is still missing cannot be rebuilt: its first NAK is due now
  (`pktRcvFilterLossTotal` counts these). At the latest it is NAKed after
  a cap: half of what the latency leaves after two re-NAK intervals,
  within [5 ms, latency/4] (`always`: also <= SRTT/2; `fec_nak_cap_us`
  overrides). Then the normal per-hole schedule re-NAKs it until its
  deadline, with NAK copies. libsrt `onreq` NAKs an irrecoverable loss
  exactly once, judged up to two matrices late (spec 8.7).
- Large drop: a jump past the group history releases every loss before
  it at once; otherwise closing the passed groups releases them row by
  row (libsrt resets its groups without reporting, spec 8.8). Holes stay
  in the loss list in any case, so the cap NAKs anything the filter never
  decided on.
- A FEC packet carries the sequence of the data packet just before it: if
  that is beyond the highest received, the gap up to it is a loss now (a
  lost tail of a burst is known without waiting for the next burst).
- `arq:never`: no NAK at all; our sender also does no ACK-head
  retransmission, tail or head probe (FEC only, as asked).
- `pktRcvLossTotal` counts gaps in the arrival sequence before any
  rebuild, as libsrt does (comparable with and without FEC).

## Robustness (stage 3 review)

- Gap beyond the receive buffer: when a packet lands at or past
  `base + capacity` and the buffer holds nothing (TSBPD + TLPKTDROP), the
  window restarts half a buffer before it (`RcvBuf::resync`): what came
  before is counted as dropped, the half buffer before it is an ordinary
  loss (NAKed; a sender that no longer holds it answers with DROPREQ).
  libsrt breaks the connection there ("sequence discrepancy", spec 6.2
  step 3). `pktRcvResync`.
- DROPREQ: besides clearing the loss list, a range that covers the head
  moves the delivery point and the ACK over the absent packets (up to the
  first present one); a range beyond the highest received moves `highest`
  (within the window), so the next packet does not report it as a loss.
- Flow window: after a full/small ACK advertised less than a quarter of
  the buffer, a full ACK goes out on the next ACK tick as soon as the room
  grows, and every SRTT + 4 RTTVar while it stays small (libsrt:
  `m_bBufferWasFull`). Without it a sender whose window closed during a
  reader stall never learns that it reopened (it sends nothing, so the ACK
  value never changes). `pktSentWindowAck`.
- Data with KK != 0 is counted (`pktRcvUndecrypt`) and dropped; it does
  not close the connection (as libsrt).
- Sender, with FEC: stall probe. When the oldest unacknowledged packet,
  never retransmitted, is still unacknowledged the ACK-head threshold
  (SRTT + 2 RTTVar + 1 ms + `fec_ack_head_delay_us`, auto
  max(latency/4, 10 ms)) plus one ACK period after it was sent, it is sent
  again: a libsrt `onreq` receiver never reports a loss in the last,
  unfinished group, nor those its filter forgets on a reset, and repeats a
  stuck ACK only until it is ACKACKed. `pktStallProbe`.
- Sender: a retransmission (NAK, ACK-head, probe) that would reach the
  receiver after the packet's play time (now > origin + latency: it plays
  at origin + latency + one-way delay and the copy arrives at now + one-way
  delay) is skipped (`pktRexmitTooLate`); a probe of such a head is given
  up rather than retried.

## Probes and a slow-ACKing peer (rs2)

- Tail, head and stall probes wait, beyond the round trip, the peer's
  measured ACK hold-off instead of one ACK period (`probe_ack_lag`,
  default on). Sample: on an ACK advancing the window, the newest packet
  it covers that was sent once (the one before a tail-probed packet)
  waited `now - last send - SRTT` for it; skipped when a retransmission
  for a hole (NAK, ACK-head, head or stall probe; tail probes do not
  count) may lie in the acknowledged range, since a hole held that ACK.
  The hold-off is the maximum over the current and the previous 1 s
  window, capped at latency / 2, at least 10 ms. libsrt's receive worker
  ACKs a frame's tail up to ~20 ms late when idle between frames, so one
  ACK period (10 ms) made most tail probes toward libsrt duplicates.
  Sim: a peer ACKing ~20 ms after the newest packet, RTT 2 ms, 96 frames:
  96 tail probes before, 2 after; a lost tail is still repaired in time.

## Reordering with LOSSMAXTTL 0 (rs2)

- `auto_reorder` (default on, receiver timing only): with LOSSMAXTTL 0 a
  reordered packet is NAKed at once and retransmitted for nothing. When an
  original (R = 0) packet fills a hole, its lateness (arrival - detection)
  + 0.5 ms is kept as a max over two 1 s windows; new holes then wait that
  long before their first NAK (the LOSSMAXTTL waiting suffix, time-bound
  only), capped at min(latency / 8, max(SRTT / 2, 2 ms)). No reordering for
  2 s: back to NAK at once. LOSSMAXTTL > 0 keeps its own rule.
  Sim, 0-10 ms uniform jitter on data, RTT 30, L 120, 9600 packets:
  9056 needless retransmissions without, 66 with; with 1 % loss also no
  frame lost.
- With FEC (`onreq`/`always`) a group closes while its "missing" packet is
  only late; a hole the filter releases then waits the same reorder wait
  after its detection (never past its cap) before its first NAK. Bench:
  srt-rs-fec, 25 Mbit/s, jitter 5 ms, 0 % loss sent 15337 retransmissions;
  sim (FEC 10x5 staircase, 0-10 ms jitter): 7115 -> 69.

## TSBPD base settle (rs2)

- The base comes from the handshake packet (`now - ts`, libsrt's rule). If
  that packet was delayed (jitter, queueing), every packet plays that much
  late for the whole connection; libsrt's drift tracer moves only after
  1000 ACKACK samples and by at most 5 ms per step. For `tsbpd_settle_ms`
  (default 1000) after the base is set, an original data packet arriving
  earlier than the base predicts moves the base back to it (never later):
  the base becomes the least-delayed one-way offset seen. The window opens
  with the first data packet (an application may connect long before it
  sends: the bench's T0 lead is ~5 s), and the total move is capped at
  latency / 8 (on a jittery path the fastest packet is far below the mean
  delay; every µs moved comes out of the slower packets' repair budget).
  Bench: srt-rs-fec, 25 Mbit/s, jitter 5 ms: every frame 11.5 ms late
  (0+360L) from one late handshake. Sim, handshake +12 ms: 147 -> 135.05 ms.

## srt-mio

- `SrtSocket::connect(local, remote, cfg)`: non-blocking; the handshake
  proceeds in `drive(now)`; `is_connected()`, `send(now, msg)`,
  `recv(now, |payload, info|)`, `poll_timeout()`, `close()`.
  `SrtSocket` is a `mio::event::Source` (its UDP socket).
- `SrtListener::bind(addr, cfg)`: one UDP socket, demux by destination socket
  ID (0 -> the core `Listener`), connections in a map; `accept()` yields new
  connection ids; `send/recv/stats/close` by id. Timers: each connection's
  deadline is filed in a min-heap (lazy deletion); a connection touched by
  a datagram, its timer or a call is marked dirty, and `drive_io` handles
  only the dirty and due ones, then re-files their deadlines: a wake-up is
  O(touched + due x log n), not a scan of every connection.
- `SrtSocketSet`: many callers (a fan-out sender) with one timer heap, the
  same dirty/due rule; the bench's sender uses it.
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
2. (done) NAK (per-loss schedule), retransmission, sender drop, tail probe
   (spec 12).
3. (done) FEC filter.
4. GSO/GRO, encryption. (Listener and fan-out timer heaps: done.)
