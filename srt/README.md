# wavey-srt

Safe Rust SRT (Secure Reliable Transport) for Wavey: one API, two backends.

| Feature | Backend | Build needs |
| --- | --- | --- |
| `libsrt` (default) | vendored libsrt 1.4.4 through `srt-sys` (bindgen) | cmake, a C/C++ compiler, libclang, OpenSSL (vendored) |
| `pure-rust` | `srt-core` (sans-IO live-mode SRT, AES-CTR) on `srt-mio` I/O threads | Rust only (1.78+) |

```toml
# C backend (unchanged default)
srt = { package = "wavey-srt", version = "0.1.0", features = ["async"] }
# pure Rust backend
srt = { package = "wavey-srt", git = "https://github.com/wavey-ai/av-rs.git", rev = "...",
        default-features = false, features = ["async", "pure-rust"] }
```

If both features are enabled, `pure-rust` is used. `srt::BACKEND` names the
backend in a build.

## API (both backends)

- `AsyncListener::bind(addr)`, `bind_with_options(addr, [ListenerOption])`
  with `TimestampBasedPacketDeliveryMode`, `PeerLatency`, `TooLatePacketDrop`,
  `ReceiveBufferSize`, `SendBufferSize`.
- `.with_callback(|stream_id: Option<&str>| ListenerCallbackAction)`:
  `Deny`, or `Allow { passphrase }` (the caller must then encrypt with it).
- `accept().await -> (AsyncStream, SocketAddr)`; `AsyncStream::id()` is the
  caller's stream id.
- `AsyncStream::connect(addr, &ConnectOptions)` with passphrase, stream id,
  TSBPD, TLPKTDROP, buffer sizes, `MaxBandwidth::{Infinite, Relative, Absolute}`,
  payload size.
- tokio `AsyncRead` / `AsyncWrite`: one SRT message per read (cut to the
  buffer if longer, as libsrt live mode) and per write (cut to the payload
  size, 1316 by default).
- Blocking `Listener` / `Stream` with `Read` / `Write`.
- Errors: `Error::SRTError { fn_name, code, errno }` printed as
  `"{fn_name} error: {code} (errno = {errno})"` with libsrt's `SRT_ERRNO`
  numbers in both backends: a read or write after the peer closed or the
  connection broke is `srt_recv error: 2001 (errno = 0)` /
  `srt_send error: 2001`; no listener is `srt_connect error: 1001`; a
  rejection (callback `Deny`, wrong passphrase, encryption on one side only)
  is `srt_connect error: 1002`.

## How the pure Rust backend runs

One I/O thread per listener (all its connections share its UDP socket) and
one per caller. Each sleeps in `mio` on its socket, a `timerfd` armed at the
protocol's next deadline and a waker the handles use; nothing spins. A
connection and its handle share two bounded queues: a write waits (returns
`Pending`) while 256 messages are queued ahead of a full SRT send buffer
(backpressure); the thread stops taking delivered messages when 4096 wait
for the reader (the receive buffer then fills and the flow window closes, as
with libsrt). `accept()` is cancel-safe. Dropping a stream sends SHUTDOWN
after what was written has been acknowledged, at most 2 s later (libsrt's
live mode drops unsent data at once); dropping the listener stops accepting
and leaves accepted streams running.

## Differences from the libsrt backend

- No `sys` module and no `raw_stats()` (libsrt's `SRT_TRACEBSTATS`): the pure
  streams have `stats()` (`srt_core::Stats`), `latency_ms()`,
  `encryption_key_len()`, `close_reason()`, `peer_addr()`;
  `Listener::local_addr()`.
- Data the sender wrote before closing is delivered: at peer shutdown the
  receiver hands over everything it holds, TSBPD-held packets included
  (libsrt 1.4.4 discards them, up to one latency of data).
- `set_log_handler` receives this backend's own warnings (refused callers,
  socket errors), not libsrt's log lines; they also go to the `log` crate.
- A callback `Deny` is rejected with reason 0 (UNKNOWN), as libsrt without
  `srt_setrejectreason`.
- Encryption: AES-CTR, key length 16 bytes unless the listener advertises
  another; the listener follows the caller's key length. Our sender does not
  refresh keys (libsrt does every 2^24 packets; a libsrt sender's refresh is
  handled). No AES-GCM (libsrt 1.5.4+ `SRTO_CRYPTOMODE` 2).
- Accepted-but-not-taken connections are limited to 10 (`srt_listen(s, 10)`);
  more callers are rejected with BACKLOG until `accept()` runs.
- A zero or negative `ReceiveBufferSize` / `SendBufferSize` is clamped to the
  32-packet minimum (libsrt refuses it with `srt_setsockopt error: 5003`).

Behaviour matched to libsrt (not a difference, listed because it is easy to
get wrong):

- Passphrases (connect options and the callback's `Allow { passphrase }`)
  are 10 to 80 bytes, or empty for none, as libsrt's `SRTO_PASSPHRASE`
  (`HAICRYPT_SECRET_MAX_SZ` is 80; its documentation says 79). Outside that,
  `connect` fails with `srt_setsockopt error: 5003` and a callback's
  passphrase rejects the caller (reason 0) as libsrt's hook returning -1.
  Stream ids are at most 512 bytes.
- The callback gets `Some("")` when the caller sent no stream id (libsrt
  passes its empty stream id buffer); `AsyncStream::id()` is then `None`.
- Hostile input: datagrams longer than 1500 bytes are dropped (libsrt's
  receive unit); a KM message must have exactly its length (as libsrt's
  `hcryptCtx_Rx_ParseKM`), otherwise the caller is rejected with BADSECRET
  or a key refresh answered with the BADSECRET state; cleartext data
  (KK = 0) in an encrypted session is counted in `pkt_rcv_undecrypt` and
  dropped, also when the FEC filter rebuilds it.
- If an I/O thread ends unexpectedly (it should not; a panic is caught),
  every stream it served fails with `srt_recv` / `srt_send` /
  `srt_connect error: 1003` (SRT_ESOCKFAIL) and `accept()` returns
  `srt_accept error: 1003` from then on: callers should stop or back off.
- `Debug` of `ConnectOptions` and `srt_core::Config` prints the passphrase
  as `<redacted>`; srt-core zeroes its copies of the passphrase and key
  material when a connection is dropped (the AES key schedules inside the
  `aes` crate and the application's own `String`s are not zeroed).
