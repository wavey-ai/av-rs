# wavey-srt interop scripts

Build the interop driver for each backend:

    cargo build --release -p wavey-srt --no-default-features --features pure-rust,async --example srt-interop
    CARGO_TARGET_DIR=target/libsrt-backend cargo build --release -p wavey-srt --features async --example srt-interop

- `srt-interop listen|call` (examples/srt-interop.rs): AsyncListener + callback +
  accept + read (JSON line with stream id, messages, FNV hash, sequence and
  MPEG-TS continuity checks) and AsyncStream::connect + write; `--write-back`,
  `--expect`, `--read-back` exercise listener -> caller. Pair the two builds to
  test libsrt 1.4.4 (wavey-srt's C backend) against the pure Rust backend both ways.
- `tools.sh LISTENER_BIN TS OUTDIR [LATENCIES]`: srt-live-transmit (UDP -> SRT
  relay) and ffmpeg's srt output push a TS file in real time (`-re`), payload
  1316, stream id `#!::r=live/test,m=publish`, latencies 120/200/1000/2000 ms;
  compares what the listener read with what was sent (byte-exact, TS CC errors).
- `burst-cmp.sh`: an unpaced file push (no `-re`); live mode loses data there with
  any receiver (shown for both backends), kept as a negative example.

Pin each process to one core (the scripts use 28 and 29).
