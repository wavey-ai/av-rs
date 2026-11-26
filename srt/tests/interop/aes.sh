#!/usr/bin/env bash
# Encrypted interop of the pure Rust backend (srt-core feature `aes`) with
# libsrt: srt-live-transmit and ffmpeg (system libsrt, 1.5.7 with
# encryption) and wavey-srt's own libsrt 1.4.4 backend, both directions,
# key lengths 16/24/32, plus wrong / missing passphrase rejections.
#
# usage: aes.sh PURE_BIN LIBSRT144_BIN TS OUTDIR [CORE_A] [CORE_B]
# One JSON line per case in OUTDIR/results.ndjson.
set -u
pure=$1; lib144=$2; ts=$3; out=$4
ca=${5:-28}; cb=${6:-29}
pw='aes-interop-passphrase'
sid='#!::r=live/test,m=publish'
mkdir -p "$out"
port=19400
res="$out/results.ndjson"

record() { # case expect listener_json caller_json extra
  echo "{\"case\":\"$1\",\"expect\":\"$2\",\"listener\":${3:-null},\"caller\":${4:-null}$5}" >> "$res"
  echo "$1 (expect $2): listener=$(echo "${3:-null}" | cut -c1-160) caller=$(echo "${4:-null}" | cut -c1-160)"
}

last_json() { tail -1 "$1" 2>/dev/null | grep '^{' || echo null; }

# 1. srt-live-transmit caller (UDP relay, ffmpeg -re) -> pure listener, each key length
for kl in 16 24 32; do
  port=$((port + 1)); d="$out/slt-to-pure-$kl"; mkdir -p "$d"
  taskset -c "$ca" "$pure" listen "127.0.0.1:$port" --secs 20 --passphrase "$pw" --out "$d/rx.ts" > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" srt-live-transmit -q -t:10 -chunk:1316 "udp://127.0.0.1:$((port + 1000))?rcvbuf=4194304" \
    "srt://127.0.0.1:$port?latency=200&passphrase=$pw&pbkeylen=$kl&streamid=$sid" > "$d/sender.log" 2>&1 &
  sp=$!; sleep 0.5
  taskset -c "$cb" ffmpeg -hide_banner -loglevel error -re -i "$ts" -map 0 -c copy -f tee \
    "[f=mpegts]$d/sent.ts|[f=mpegts]udp://127.0.0.1:$((port + 1000))?pkt_size=1316" > "$d/ffmpeg.log" 2>&1
  wait $sp; wait $lp
  if cmp -s "$d/sent.ts" "$d/rx.ts"; then ex=true; else ex=false; fi
  record "slt-caller-to-pure-listener-pbkeylen$kl" connect "$(last_json "$d/listener.json")" null ",\"byte_exact\":$ex"
done

# 2. ffmpeg srt caller with passphrase -> pure listener
for kl in 16 32; do
  port=$((port + 1)); d="$out/ffmpeg-to-pure-$kl"; mkdir -p "$d"
  taskset -c "$ca" "$pure" listen "127.0.0.1:$port" --secs 20 --passphrase "$pw" --out "$d/rx.ts" > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" ffmpeg -hide_banner -loglevel error -re -i "$ts" -map 0 -c copy -f tee \
    "[f=mpegts]$d/sent.ts|[f=mpegts]srt://127.0.0.1:$port?pkt_size=1316&latency=200000&passphrase=$pw&pbkeylen=$kl&streamid=$sid" > "$d/ffmpeg.log" 2>&1
  wait $lp
  record "ffmpeg-caller-to-pure-listener-pbkeylen$kl" connect "$(last_json "$d/listener.json")" null ",\"rx_bytes\":$(stat -c %s "$d/rx.ts"),\"sent_bytes\":$(stat -c %s "$d/sent.ts")"
done

# 3. pure caller -> srt-live-transmit listener (listener sets pbkeylen: the caller adopts it)
for kl in 16 24 32; do
  port=$((port + 1)); d="$out/pure-to-slt-$kl"; mkdir -p "$d"
  taskset -c "$ca" timeout 15 srt-live-transmit -q "srt://:$port?latency=200&passphrase=$pw&pbkeylen=$kl" "file://con" > "$d/rx.bin" 2> "$d/listener.log" &
  lp=$!; sleep 0.5
  taskset -c "$cb" "$pure" call "127.0.0.1:$port" --sid "$sid" --passphrase "$pw" --count 3000 --interval-us 1000 > "$d/caller.json"
  sleep 1; kill $lp 2>/dev/null; wait $lp 2>/dev/null
  n=$(stat -c %s "$d/rx.bin")
  # the payloads start with a BE sequence number: check the first 3000 x 1316 bytes
  ok=$(python3 -I -c "
import sys
b=open(sys.argv[1],'rb').read()
n=len(b)//1316
good=sum(1 for i in range(n) if int.from_bytes(b[i*1316:i*1316+4],'big')==i and b[i*1316+4]==(i&255))
print(good)" "$d/rx.bin")
  record "pure-caller-to-slt-listener-pbkeylen$kl" connect null "$(last_json "$d/caller.json")" ",\"slt_rx_bytes\":$n,\"slt_rx_messages_in_order_and_clear\":$ok"
done

# 4. wavey-srt libsrt 1.4.4 backend <-> pure, encrypted, both ways (with write-back)
for pair in "lib144:$lib144:pure:$pure" "pure:$pure:lib144:$lib144"; do
  IFS=: read -r ln lb cn cbin <<< "$pair"
  port=$((port + 1)); d="$out/$cn-caller-to-$ln-listener"; mkdir -p "$d"
  taskset -c "$ca" "$lb" listen "127.0.0.1:$port" --secs 15 --passphrase "$pw" --write-back 500 --expect 1000 > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" "$cbin" call "127.0.0.1:$port" --sid "$sid" --passphrase "$pw" --count 2000 --interval-us 500 --read-back 500 > "$d/caller.json"
  wait $lp
  record "$cn-caller-to-$ln-listener" connect "$(last_json "$d/listener.json")" "$(last_json "$d/caller.json")" ""
done

# 5. rejections: wrong passphrase, passphrase on one side only
port=$((port + 1)); d="$out/reject-wrong-pw-slt"; mkdir -p "$d"
taskset -c "$ca" "$pure" listen "127.0.0.1:$port" --secs 6 --passphrase "$pw" > "$d/listener.json" &
lp=$!; sleep 0.3
echo x | taskset -c "$cb" timeout 5 srt-live-transmit -q "file://con" "srt://127.0.0.1:$port?passphrase=wrong-passphrase-123" > "$d/caller.log" 2>&1
wait $lp
record "slt-caller-wrong-passphrase-to-pure" reject "$(last_json "$d/listener.json")" null ",\"slt_log\":\"$(tr -d '\n"' < "$d/caller.log" | cut -c1-200)\""

for pair in "pure:$pure:lib144:$lib144" "lib144:$lib144:pure:$pure"; do
  IFS=: read -r ln lb cn cbin <<< "$pair"
  port=$((port + 1)); d="$out/reject-$cn-wrong-pw-to-$ln"; mkdir -p "$d"
  taskset -c "$ca" "$lb" listen "127.0.0.1:$port" --secs 6 --passphrase "$pw" > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" "$cbin" call "127.0.0.1:$port" --passphrase "wrong-passphrase-123" --count 10 > "$d/caller.json"
  wait $lp
  record "$cn-caller-wrong-passphrase-to-$ln" reject "$(last_json "$d/listener.json")" "$(last_json "$d/caller.json")" ""
  port=$((port + 1)); d="$out/reject-$cn-clear-to-$ln-encrypted"; mkdir -p "$d"
  taskset -c "$ca" "$lb" listen "127.0.0.1:$port" --secs 6 --passphrase "$pw" > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" "$cbin" call "127.0.0.1:$port" --count 10 > "$d/caller.json"
  wait $lp
  record "$cn-caller-clear-to-$ln-encrypted" reject "$(last_json "$d/listener.json")" "$(last_json "$d/caller.json")" ""
  port=$((port + 1)); d="$out/reject-$cn-encrypted-to-$ln-clear"; mkdir -p "$d"
  taskset -c "$ca" "$lb" listen "127.0.0.1:$port" --secs 6 > "$d/listener.json" &
  lp=$!; sleep 0.3
  taskset -c "$cb" "$cbin" call "127.0.0.1:$port" --passphrase "$pw" --count 10 > "$d/caller.json"
  wait $lp
  record "$cn-caller-encrypted-to-$ln-clear" reject "$(last_json "$d/listener.json")" "$(last_json "$d/caller.json")" ""
done
