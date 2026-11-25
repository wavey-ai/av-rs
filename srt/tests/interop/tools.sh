#!/usr/bin/env bash
# Interop of a wavey-srt listener (AsyncListener + callback + accept + read,
# either backend, built as the srt-interop example) with external SRT
# senders: srt-live-transmit and ffmpeg's srt protocol (both libsrt from the
# system, 1.5.7 on the dev box) pushing MPEG-TS at real time, payload 1316,
# stream id '#!::r=live/test,m=publish', for each latency.
#
# usage: tools.sh LISTENER_BIN TS OUTDIR [LATENCIES] [CORE_LISTENER] [CORE_SENDER]
# Writes OUTDIR/<sender>-<latency>/{listener.json,sent.ts,rx.ts,sender.log}
# and one summary line per case to OUTDIR/results.ndjson.
set -u
bin=$1; ts=$2; out=$3
lats=${4:-"120 200 1000 2000"}
cl=${5:-28}; cs=${6:-29}
sid='#!::r=live/test,m=publish'
mkdir -p "$out"
dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$ts" | cut -d. -f1)
port=19100
for lat in $lats; do
  for sender in slt ffmpeg; do
    port=$((port + 1))
    d="$out/$sender-$lat"
    mkdir -p "$d"
    taskset -c "$cl" "$bin" listen "127.0.0.1:$port" --secs $((dur + 15)) --out "$d/rx.ts" > "$d/listener.json" &
    lp=$!
    sleep 0.3
    if [ "$sender" = slt ]; then
      # srt-live-transmit as a UDP->SRT relay (its usual use); ffmpeg -re
      # paces the TS into it (7 TS packets per datagram) and keeps a copy.
      # It does not end on its own: -t stops it after the file.
      uport=$((port + 1000))
      taskset -c "$cs" srt-live-transmit -q -t:$((dur + 4)) -chunk:1316 "udp://127.0.0.1:$uport?rcvbuf=4194304" \
          "srt://127.0.0.1:$port?latency=$lat&streamid=$sid" > "$d/sender.log" 2>&1 &
      sp=$!
      sleep 0.5
      taskset -c "$cs" ffmpeg -hide_banner -loglevel error -re -i "$ts" -map 0 -c copy -f tee \
        "[f=mpegts]$d/sent.ts|[f=mpegts]udp://127.0.0.1:$uport?pkt_size=1316" > "$d/ffmpeg.log" 2>&1
      wait $sp
    else
      # ffmpeg's own srt output (latency in us), a tee keeps a copy of the mux
      taskset -c "$cs" ffmpeg -hide_banner -loglevel error -re -i "$ts" -map 0 -c copy -f tee \
        "[f=mpegts]$d/sent.ts|[f=mpegts]srt://127.0.0.1:$port?pkt_size=1316&latency=$((lat * 1000))&streamid=$sid" \
        > "$d/sender.log" 2>&1
    fi
    echo "sender_exit=$?" >> "$d/sender.log"
    wait $lp
    sent_bytes=$(stat -c %s "$d/sent.ts" 2>/dev/null || echo 0)
    rx_bytes=$(stat -c %s "$d/rx.ts" 2>/dev/null || echo 0)
    if cmp -s "$d/sent.ts" "$d/rx.ts"; then exact=true; else exact=false; fi
    res=$(tail -1 "$d/listener.json")
    echo "{\"sender\":\"$sender\",\"latency\":$lat,\"sent_bytes\":$sent_bytes,\"rx_bytes\":$rx_bytes,\"byte_exact\":$exact,\"listener\":$res}" >> "$out/results.ndjson"
    echo "$sender latency=$lat sent=$sent_bytes rx=$rx_bytes exact=$exact"
  done
done
