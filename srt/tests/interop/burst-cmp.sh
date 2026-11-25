#!/usr/bin/env bash
# Unpaced file push (srt-live-transmit, libsrt 1.5.7) into an srt-interop listener.
# usage: burst-cmp.sh LISTENER_BIN PORT TS OUTDIR
set -u
bin=$1; port=$2; ts=$3; out=$4
mkdir -p "$out"
taskset -c 28 "$bin" listen 127.0.0.1:$port --secs 12 --out "$out/rx.ts" > "$out/listener.json" &
lp=$!
sleep 0.3
cat "$ts" | timeout 10 taskset -c 29 srt-live-transmit -q -chunk:1316 "file://con" "srt://127.0.0.1:$port?latency=2000&streamid=#!::r=live/test,m=publish"
echo "slt exit $?" > "$out/slt.txt"
wait $lp
