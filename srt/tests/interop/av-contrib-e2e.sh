#!/usr/bin/env bash
# End to end: ffmpeg pushes an MPEG-TS file in real time over SRT into
# av-contrib's SRT ingest (web-services upload-response SrtIngest on
# wavey-srt), and av-contrib turns it into fMP4 parts. Records av-contrib's
# log, /api/status and /metrics before and after, and the sender log.
#
# usage: av-contrib-e2e.sh AV_CONTRIB_BIN TS OUTDIR [LATENCY_MS] [CORES_CONTRIB] [CORE_SENDER] [PASSPHRASE]
set -u
bin=$1; ts=$2; out=$3
lat=${4:-120}; cc=${5:-29-31}; cs=${6:-28}; pw=${7:-}
http=19443; srt=27001
mkdir -p "$out"
RUST_LOG="${RUST_LOG:-av_contrib=info,upload_response=debug,info}" \
  taskset -c "$cc" "$bin" --http-port $http \
    --mesh-fec-target 127.0.0.1:12001 --mesh-media-fec-target 127.0.0.1:12101 \
    --stream-id 1 --srt-bind 127.0.0.1:$srt --srt-stream-id 1 > "$out/av-contrib.log" 2>&1 &
cp=$!
for _ in $(seq 1 150); do
  curl -kfsS "https://127.0.0.1:$http/up" >/dev/null 2>&1 && break
  curl -fsS "http://127.0.0.1:$http/up" >/dev/null 2>&1 && break
  sleep 0.2
done
scheme=https; curl -kfsS "https://127.0.0.1:$http/up" >/dev/null 2>&1 || scheme=http
curl -ksS "$scheme://127.0.0.1:$http/api/status" > "$out/status-before.json"
curl -ksS "$scheme://127.0.0.1:$http/metrics" > "$out/metrics-before.txt"
url="srt://127.0.0.1:$srt?mode=caller&transtype=live&pkt_size=1316&latency=$((lat * 1000))&connect_timeout=3000&streamid=#!::r=live/test,m=publish"
[ -n "$pw" ] && url="$url&passphrase=$pw&pbkeylen=16"
start=$(date +%s.%N)
taskset -c "$cs" ffmpeg -hide_banner -nostdin -loglevel info -stats_period 1 -re -i "$ts" -map 0 -c copy -f mpegts "$url" > "$out/ffmpeg.log" 2>&1
echo "ffmpeg_exit=$?" >> "$out/ffmpeg.log"
end=$(date +%s.%N)
sleep 5
curl -ksS "$scheme://127.0.0.1:$http/api/status" > "$out/status-after.json"
curl -ksS "$scheme://127.0.0.1:$http/metrics" > "$out/metrics-after.txt"
ps -o pid,etimes,times,rss,cmd -p $cp > "$out/av-contrib-ps.txt" 2>&1
grep -E "^(cpu|ctxt)" /proc/$cp/stat > /dev/null 2>&1; cat /proc/$cp/status > "$out/av-contrib-proc-status.txt" 2>/dev/null
kill $cp; wait $cp 2>/dev/null
echo "{\"ts\":\"$ts\",\"ts_bytes\":$(stat -c %s "$ts"),\"latency_ms\":$lat,\"send_start\":$start,\"send_end\":$end,\"encrypted\":$([ -n "$pw" ] && echo true || echo false)}" > "$out/run.json"
grep -cE "SRT packet read" "$out/av-contrib.log" | sed 's/^/srt_packet_read_lines=/' >> "$out/run.json.txt"
grep -E "SRT request complete|SRT connection established|SRT peer closed|SRT read error|SRT connection error|SRT accept error" "$out/av-contrib.log" | tail -20 > "$out/srt-events.txt"
cat "$out/srt-events.txt"
