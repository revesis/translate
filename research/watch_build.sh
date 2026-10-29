#!/bin/bash
# Watch the remote Chromium build and exit when ninja stops (finished or failed).
# Prints one line per poll so the transcript keeps a progress trail.
H=root@192.168.92.26
while true; do
  line=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$H" \
    'tail -1 /root/build.log 2>/dev/null; if pgrep -f "ninja -C out/Rel" >/dev/null; then echo __RUNNING__; else echo __STOPPED__; fi' 2>/dev/null)
  printf '%s %s\n' "$(date +%H:%M:%S)" "$(echo "$line" | tr '\n' ' ')"
  case "$line" in
    *__STOPPED__*) break ;;
  esac
  sleep 300
done
echo "=== final ==="
ssh -o BatchMode=yes "$H" 'tail -25 /root/build.log; ls -la /root/chromium/src/out/Rel/chrome 2>/dev/null || echo "no chrome binary"'
