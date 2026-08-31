#!/bin/sh
set -eu

component=${1:-org.kysecurity.mail/org.kysecurity.mail.MainActivity}
limit_ms=${KYPOST_STARTUP_LIMIT_MS:-4000}
times_file=$(mktemp)
trap 'rm -f "$times_file"' EXIT

# connectedAndroidTest removes its APKs during cleanup, so install the build being measured.
adb install -r app/build/outputs/apk/play/debug/app-play-debug.apk >/dev/null

# One warm-up absorbs emulator/package-manager startup; the next three runs are the measurement.
i=0
while [ "$i" -lt 4 ]; do
  adb shell am force-stop "${component%%/*}"
  result=$(adb shell am start -W -n "$component")
  elapsed=$(printf '%s\n' "$result" | awk -F: '/^TotalTime:/ { gsub(/ /, "", $2); print $2 }')
  test -n "$elapsed" || { printf '%s\n' "$result" >&2; exit 1; }
  if [ "$i" -gt 0 ]; then printf '%s\n' "$elapsed" >> "$times_file"; fi
  i=$((i + 1))
done

median=$(sort -n "$times_file" | sed -n '2p')
printf 'KyPost cold startup: %sms median (runs: %s, limit: %sms)\n' \
  "$median" "$(paste -sd, "$times_file")" "$limit_ms"
test "$median" -le "$limit_ms"
