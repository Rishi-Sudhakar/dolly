#!/bin/sh
# Swift <-> Kotlin over real UDP sockets on this machine.
# Each tool prints a ticket, reads the other's, hole-punches, and must receive the other's message.
# Exit code 0 means an iPhone-side and an Android-side implementation really talked to each other.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${JAVA_HOME:-}" ] && [ -d /opt/homebrew/opt/openjdk@17 ]; then
    export JAVA_HOME=/opt/homebrew/opt/openjdk@17
fi

echo "Building the Swift and Kotlin tools..."
(cd "$root/core-swift" && swift build --product dolly)
(cd "$root/core-kotlin" && gradle -q installDist)

swift_bin="$root/core-swift/.build/debug/dolly"
kotlin_bin="$root/core-kotlin/build/install/dolly/bin/dolly"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Starting both sides..."
"$swift_bin" --loopback --ticket-out "$tmp/swift.ticket" --ticket-in "$tmp/kotlin.ticket" \
    --send "hello from Swift" --exit-after 1 </dev/null >"$tmp/swift.log" 2>&1 &
swift_pid=$!
"$kotlin_bin" --loopback --ticket-out "$tmp/kotlin.ticket" --ticket-in "$tmp/swift.ticket" \
    --send "hello from Kotlin" --exit-after 1 </dev/null >"$tmp/kotlin.log" 2>&1 &
kotlin_pid=$!

ok=1
wait "$swift_pid" || ok=0
wait "$kotlin_pid" || ok=0
grep -q "peer> hello from Kotlin" "$tmp/swift.log" || ok=0
grep -q "peer> hello from Swift" "$tmp/kotlin.log" || ok=0

if [ "$ok" = 1 ]; then
    echo "PASS: Swift and Kotlin exchanged encrypted messages over real UDP."
else
    echo "FAIL"
    echo "--- Swift log";  cat "$tmp/swift.log"
    echo "--- Kotlin log"; cat "$tmp/kotlin.log"
    exit 1
fi
