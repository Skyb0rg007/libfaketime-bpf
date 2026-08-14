#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify faketime-bpf rewrites absolute CLOCK_REALTIME deadlines computed
# against the faked clock (clock_nanosleep(2), timerfd_settime(2)) back
# into real-clock terms, so a program that schedules "one second from the
# faked now" actually waits about one real second, in both freeze and
# flow mode, rather than returning instantly because the deadline (in
# faked terms) is already in the past relative to the real clock.
set -eu

: "${BUILDDIR:=_build}"

epoch=1700000000
status=0

check_elapsed() {
    # $1 = label, $2 = mode description, $3 = output
    label=$1
    desc=$2
    out=$3
    elapsed=$(echo "$out" | awk -v l="$label" '$0 ~ "^"l" elapsed:" { print $3 }')
    ok=$(awk -v e="$elapsed" 'BEGIN { print (e >= 0.9 && e <= 5.0) ? 1 : 0 }')
    if [ "$ok" -ne 1 ]; then
        echo "FAIL: $desc '$label' elapsed ${elapsed}s, expected ~1s" >&2
        status=1
    else
        echo "  OK: $desc '$label' elapsed ${elapsed}s"
    fi
}

echo "freeze mode (epoch=$epoch, no '@'):"
freeze=$("$BUILDDIR/faketime-bpf" "$epoch" "$BUILDDIR/test-deadline")
echo "$freeze" | sed 's/^/  /'
check_elapsed "clock_nanosleep" "freeze mode" "$freeze"
check_elapsed "timerfd_settime" "freeze mode" "$freeze"

echo "flow mode (epoch=@$epoch):"
flow=$("$BUILDDIR/faketime-bpf" "@$epoch" "$BUILDDIR/test-deadline")
echo "$flow" | sed 's/^/  /'
check_elapsed "clock_nanosleep" "flow mode" "$flow"
check_elapsed "timerfd_settime" "flow mode" "$flow"

if [ "$status" -eq 0 ]; then
    echo "PASS: absolute wall-clock deadlines computed from the faked clock still wait ~1 real second"
fi

exit "$status"
