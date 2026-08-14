#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify faketime-bpf intercepts clock_gettime(2)/gettimeofday(2)/time(2)
# for a program using their ordinary libc wrappers, and that freeze/flow
# mode behave as advertised across a real 1-second sleep.
set -eu

: "${BUILDDIR:=_build}"

epoch=1700000000

real=$("$BUILDDIR/test-time")
echo "unfaked:"
echo "$real" | sed 's/^/  /'

status=0

echo "freeze mode (epoch=$epoch, no '@'):"
freeze=$("$BUILDDIR/faketime-bpf" "$epoch" "$BUILDDIR/test-time")
echo "$freeze" | sed 's/^/  /'
for want in \
    "before clock_gettime: $epoch.000000000" "before gettimeofday: $epoch.000000" "before time: $epoch" \
    "after clock_gettime: $epoch.000000000"  "after gettimeofday: $epoch.000000"  "after time: $epoch"
do
    if ! echo "$freeze" | grep -qx "$want"; then
        echo "FAIL: expected line '$want' in freeze-mode output" >&2
        status=1
    fi
done

echo "flow mode (epoch=@$epoch):"
flow=$("$BUILDDIR/faketime-bpf" "@$epoch" "$BUILDDIR/test-time")
echo "$flow" | sed 's/^/  /'

before_time=$(echo "$flow" | awk '/^before time:/ { print $3 }')
after_time=$(echo "$flow" | awk '/^after time:/ { print $3 }')

if [ "$before_time" -lt "$epoch" ] || [ "$before_time" -gt "$((epoch + 1))" ]; then
    echo "FAIL: flow-mode 'before time' ($before_time) not close to epoch ($epoch)" >&2
    status=1
fi

elapsed=$((after_time - before_time))
if [ "$elapsed" -lt 1 ] || [ "$elapsed" -gt 2 ]; then
    echo "FAIL: flow-mode elapsed time (${elapsed}s) is not ~1s after test-time's sleep(1)" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "PASS: freeze mode stays fixed across a real sleep; flow mode advances with it"
fi

exit "$status"
