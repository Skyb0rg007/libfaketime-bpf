#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify faketime-bpf actually intercepts clock_gettime(2)/gettimeofday(2)/
# time(2) for a program that issues them as raw syscalls (test-time),
# bypassing the vDSO.
set -eu

epoch=1700000000

real=$(./test-time)
echo "unfaked:"
echo "$real" | sed 's/^/  /'

fake=$(./faketime-bpf "@$epoch" ./test-time)
echo "faked (epoch=$epoch):"
echo "$fake" | sed 's/^/  /'

status=0
for want in "clock_gettime: $epoch.000000000" "gettimeofday: $epoch.000000" "time: $epoch"; do
    if ! echo "$fake" | grep -qx "$want"; then
        echo "FAIL: expected line '$want' in faked output" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "PASS: clock_gettime, gettimeofday and time were all faked, including their zeroed sub-second fields"
fi

exit "$status"
