#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify -c makes consumed CPU time read as zero through getrusage(2),
# times(2) and CLOCK_PROCESS_CPUTIME_ID, that it reaches descendants, and
# that without it those interfaces are left alone.
set -eu

: "${BUILDDIR:=_build}"

epoch=1700000000

status=0

fields="getrusage times cpuclock"

get() {
    printf '%s\n' "$2" | awk -v k="$1:" '$1 == k { print $2 }'
}

echo "unfaked CPU time (no -c), after burning ~250ms:"
plain=$("$BUILDDIR/faketime-bpf" "$epoch" "$BUILDDIR/test-cpu")
echo "$plain" | sed 's/^/  /'
for f in $fields; do
    v=$(get "$f" "$plain")
    if [ -z "$v" ]; then
        echo "FAIL: no '$f' line in output" >&2
        status=1
    elif [ "$v" -le 0 ]; then
        echo "FAIL: $f reported $v without -c; the burn should have registered" >&2
        status=1
    fi
done

echo "faked CPU time (-c):"
faked=$("$BUILDDIR/faketime-bpf" -c "$epoch" "$BUILDDIR/test-cpu")
echo "$faked" | sed 's/^/  /'
for f in $fields; do
    v=$(get "$f" "$faked")
    if [ "$v" != "0" ]; then
        echo "FAIL: $f reported '$v' under -c, want 0" >&2
        status=1
    fi
done

# Same reasoning as check-descendants.sh: a shell execs the last command
# of `sh -c` in place, so the trailing ':' is what makes test-cpu a forked
# grandchild rather than the process faketime-bpf exec'd itself.
echo "-c reaches a forked descendant:"
nested=$("$BUILDDIR/faketime-bpf" -c "$epoch" sh -c "\"$BUILDDIR/test-cpu\"; :")
for f in $fields; do
    v=$(get "$f" "$nested")
    if [ "$v" = "0" ]; then
        echo "  OK: $f"
    else
        echo "  FAIL: $f reported '$v' in a descendant under -c, want 0" >&2
        status=1
    fi
done

echo "-c leaves the wall clock alone:"
wall=$("$BUILDDIR/faketime-bpf" -c "$epoch" "$BUILDDIR/test-time")
if echo "$wall" | grep -qx "before time: $epoch"; then
    echo "  OK: wall clock still frozen at $epoch"
else
    echo "  FAIL: expected 'before time: $epoch' with -c" >&2
    echo "$wall" | sed 's/^/    /' >&2
    status=1
fi

echo "--long form and -- terminator:"
long=$("$BUILDDIR/faketime-bpf" --fake-cpu-time -- "$epoch" "$BUILDDIR/test-cpu")
if [ "$(get cpuclock "$long")" = "0" ]; then
    echo "  OK: --fake-cpu-time -- EPOCH"
else
    echo "  FAIL: --fake-cpu-time did not take effect" >&2
    status=1
fi

echo "an unknown option is rejected:"
set +e
out=$("$BUILDDIR/faketime-bpf" -Z "$epoch" true 2>&1)
rc=$?
set -e
if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "unknown option"; then
    echo "  OK: -Z rejected"
else
    echo "  FAIL: -Z should have been rejected (rc=$rc)" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "PASS: -c zeroes CPU time everywhere it can be read, tree-wide"
fi

exit "$status"
