#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify the faked clock reaches descendants, not just the process
# faketime-bpf execs directly. Each execve(2) gets a fresh auxv with a
# real AT_SYSINFO_EHDR, so a process whose exec isn't intercepted reads
# the true clock straight out of the vDSO even though it inherited the
# seccomp filter.
#
# Note that a shell execs the *last* command of `sh -c` in place rather
# than forking, so a one-command script would pass even without tracing
# descendants; every case below keeps a command after the one it checks.
set -eu

: "${BUILDDIR:=_build}"

epoch=1700000000
want="$epoch"

status=0

check() {
    label=$1
    script=$2

    got=$("$BUILDDIR/faketime-bpf" "$epoch" sh -c "$script")
    if [ "$got" = "$want" ]; then
        echo "  OK: $label"
    else
        echo "  FAIL: $label: got '$got', want '$want'" >&2
        status=1
    fi
}

echo "faked clock reaches descendants:"
check "forked grandchild"  'date -u +%s; :'
check "second of two"      'date -u +%s >/dev/null; date -u +%s; :'
check "great-grandchild"   'sh -c "date -u +%s"; :'
check "background job"     'date -u +%s & wait; :'

echo "exit status still propagates through a forking tracee:"
set +e
"$BUILDDIR/faketime-bpf" "$epoch" sh -c 'true; exit 42' >/dev/null
rc=$?
set -e
if [ "$rc" -eq 42 ]; then
    echo "  OK: exit 42 propagated"
else
    echo "  FAIL: exit status: got $rc, want 42" >&2
    status=1
fi

# A long process tree exercises reaping: a tracee left stopped, or one
# never continued past its attach stop, hangs this instead of finishing.
echo "a wide process tree runs to completion with one faked clock:"
n=50
got=$("$BUILDDIR/faketime-bpf" "$epoch" \
    sh -c "i=0; while [ \$i -lt $n ]; do date -u +%s; i=\$((i + 1)); done | sort -u | wc -l")
if [ "$got" = "1" ]; then
    echo "  OK: all $n processes agreed on the faked time"
else
    echo "  FAIL: $n processes reported $got distinct times, want 1" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "PASS: the faked clock covers the whole process tree"
fi

exit "$status"
