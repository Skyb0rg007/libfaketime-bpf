#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verify faketime-bpf's signal handling:
#   - a signal sent straight to the faketime-bpf process (not its whole
#     process group) is relayed to the tracee, rather than either being
#     ignored or killing faketime-bpf out from under it;
#   - PTRACE_O_EXITKILL cleans up the tracee if faketime-bpf itself is
#     killed uncatchably;
#   - a tracee that forks/execs children of its own (e.g. a shell) no
#     longer deadlocks the first time one of those children exits and
#     delivers SIGCHLD to the tracee -- ptrace stops on every signal
#     delivery, not just exec, and that stop must be continued by the
#     tracer or the tracee (and anything waiting on it) hangs forever.
set -u

status=0

wait_for_child() {
    # find the immediate child of pid $1 named $2, polling briefly
    i=0
    while [ "$i" -lt 50 ]; do
        pid=$(pgrep -P "$1" -x "$2" 2>/dev/null | head -n1)
        if [ -n "$pid" ]; then
            echo "$pid"
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

echo "SIGINT sent directly to faketime-bpf is relayed to the tracee:"
./faketime-bpf 1700000000 sleep 30 &
bpf_pid=$!
child_pid=$(wait_for_child "$bpf_pid" sleep) || {
    echo "FAIL: tracee (sleep) never showed up under faketime-bpf" >&2
    status=1
}
if [ -n "${child_pid:-}" ]; then
    start=$(date +%s)
    kill -INT "$bpf_pid"
    wait "$bpf_pid"
    rc=$?
    elapsed=$(($(date +%s) - start))
    if [ "$rc" -ne 130 ]; then
        echo "FAIL: expected exit 130 (128+SIGINT), got $rc" >&2
        status=1
    elif [ "$elapsed" -gt 5 ]; then
        echo "FAIL: took ${elapsed}s to react to SIGINT (sleep 30 was not interrupted)" >&2
        status=1
    else
        echo "  OK: exited $rc after ${elapsed}s (sleep 30 was cut short)"
    fi
fi

echo "PTRACE_O_EXITKILL cleans up the tracee if faketime-bpf is SIGKILLed:"
./faketime-bpf 1700000000 sleep 30 &
bpf_pid=$!
child_pid=$(wait_for_child "$bpf_pid" sleep) || {
    echo "FAIL: tracee (sleep) never showed up under faketime-bpf" >&2
    status=1
}
if [ -n "${child_pid:-}" ]; then
    kill -KILL "$bpf_pid"
    wait "$bpf_pid" 2>/dev/null
    sleep 0.5
    if kill -0 "$child_pid" 2>/dev/null; then
        echo "FAIL: tracee (pid $child_pid) is still running after faketime-bpf was SIGKILLed" >&2
        status=1
        kill -KILL "$child_pid" 2>/dev/null
    else
        echo "  OK: tracee (pid $child_pid) no longer exists"
    fi
fi

echo "a tracee whose own children exit (SIGCHLD) does not deadlock:"
if timeout 10 ./faketime-bpf 1700000000 \
        sh -c './test-time >/dev/null; sleep 1; ./test-time >/dev/null'
then
    echo "  OK: sh -c with subprocess forks completed"
else
    rc=$?
    if [ "$rc" -eq 124 ]; then
        echo "FAIL: sh -c scenario hung (previously deadlocked on the first SIGCHLD)" >&2
    else
        echo "FAIL: sh -c scenario exited $rc" >&2
    fi
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "PASS: SIGINT is relayed, SIGKILL cleans up via EXITKILL, and SIGCHLD no longer deadlocks"
fi

exit "$status"
