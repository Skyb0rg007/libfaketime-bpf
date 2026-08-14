#!/bin/sh

# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Runs the full check suite, unless SECCOMP_FILTER_FLAG_NEW_LISTENER isn't
# supported in this environment (as under qemu-user emulation, which
# doesn't implement it). There's no reliable way to detect qemu-user
# itself: it fully virtualizes /proc for the guest process, so nothing
# about the host leaks through. Instead, probe the actual capability
# faketime-bpf needs and treat its own distinct failure message for that
# as a signal to skip, not a test failure.
set -eu

dir=$(dirname "$0")
: "${BUILDDIR:=_build}"

set +e
probe=$("$BUILDDIR/faketime-bpf" 0 true 2>&1)
probe_rc=$?
set -e

if [ "$probe_rc" -ne 0 ] && printf '%s\n' "$probe" | grep -q "seccomp user notifications are not supported"; then
    echo "faketime-bpf: seccomp user notifications aren't supported in this environment (e.g. qemu-user emulation); skipping checks"
    exit 0
fi

"$dir/check.sh"
"$dir/check-descendants.sh"
"$dir/check-signals.sh"
"$dir/check-deadline.sh"
