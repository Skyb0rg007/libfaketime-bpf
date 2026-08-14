<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# libfaketime-bpf

An implementation of libfaketime without `LD_PRELOAD`.

```
usage: faketime-bpf [-c] TIME command [args...]
  EPOCH   freeze: clock stopped dead at this instant
  @EPOCH  flow: clock keeps advancing at real speed from here
  -c      consumed CPU time reads as zero, via getrusage(2),
          times(2) and the CPUTIME clocks (--fake-cpu-time)
```

The faked clock covers the whole process tree, not just the command
named on the command line.

`-c` exists for reproducible builds. A frozen wall clock is not enough
when the thing being built records how much CPU it took: that measures
work done rather than time passed, so no epoch makes it deterministic
and the only stable answer is zero. Note that `getrusage(2)` reports
more than CPU time, and all of it varies from run to run, so the whole
struct is zeroed.

This code is adapted from [timewarp][].

[timewarp]: https://github.com/renard/timewarp
