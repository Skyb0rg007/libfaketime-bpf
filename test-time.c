/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * test-time.c
 *
 * Prints the wall clock as reported by clock_gettime(2), gettimeofday(2)
 * and time(2), invoked via syscall(2) so that glibc's vDSO-backed wrappers
 * are bypassed and the real syscalls actually reach the kernel (and, when
 * run under faketime-bpf, its seccomp-bpf filter).
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

int main(void)
{
    struct timespec ts = { 0 };
    if (syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return 1;
    }
    printf("clock_gettime: %" PRId64 ".%09ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);

    struct timeval tv = { 0 };
    if (syscall(SYS_gettimeofday, &tv, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }
    printf("gettimeofday: %" PRId64 ".%06ld\n", (int64_t)tv.tv_sec, (long)tv.tv_usec);

    time_t t = 0;
    long r = syscall(SYS_time, &t);
    if (r < 0) {
        perror("time");
        return 1;
    }
    printf("time: %" PRId64 "\n", (int64_t)t);

    return 0;
}
