/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * test-time.c
 *
 * Prints the wall clock as reported by clock_gettime(2), gettimeofday(2)
 * and time(2), through their ordinary libc wrappers. On x86-64 those are
 * normally served straight out of the vDSO without ever making a real
 * syscall, so this only gets faked under faketime-bpf because it disables
 * the vDSO for the traced process (see disable_vdso() in faketime-bpf.c).
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <sys/time.h>

int main(void)
{
    struct timespec ts = { 0 };
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return 1;
    }
    printf("clock_gettime: %" PRId64 ".%09ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);

    struct timeval tv = { 0 };
    if (gettimeofday(&tv, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }
    printf("gettimeofday: %" PRId64 ".%06ld\n", (int64_t)tv.tv_sec, (long)tv.tv_usec);

    time_t t = time(NULL);
    if (t == (time_t)-1) {
        perror("time");
        return 1;
    }
    printf("time: %" PRId64 "\n", (int64_t)t);

    return 0;
}
