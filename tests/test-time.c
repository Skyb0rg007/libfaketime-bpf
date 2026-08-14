/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * test-time.c
 *
 * Prints the wall clock as reported by clock_gettime(2), gettimeofday(2)
 * and time(2), through their ordinary libc wrappers, once before and once
 * after a real sleep(3). Under freeze mode both rounds report the same
 * instant; under flow mode the second round is the first plus however
 * long the sleep took.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

static int print_now(const char *label)
{
    struct timespec ts = { 0 };
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return 1;
    }
    printf("%s clock_gettime: %" PRId64 ".%09ld\n", label, (int64_t)ts.tv_sec, ts.tv_nsec);

    struct timeval tv = { 0 };
    if (gettimeofday(&tv, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }
    printf("%s gettimeofday: %" PRId64 ".%06ld\n", label, (int64_t)tv.tv_sec, (long)tv.tv_usec);

    time_t t = time(NULL);
    if (t == (time_t)-1) {
        perror("time");
        return 1;
    }
    printf("%s time: %" PRId64 "\n", label, (int64_t)t);

    return 0;
}

int main(void)
{
    if (print_now("before") != 0) return 1;
    sleep(1);
    if (print_now("after") != 0) return 1;
    return 0;
}
