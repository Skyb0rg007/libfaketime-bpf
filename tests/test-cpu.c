/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * test-cpu.c
 *
 * Burns a measurable amount of CPU, then prints how much of it the three
 * interfaces admit to: getrusage(2), times(2) and
 * clock_gettime(CLOCK_PROCESS_CPUTIME_ID). Unfaked, all three report the
 * work; under -c all three report zero.
 *
 * The burn is bounded by CLOCK_MONOTONIC, which faketime-bpf never
 * touches. Bounding it by a CPU clock would spin forever under -c, since
 * that clock is exactly what stops advancing.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/times.h>

#define BURN_MS 250

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        return -1;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void burn(void)
{
    int64_t start = monotonic_ms();
    if (start < 0) return;

    volatile uint64_t sink = 0;
    while (monotonic_ms() - start < BURN_MS)
        for (int i = 0; i < 100000; i++) sink += (uint64_t)i * 2654435761u;
}

int main(void)
{
    burn();

    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) < 0) {
        perror("getrusage");
        return 1;
    }
    printf("getrusage: %" PRId64 "\n",
           (int64_t)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
           (int64_t)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec);

    struct tms tms;
    if (times(&tms) == (clock_t)-1) {
        perror("times");
        return 1;
    }
    printf("times: %" PRId64 "\n", (int64_t)tms.tms_utime + (int64_t)tms.tms_stime);

    struct timespec cpu;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu) < 0) {
        perror("clock_gettime(CLOCK_PROCESS_CPUTIME_ID)");
        return 1;
    }
    printf("cpuclock: %" PRId64 "\n",
           (int64_t)cpu.tv_sec * 1000000000 + cpu.tv_nsec);

    return 0;
}
