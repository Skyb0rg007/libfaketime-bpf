/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * test-deadline.c
 *
 * Computes an absolute CLOCK_REALTIME deadline one second past the
 * (possibly faked) wall clock, then waits for it via clock_nanosleep(2)
 * and again via timerfd_settime(2), timing each wait against
 * CLOCK_MONOTONIC (never faked). If the tracer isn't rewriting the
 * deadline back into real-clock terms, a faked wall clock far from the
 * real one makes both waits return immediately instead of after ~1s.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/timerfd.h>

static int64_t ns_of(const struct timespec *ts)
{
    return (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

static void add_one_second(struct timespec *ts)
{
    int64_t total = ns_of(ts) + 1000000000LL;
    ts->tv_sec  = (time_t)(total / 1000000000LL);
    ts->tv_nsec = (long)(total % 1000000000LL);
}

static double monotonic_elapsed(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(ns_of(&now) - ns_of(start)) / 1e9;
}

int main(void)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) < 0) {
        perror("clock_gettime");
        return 1;
    }
    add_one_second(&deadline);

    struct timespec mstart;
    clock_gettime(CLOCK_MONOTONIC, &mstart);
    if (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &deadline, NULL) != 0) {
        perror("clock_nanosleep");
        return 1;
    }
    printf("clock_nanosleep elapsed: %.3f\n", monotonic_elapsed(&mstart));

    int fd = timerfd_create(CLOCK_REALTIME, 0);
    if (fd < 0) {
        perror("timerfd_create");
        return 1;
    }

    if (clock_gettime(CLOCK_REALTIME, &deadline) < 0) {
        perror("clock_gettime");
        return 1;
    }
    add_one_second(&deadline);
    struct itimerspec its = { .it_value = deadline };
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
        perror("timerfd_settime");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &mstart);
    uint64_t expirations;
    if (read(fd, &expirations, sizeof(expirations)) != sizeof(expirations)) {
        perror("read(timerfd)");
        return 1;
    }
    printf("timerfd_settime elapsed: %.3f\n", monotonic_elapsed(&mstart));

    return 0;
}
