# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

FTBPF_CFLAGS = -std=c99 -Wall -Wextra $(shell pkg-config --cflags libseccomp)
FTBPF_LDFLAGS = $(shell pkg-config --libs-only-L --libs-only-other libseccomp)
FTBPF_LDLIBS = $(shell pkg-config --libs-only-l libseccomp)

TEST_CFLAGS = -std=c99 -Wall -Wextra

.DEFAULT: all
.PHONY: all install check clean

all: faketime-bpf

faketime-bpf: faketime-bpf.o
	$(CC) $(FTBPF_LDFLAGS) $(LDFLAGS) -o faketime-bpf faketime-bpf.o $(FTBPF_LDLIBS) $(LDLIBS)

faketime-bpf.o: faketime-bpf.c
	$(CC) $(FTBPF_CFLAGS) $(CFLAGS) -c -o faketime-bpf.o faketime-bpf.c

test-time: test-time.o
	$(CC) $(LDFLAGS) -o test-time test-time.o $(LDLIBS)

test-time.o: test-time.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -c -o test-time.o test-time.c

install:
	:

check: all test-time
	./check.sh
	./check-signals.sh

clean:
	$(RM) *.o faketime-bpf test-time
