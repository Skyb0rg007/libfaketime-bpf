# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin

SRCDIR ?= src
TESTDIR ?= tests
BUILDDIR ?= _build
export BUILDDIR

FTBPF_CFLAGS = -std=c99 -Wall -Wextra $(shell pkg-config --cflags libseccomp)
FTBPF_LDFLAGS = $(shell pkg-config --libs-only-L --libs-only-other libseccomp)
FTBPF_LDLIBS = $(shell pkg-config --libs-only-l libseccomp)

TEST_CFLAGS = -std=c99 -Wall -Wextra

.DEFAULT: all
.PHONY: all install check clean

all: $(BUILDDIR)/faketime-bpf

$(BUILDDIR)/faketime-bpf: $(BUILDDIR)/faketime-bpf.o
	$(CC) $(FTBPF_LDFLAGS) $(LDFLAGS) -o $@ $< $(FTBPF_LDLIBS) $(LDLIBS)

$(BUILDDIR)/faketime-bpf.o: $(SRCDIR)/faketime-bpf.c | $(BUILDDIR)
	$(CC) $(FTBPF_CFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/test-time: $(BUILDDIR)/test-time.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BUILDDIR)/test-time.o: $(TESTDIR)/test-time.c | $(BUILDDIR)
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/test-deadline: $(BUILDDIR)/test-deadline.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BUILDDIR)/test-deadline.o: $(TESTDIR)/test-deadline.c | $(BUILDDIR)
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

install: all
	install -Dm755 $(BUILDDIR)/faketime-bpf $(BINDIR)/faketime-bpf

check: all $(BUILDDIR)/test-time $(BUILDDIR)/test-deadline
	$(TESTDIR)/check.sh
	$(TESTDIR)/check-signals.sh
	$(TESTDIR)/check-deadline.sh

clean:
	$(RM) -r $(BUILDDIR)
