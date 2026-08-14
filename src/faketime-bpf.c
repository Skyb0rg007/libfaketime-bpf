/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * faketime-bpf.c
 *
 * Runs a command with a faked wall clock, without LD_PRELOAD.
 *
 * TIME is a unix epoch: a bare epoch freezes the clock at that instant;
 * an '@'-prefixed epoch sets a start-at instant that the clock keeps
 * advancing from at real speed (libfaketime's freeze/flow convention).
 * clock_gettime(2), gettimeofday(2) and time(2) are intercepted to serve
 * the faked clock; clock_nanosleep(2) and timerfd_settime(2) are also
 * intercepted, but only to rewrite absolute wall-clock deadlines that the
 * tracee computed against the faked clock back into real-clock terms
 * before letting the kernel run them, so it actually waits the intended
 * duration.
 *
 * clock_gettime(CLOCK_REALTIME) and gettimeofday() are normally served
 * straight out of the vDSO, without a real syscall, so a seccomp filter
 * alone can't see them. The child is ptrace(2)-attached and, at every
 * exec-stop, AT_SYSINFO_EHDR is zeroed in its auxv so the C runtime
 * skips the vDSO and calls the kernel directly instead; the resulting
 * real syscalls are trapped by a SECCOMP_RET_USER_NOTIF filter the
 * child installs on itself, right before execvp(). The listener fd is
 * handed to the parent over a socketpair beforehand, and stays valid
 * across any further fork/exec the tracee performs.
 *
 * The auxv patch, unlike the filter, does not survive into descendants:
 * execve(2) rebuilds auxv from scratch, complete with a fresh
 * AT_SYSINFO_EHDR, so a grandchild would go back to reading the real
 * clock out of the vDSO. Tracing therefore follows the whole process
 * tree -- PTRACE_O_TRACEFORK/VFORK/CLONE auto-attach every descendant --
 * and each one's exec-stops get the same patch.
 *
 * A ptrace-attached process stops on every signal delivery, not just
 * exec, and each stop blocks until the tracer continues it. A signalfd
 * for SIGCHLD drives a waitpid loop that continues every such stop,
 * forwarding whatever signal caused it. A few terminating signals
 * (SIGINT, SIGTERM, SIGHUP, SIGQUIT) are also blocked in this process
 * and relayed to the tracee by hand, so it reacts correctly whether or
 * not it shares a terminal's foreground process group, and this
 * process is never killed out from under it. PTRACE_O_EXITKILL covers
 * the reverse case: if this process dies uncatchably, the kernel kills
 * the tracee too.
 *
 * Adapted from timewarp <https://github.com/renard/timewarp>.
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <seccomp.h>

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "faketime-bpf: unsupported architecture"
#endif

// FT_MODE_FREEZE stops the clock dead; FT_MODE_FLOW advances it from a start-at instant
typedef enum { FT_MODE_FREEZE, FT_MODE_FLOW } faketime_mode_t;

// Time math
static int64_t timespec_to_ns(const struct timespec *ts);
static void ns_to_timespec(int64_t total_ns, struct timespec *ts);
static int64_t make_value_ns(faketime_mode_t mode, time_t fake_epoch);
static void fake_now(faketime_mode_t mode, int64_t value_ns, struct timespec *ts);
static void unfake_deadline(faketime_mode_t mode, int64_t value_ns, struct timespec *ts);

// Argument parsing
static int parse_time_arg(const char *s, time_t *out, faketime_mode_t *mode);
static void usage(const char *prog);

// fd passing (seccomp listener fd, child to parent)
static int send_fd(int sock, int fd);
static int recv_fd(int sock);

// Live tracees
static int track_pid(pid_t pid);
static void forget_pid(pid_t pid);

// seccomp + ptrace
static int install_seccomp_filter(void);
static int tracee_sp(pid_t pid, unsigned long *sp);
static void disable_vdso(pid_t pid);
static void reap_tracees(pid_t root, int *root_exited, int *root_status);
static int read_from_child(pid_t pid, uint64_t remote_addr, void *data, size_t len);
static int write_to_child(pid_t pid, uint64_t remote_addr, const void *data, size_t len);
static int get_timerfd_clockid(pid_t pid, int fd);
static void handle_time_notif(int notif_fd, faketime_mode_t mode, int64_t value_ns);

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    unsigned api = seccomp_api_get();
    if (api < 5) {
        fprintf(stderr, "faketime-bpf: seccomp user notifications are not supported\n");
        return 1;
    }

    time_t fake_epoch;
    faketime_mode_t mode;
    if (!parse_time_arg(argv[1], &fake_epoch, &mode)) {
        fprintf(stderr, "faketime-bpf: invalid time '%s' (expected [@]epoch)\n", argv[1]);
        return 1;
    }
    int64_t value_ns = make_value_ns(mode, fake_epoch);

    /*
     * POSIX shells set SIGINT/SIGQUIT to SIG_IGN for an asynchronous list
     * ("cmd &"), and that disposition survives execve(2). A signal whose
     * disposition is SIG_IGN is discarded by the kernel when generated,
     * before it can become pending, so blocking it below would not help.
     * Reset only these two (not SIGHUP: nohup(1) sets it deliberately,
     * and that should still apply to the target command).
     */
    struct sigaction sa_dfl = { .sa_handler = SIG_DFL };
    sigemptyset(&sa_dfl.sa_mask);
    sigaction(SIGINT, &sa_dfl, NULL);
    sigaction(SIGQUIT, &sa_dfl, NULL);

    /*
     * Block SIGCHLD (drives the waitpid loop below) and a few terminating
     * signals (relayed to the tracee by hand) before forking, so signalfd
     * reliably catches all of them. The child restores the default mask
     * before exec so the target program's own signal handling is unaffected.
     */
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
        perror("sigprocmask");
        return 1;
    }

    int sfd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sfd < 0) {
        perror("signalfd");
        return 1;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        close(sv[0]);
        close(sfd);
        sigprocmask(SIG_UNBLOCK, &sigmask, NULL);

        // Stop so the parent can arm PTRACE_O_TRACEEXEC before we exec
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }
        raise(SIGSTOP);

        int notif_fd = install_seccomp_filter();
        if (notif_fd < 0) _exit(1);

        if (send_fd(sv[1], notif_fd) < 0) {
            perror("send_fd");
            _exit(1);
        }
        close(notif_fd);
        close(sv[1]);

        execvp(argv[2], &argv[2]);
        perror(argv[2]);
        _exit(127);
    }

    close(sv[1]);

    int wstatus;
    if (waitpid(child, &wstatus, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFSTOPPED(wstatus)) {
        fprintf(stderr, "faketime-bpf: unexpected initial child state\n");
        return 1;
    }
    /*
     * These options are inherited by every auto-attached descendant, so
     * setting them once here arms the whole tree: each fork/vfork/clone
     * hands us the new process, and each of its execs stops for the auxv
     * patch that keeps it off the vDSO.
     */
    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(unsigned long)(PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL |
                                       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                                       PTRACE_O_TRACECLONE)) < 0) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        return 1;
    }
    if (track_pid(child) < 0) {
        perror("track_pid");
        return 1;
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_CONT)");
        return 1;
    }

    int notif_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "faketime-bpf: failed to receive notification fd\n");
        waitpid(child, &wstatus, 0);
        return 1;
    }

    // Exec-stop: patch AT_SYSINFO_EHDR in the fresh auxv, then let it run
    if (waitpid(child, &wstatus, 0) < 0) { perror("waitpid"); return 1; }
    if (WIFSTOPPED(wstatus) &&
        (wstatus >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        disable_vdso(child);
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
        perror("ptrace(PTRACE_CONT)");
        return 1;
    }

    /*
     * The seccomp filter (and thus this listener fd) is inherited across
     * any further fork/exec the tracee performs, so a single poll loop
     * over notif_fd and the signalfd covers the whole run. The kernel
     * signals POLLHUP on notif_fd once no process holds the filter
     * anymore, i.e. once the tracee (and any descendants) has exited.
     */
    int child_exited = 0;
    struct pollfd pfds[2] = {
        { .fd = notif_fd, .events = POLLIN },
        { .fd = sfd,       .events = POLLIN },
    };
    for (;;) {
        int r = poll(pfds, 2, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (pfds[0].revents & POLLIN)
            handle_time_notif(notif_fd, mode, value_ns);
        if ((pfds[0].revents & POLLHUP) && !(pfds[0].revents & POLLIN))
            break;

        if (!(pfds[1].revents & POLLIN))
            continue;

        struct signalfd_siginfo ssi;
        while (read(sfd, &ssi, sizeof(ssi)) == (ssize_t)sizeof(ssi)) {
            if ((int)ssi.ssi_signo != SIGCHLD) {
                // A terminating signal aimed at us: relay it to the tracee
                kill(child, (int)ssi.ssi_signo);
                continue;
            }

            /*
             * signalfd collapses repeats, so one SIGCHLD can stand for
             * several state changes across the tree; drain them all.
             */
            reap_tracees(child, &child_exited, &wstatus);
        }
    }
    close(notif_fd);
    close(sfd);

    if (!child_exited && waitpid(child, &wstatus, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (WIFEXITED(wstatus))   return WEXITSTATUS(wstatus);
    if (WIFSIGNALED(wstatus)) return 128 + WTERMSIG(wstatus);
    return 1;
}

// --- Time math ---------------------------------------------------------

static int64_t timespec_to_ns(const struct timespec *ts)
{
    return (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

static void ns_to_timespec(int64_t total_ns, struct timespec *ts)
{
    int64_t sec  = total_ns / 1000000000LL;
    int64_t nsec = total_ns % 1000000000LL;
    if (nsec < 0) {
        nsec += 1000000000LL;
        sec  -= 1;
    }
    ts->tv_sec  = (time_t)sec;
    ts->tv_nsec = (long)nsec;
}

// The frozen target instant in FT_MODE_FREEZE, or an offset from the current real clock in FT_MODE_FLOW
static int64_t make_value_ns(faketime_mode_t mode, time_t fake_epoch)
{
    if (mode == FT_MODE_FREEZE)
        return (int64_t)fake_epoch * 1000000000LL;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (int64_t)fake_epoch * 1000000000LL - timespec_to_ns(&now);
}

// The faked wall-clock reading: value_ns itself when frozen, or value_ns added to the live clock when flowing
static void fake_now(faketime_mode_t mode, int64_t value_ns, struct timespec *ts)
{
    if (mode == FT_MODE_FREEZE) {
        ns_to_timespec(value_ns, ts);
        return;
    }

    struct timespec real;
    clock_gettime(CLOCK_REALTIME, &real);
    ns_to_timespec(timespec_to_ns(&real) + value_ns, ts);
}

// Converts an absolute deadline the tracee computed against the faked clock back into real-clock terms, so the kernel waits the intended duration
static void unfake_deadline(faketime_mode_t mode, int64_t value_ns, struct timespec *ts)
{
    if (mode == FT_MODE_FREEZE) {
        // The deadline was an offset from the frozen "now"; honor it as a real-time duration from the current instant
        struct timespec real_now;
        clock_gettime(CLOCK_REALTIME, &real_now);
        ns_to_timespec(timespec_to_ns(ts) - value_ns + timespec_to_ns(&real_now), ts);
        return;
    }

    ns_to_timespec(timespec_to_ns(ts) - value_ns, ts);
}

// --- Argument parsing ---------------------------------------------------

// A unix epoch, e.g. "1700000000" (freeze) or "@1700000000" (flow)
static int parse_time_arg(const char *s, time_t *out, faketime_mode_t *mode)
{
    *mode = FT_MODE_FREEZE;
    if (*s == '@') {
        *mode = FT_MODE_FLOW;
        s++;
    }
    if (*s == '\0') return 0;

    errno = 0;
    char *end;
    long long v = strtoll(s, &end, 10);
    if (errno || *end != '\0') return 0;

    *out = (time_t)v;
    return 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s TIME command [args...]\n"
            "  EPOCH   freeze: clock stopped dead at this instant\n"
            "  @EPOCH  flow: clock keeps advancing at real speed from here\n",
            prog);
}

// --- fd passing ----------------------------------------------------------

// Pass a file descriptor over a Unix socket via SCM_RIGHTS
static int send_fd(int sock, int fd)
{
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char dummy = 0;
    struct iovec iov = { &dummy, 1 };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock)
{
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char dummy;
    struct iovec iov = { &dummy, 1 };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    if (recvmsg(sock, &msg, 0) <= 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

// --- Live tracees --------------------------------------------------------

/*
 * Every pid currently attached to us. Its only job is to tell a
 * descendant's first stop -- the SIGSTOP the kernel raises when
 * auto-attaching it, whose signal must be swallowed rather than injected
 * -- apart from the ordinary signal-delivery stops that follow. Entries
 * are dropped as processes exit, so pid reuse cannot alias a live one.
 * Membership is a linear scan, which is fine: this holds only the
 * processes alive at one instant, not every one ever spawned.
 */
static pid_t *tracees;
static size_t num_tracees;
static size_t tracees_cap;

// 0 if pid was newly added, 1 if it was already known, -1 on allocation failure
static int track_pid(pid_t pid)
{
    for (size_t i = 0; i < num_tracees; i++)
        if (tracees[i] == pid) return 1;

    if (num_tracees == tracees_cap) {
        size_t cap = tracees_cap ? tracees_cap * 2 : 16;
        pid_t *p = realloc(tracees, cap * sizeof(*tracees));
        if (!p) return -1;
        tracees     = p;
        tracees_cap = cap;
    }
    tracees[num_tracees++] = pid;
    return 0;
}

static void forget_pid(pid_t pid)
{
    for (size_t i = 0; i < num_tracees; i++) {
        if (tracees[i] == pid) {
            tracees[i] = tracees[--num_tracees];
            return;
        }
    }
}

// --- seccomp + ptrace ----------------------------------------------------

// Installs the seccomp-bpf filter; called by the child, before execvp()
static int install_seccomp_filter(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return -1;
    }

    /*
     * Not every syscall exists on every architecture -- aarch64 has no
     * separate time(2)/gettimeofday(2), glibc there builds both on top
     * of clock_gettime(2) -- so a failed rule add is skipped rather than
     * fatal, as long as at least one syscall is filtered.
     */
    int syscalls[] = {
        SCMP_SYS(clock_gettime),
        SCMP_SYS(gettimeofday),
        SCMP_SYS(time),
        SCMP_SYS(clock_nanosleep),
        SCMP_SYS(timerfd_settime),
    };
    int added = 0;
    for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, syscalls[i], 0) == 0)
            added++;
    }
    if (added == 0) {
        fprintf(stderr, "seccomp_rule_add: no syscalls to filter on this architecture\n");
        seccomp_release(ctx);
        return -1;
    }

    int rc = seccomp_load(ctx);
    if (rc < 0) {
        fprintf(stderr, "seccomp_load: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }

    int notif_fd = seccomp_notify_fd(ctx);
    seccomp_release(ctx);
    if (notif_fd < 0) {
        fprintf(stderr, "seccomp_notify_fd failed\n");
        return -1;
    }
    return notif_fd;
}

// The tracee's stack pointer at its current ptrace-stop
static int tracee_sp(pid_t pid, unsigned long *sp)
{
    struct user_regs_struct regs;
#if defined(__x86_64__)
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) return -1;
    *sp = (unsigned long)regs.rsp;
#elif defined(__aarch64__)
    // aarch64 glibc has no PTRACE_GETREGS; use the generic regset API instead
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) return -1;
    *sp = (unsigned long)regs.sp;
#endif
    return 0;
}

// Zeroes AT_SYSINFO_EHDR in the tracee's auxv; must run at each exec-stop, since the kernel rebuilds auxv on every execve(2)
static void disable_vdso(pid_t pid)
{
    unsigned long sp;
    if (tracee_sp(pid, &sp) < 0) {
        perror("ptrace(GETREGS)");
        return;
    }

    errno = 0;
    long argc = ptrace(PTRACE_PEEKDATA, pid, (void *)sp, NULL);
    if (errno) { perror("ptrace(PEEKDATA) argc"); return; }

    // sp points at argc; skip argc, argv[0..argc-1] and argv's NULL terminator
    unsigned long ptr = sp + (size_t)(argc + 2) * sizeof(long);

    // Skip envp[] until its own NULL terminator
    for (;;) {
        errno = 0;
        long v = ptrace(PTRACE_PEEKDATA, pid, (void *)ptr, NULL);
        if (errno) { perror("ptrace(PEEKDATA) envp"); return; }
        ptr += sizeof(long);
        if (v == 0) break;
    }

    // Scan auxv[] for AT_SYSINFO_EHDR
    for (;;) {
        errno = 0;
        long type = ptrace(PTRACE_PEEKDATA, pid, (void *)ptr, NULL);
        if (errno) { perror("ptrace(PEEKDATA) auxv type"); return; }
        if (type == AT_NULL) return;
        if (type == AT_SYSINFO_EHDR) {
            if (ptrace(PTRACE_POKEDATA, pid,
                       (void *)(ptr + sizeof(long)), 0L) < 0)
                perror("ptrace(POKEDATA) AT_SYSINFO_EHDR");
            return;
        }
        ptr += 2 * sizeof(long);
    }
}

/*
 * Continues every tracee with a state change pending, without blocking.
 * root's exit status is reported back through root_exited/root_status;
 * the rest of the tree is reaped for its own sake, since a tracee left
 * stopped never runs again and a descendant that outlives root still
 * holds the seccomp filter this process is listening on.
 */
static void reap_tracees(pid_t root, int *root_exited, int *root_status)
{
    for (;;) {
        int wstatus;
        pid_t pid = waitpid(-1, &wstatus, WNOHANG | __WALL);
        if (pid <= 0) return;

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            forget_pid(pid);
            if (pid == root) {
                *root_exited = 1;
                *root_status = wstatus;
            }
            continue;
        }
        if (!WIFSTOPPED(wstatus)) continue;

        /*
         * A pid we have never seen is a freshly auto-attached descendant
         * sitting at its attach stop. That stop's SIGSTOP is an artifact
         * of the attach, so continue it with no signal; injecting it
         * would stop the process for real.
         */
        if (track_pid(pid) != 1) {
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;
        }

        int event = wstatus >> 16;
        if (event == PTRACE_EVENT_EXEC) {
            // execve(2) rebuilt auxv from scratch, AT_SYSINFO_EHDR and all
            disable_vdso(pid);
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;
        }
        if (event != 0) {
            // fork/vfork/clone: the new process reports its own attach stop
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;
        }

        // Signal-delivery-stop: forward the stopping signal
        int sig = WSTOPSIG(wstatus);
        if (sig == SIGTRAP) sig = 0;
        ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig);
    }
}

// Reads data directly out of the tracee's address space
static int read_from_child(pid_t pid, uint64_t remote_addr, void *data, size_t len)
{
    if (!remote_addr) return -1;
    struct iovec local  = { data,                len };
    struct iovec remote = { (void *)remote_addr, len };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_readv");
        return -1;
    }
    return 0;
}

// Writes data directly into the tracee's address space
static int write_to_child(pid_t pid, uint64_t remote_addr,
                           const void *data, size_t len)
{
    if (!remote_addr) return 0;
    struct iovec local  = { (void *)data,        len };
    struct iovec remote = { (void *)remote_addr, len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        return -1;
    }
    return 0;
}

// Returns the clockid a timerfd was created with, by reading /proc/<pid>/fdinfo/<fd> -- avoids tracking fd -> clockid across fork/dup/SCM_RIGHTS
static int get_timerfd_clockid(pid_t pid, int fd)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", pid, fd);
    int f = open(path, O_RDONLY | O_CLOEXEC);
    if (f < 0) return -1;

    char buf[512];
    ssize_t n = read(f, buf, sizeof(buf) - 1);
    close(f);
    if (n <= 0) return -1;
    buf[n] = '\0';

    int clockid = -1;
    char *p = strstr(buf, "clockid:");
    if (p) sscanf(p, "clockid: %d", &clockid);
    return clockid;
}

// Services one intercepted syscall, faking wall-time reads per mode/value_ns
static void handle_time_notif(int notif_fd, faketime_mode_t mode, int64_t value_ns)
{
    struct seccomp_notif      *req  = NULL;
    struct seccomp_notif_resp *resp = NULL;

    if (seccomp_notify_alloc(&req, &resp) < 0) {
        perror("seccomp_notify_alloc");
        return;
    }

    int rc = seccomp_notify_receive(notif_fd, req);
    if (rc < 0) {
        if (rc != -EINTR && rc != -ENOENT)
            fprintf(stderr, "seccomp_notify_receive: %s\n", strerror(-rc));
        seccomp_notify_free(req, resp);
        return;
    }

    memset(resp, 0, sizeof(*resp));
    resp->id = req->id;

    // The tracee may have been killed/continued already; bail out quietly
    if (seccomp_notify_id_valid(notif_fd, req->id) < 0)
        goto send;

    switch (req->data.nr) {

    case SCMP_SYS(clock_gettime): {
        clockid_t clockid = (clockid_t)(int32_t)req->data.args[0];
        if (clockid != CLOCK_REALTIME && clockid != CLOCK_REALTIME_COARSE) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            break;
        }
        struct timespec ts;
        fake_now(mode, value_ns, &ts);
        if (write_to_child(req->pid, req->data.args[1], &ts, sizeof(ts)) < 0)
            resp->error = -errno;
        break;
    }

    case SCMP_SYS(gettimeofday): {
        struct timespec ts;
        fake_now(mode, value_ns, &ts);
        struct timeval tv = {
            .tv_sec  = ts.tv_sec,
            .tv_usec = ts.tv_nsec / 1000,
        };
        if (write_to_child(req->pid, req->data.args[0], &tv, sizeof(tv)) < 0)
            resp->error = -errno;
        break;
    }

    case SCMP_SYS(time): {
        struct timespec ts;
        fake_now(mode, value_ns, &ts);
        time_t now = ts.tv_sec;
        resp->val  = (int64_t)now;
        if (write_to_child(req->pid, req->data.args[0], &now, sizeof(now)) < 0)
            resp->error = -errno;
        break;
    }

    case SCMP_SYS(clock_nanosleep): {
        /*
         * Only an absolute deadline on a wall clock needs fixing up: it was
         * computed against the faked clock, so must be converted back to
         * real-clock terms before the kernel runs it. Relative sleeps and
         * non-wall clocks are correct as-is.
         */
        clockid_t clockid = (clockid_t)(int32_t)req->data.args[0];
        int       flags   = (int)req->data.args[1];
        if (!(flags & TIMER_ABSTIME) ||
            (clockid != CLOCK_REALTIME &&
             clockid != CLOCK_REALTIME_COARSE &&
             clockid != CLOCK_TAI)) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            break;
        }

        struct timespec ts;
        if (read_from_child(req->pid, req->data.args[2], &ts, sizeof(ts)) < 0) {
            resp->error = -errno;
            break;
        }
        unfake_deadline(mode, value_ns, &ts);
        if (write_to_child(req->pid, req->data.args[2], &ts, sizeof(ts)) < 0) {
            resp->error = -errno;
            break;
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        break;
    }

    case SCMP_SYS(timerfd_settime): {
        /*
         * As above, only an absolute expiration on a wall clock needs
         * fixing up. timerfd_gettime(2) isn't intercepted, so the caller's
         * old_value output (args[3]) is left in real-clock terms.
         */
        int fd    = (int)req->data.args[0];
        int flags = (int)req->data.args[1];
        if (!(flags & TFD_TIMER_ABSTIME)) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            break;
        }

        int clockid = get_timerfd_clockid(req->pid, fd);
        if (clockid != CLOCK_REALTIME &&
            clockid != CLOCK_REALTIME_COARSE &&
            clockid != CLOCK_TAI) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            break;
        }

        struct itimerspec its;
        if (read_from_child(req->pid, req->data.args[2], &its, sizeof(its)) < 0) {
            resp->error = -errno;
            break;
        }
        // it_value is the absolute expiry to fix up; it_interval is a relative period and is left alone
        unfake_deadline(mode, value_ns, &its.it_value);
        if (write_to_child(req->pid, req->data.args[2], &its, sizeof(its)) < 0) {
            resp->error = -errno;
            break;
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        break;
    }

    default:
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        break;
    }

send:
    rc = seccomp_notify_respond(notif_fd, resp);
    if (rc < 0 && rc != -ENOENT)
        fprintf(stderr, "seccomp_notify_respond: %s\n", strerror(-rc));

    seccomp_notify_free(req, resp);
}
