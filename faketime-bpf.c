/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * faketime-bpf.c
 *
 * Run a command with a faked wall clock, without LD_PRELOAD.
 *
 * Minimal first cut: only clock_gettime(2), gettimeofday(2) and time(2)
 * are intercepted, and the fake time is a single fixed unix epoch (no
 * "flowing" mode, no relative offsets, no date parsing).
 *
 * On x86-64, glibc/musl serve clock_gettime(CLOCK_REALTIME) and
 * gettimeofday() straight out of the vDSO -- a read-only page the kernel
 * maps into every process -- without ever making a real syscall, so
 * seccomp alone cannot intercept them. To force the real syscalls to
 * happen, the child is ptrace(2)-stopped at its own exec(2) and
 * AT_SYSINFO_EHDR is zeroed in its freshly built auxv (see disable_vdso()
 * below); with that entry zeroed, the C runtime skips the vDSO and always
 * calls the kernel directly for these functions, which the seccomp-bpf
 * filter (installed by the child itself, right before execvp()) then
 * traps via SECCOMP_RET_USER_NOTIF.
 *
 * The seccomp listener fd is handed from the child to the parent over a
 * socketpair before execvp() replaces the child's image. That filter (and
 * therefore the listener fd) is inherited across any further fork(2)/
 * exec(2) the child performs, so a single poll loop over that one fd is
 * enough to service every intercepted syscall -- no further ptrace
 * supervision is needed beyond the single initial exec-stop.
 *
 * Adapted from timewarp <https://github.com/renard/timewarp>.
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <seccomp.h>

/*
 * disable_vdso() reads the stack pointer at the tracee's exec-stop to
 * locate argc/argv/envp/auxv, which lives at a register that is named
 * differently per architecture. Other architectures can be added here as
 * needed; until then, fail loudly at compile time rather than silently
 * reading the wrong register.
 */
#if defined(__x86_64__)
#define FTBPF_REG_SP(regs) ((unsigned long)(regs).rsp)
#else
#error "faketime-bpf: disable_vdso() is not implemented for this architecture"
#endif

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

/*
 * Install the seccomp-bpf filter; called by the child, before execvp().
 *
 * libseccomp builds the BPF program (including the architecture check
 * that keeps a mismatched-arch syscall, e.g. a 32-bit compat call, from
 * being misinterpreted against these x86-64 syscall numbers) and sets
 * PR_SET_NO_NEW_PRIVS on load, so neither is done by hand here.
 */
static int install_seccomp_filter(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return -1;
    }

    int syscalls[] = {
        SCMP_SYS(clock_gettime),
        SCMP_SYS(gettimeofday),
        SCMP_SYS(time),
    };
    for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, syscalls[i], 0);
        if (rc < 0) {
            fprintf(stderr, "seccomp_rule_add: %s\n", strerror(-rc));
            seccomp_release(ctx);
            return -1;
        }
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

/*
 * Zero AT_SYSINFO_EHDR in the tracee's auxv so its C runtime skips the
 * vDSO and always issues real clock_gettime/gettimeofday/time syscalls --
 * without this, those are normally served straight out of a shared
 * kernel page and never reach our seccomp filter at all.
 *
 * Must be called at the ptrace exec-stop: the kernel builds a fresh auxv
 * for every execve(2), before a single instruction of the new image runs.
 *
 * This is the plain word-by-word PTRACE_PEEKDATA/PTRACE_POKEDATA scan
 * (no process_vm_readv/writev fast path).
 */
static void disable_vdso(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(PTRACE_GETREGS)");
        return;
    }

    unsigned long sp = FTBPF_REG_SP(regs);

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

// Write data directly into the tracee's address space
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

// Service one intercepted syscall, faking wall-time reads to fake_epoch
static void handle_time_notif(int notif_fd, time_t fake_epoch)
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
        struct timespec ts = { .tv_sec = fake_epoch, .tv_nsec = 0 };
        if (write_to_child(req->pid, req->data.args[1], &ts, sizeof(ts)) < 0)
            resp->error = -errno;
        break;
    }

    case SCMP_SYS(gettimeofday): {
        struct timeval tv = { .tv_sec = fake_epoch, .tv_usec = 0 };
        if (write_to_child(req->pid, req->data.args[0], &tv, sizeof(tv)) < 0)
            resp->error = -errno;
        break;
    }

    case SCMP_SYS(time): {
        resp->val = (int64_t)fake_epoch;
        if (write_to_child(req->pid, req->data.args[0], &fake_epoch, sizeof(fake_epoch)) < 0)
            resp->error = -errno;
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

// Parse a (possibly '@'-prefixed) unix epoch, e.g. "1700000000" or "@1700000000"
static int parse_epoch(const char *s, time_t *out)
{
    if (*s == '@') s++;
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
    fprintf(stderr, "usage: %s [@]epoch command [args...]\n", prog);
}

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
    if (!parse_epoch(argv[1], &fake_epoch)) {
        fprintf(stderr, "faketime-bpf: invalid time '%s' (expected [@]epoch)\n", argv[1]);
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

        /*
         * Stop immediately so the parent can set PTRACE_O_TRACEEXEC
         * before we execvp(): it needs to catch the exec-stop to zero
         * AT_SYSINFO_EHDR in the new image's auxv (see disable_vdso()).
         */
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
    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(unsigned long)PTRACE_O_TRACEEXEC) < 0) {
        perror("ptrace(PTRACE_SETOPTIONS)");
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
     * No further ptrace supervision is needed past the exec-stop above:
     * the seccomp filter (and thus this listener fd) is inherited across
     * any further fork/exec the tracee performs, so a single poll loop
     * here covers it. The kernel signals POLLHUP once no process holds
     * the filter anymore, i.e. once the tracee (and any descendants) has
     * exited.
     */
    struct pollfd pfd = { .fd = notif_fd, .events = POLLIN };
    for (;;) {
        int r = poll(&pfd, 1, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (pfd.revents & POLLIN)
            handle_time_notif(notif_fd, fake_epoch);
        if ((pfd.revents & POLLHUP) && !(pfd.revents & POLLIN))
            break;
    }
    close(notif_fd);

    if (waitpid(child, &wstatus, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (WIFEXITED(wstatus))   return WEXITSTATUS(wstatus);
    if (WIFSIGNALED(wstatus)) return 128 + WTERMSIG(wstatus);
    return 1;
}
