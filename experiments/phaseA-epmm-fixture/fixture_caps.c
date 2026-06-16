// Decisive control: what ACTUALLY makes setns(CLONE_NEWNS) back to the original mount
// namespace return EPERM? Per fs/namespace.c mntns_install(), the ONLY EPERM source is the
// capability triple:
//     ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) &&
//     ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN) &&
//     ns_capable(current_user_ns(), CAP_SYS_ADMIN)
// There is NO mount-propagation reconciliation in this path. This program reproduces the
// EPERM via a user-namespace capability mismatch and shows the propagation flag is irrelevant.
//
// Model: a child enters a NEW user namespace (root-mapped, so it holds CAP_SYS_ADMIN only
// over its OWN userns) while the "original" mount namespace remains owned by the parent
// (init) user namespace. The child runs the supervisor sequence and setns() back to the
// init-owned original ns -> EPERM, identically for every propagation mode.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_file(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int rc = write(fd, val, strlen(val));
    close(fd);
    return rc < 0 ? -1 : 0;
}

// Returns errno of the setns-back (0 on success).
static int run_seq(const char *mode) {
    int original_ns = open("/proc/thread-self/ns/mnt", O_RDONLY);
    if (original_ns < 0) { perror("open original"); return -1; }
    if (unshare(CLONE_NEWNS) != 0) { perror("unshare mnt"); return -1; }
    if (!strcmp(mode, "buggy")) {
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
            fprintf(stderr, "  (mount / rprivate: %s)\n", strerror(errno));
    } else if (!strcmp(mode, "private")) {
        mount(NULL, "/proc", NULL, MS_PRIVATE, NULL); // any existing mount; flag-scope is the point
    }
    errno = 0;
    int rc = setns(original_ns, CLONE_NEWNS);
    int e = rc == 0 ? 0 : errno;
    close(original_ns);
    return e;
}

int main(void) {
    const char *modes[] = {"buggy", "private", NULL};
    for (int i = 0; modes[i]; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Enter a new user namespace; map our uid->root so we hold caps over THIS userns
            // but NOT over the parent/init userns that owns the original mount namespace.
            uid_t uid = getuid(); gid_t gid = getgid();
            if (unshare(CLONE_NEWUSER) != 0) { perror("unshare userns"); _exit(3); }
            char m[64];
            write_file("/proc/self/setgroups", "deny");
            snprintf(m, sizeof m, "0 %u 1", uid); write_file("/proc/self/uid_map", m);
            snprintf(m, sizeof m, "0 %u 1", gid); write_file("/proc/self/gid_map", m);
            int e = run_seq(modes[i]);
            printf("MODE=%-8s setns_back: %s\n", modes[i],
                   e == 0 ? "OK (no EPERM)" : strerror(e));
            _exit(e == EPERM ? 42 : (e == 0 ? 0 : 1));
        }
        int st; waitpid(pid, &st, 0);
        (void)st;
    }
    return 0;
}
