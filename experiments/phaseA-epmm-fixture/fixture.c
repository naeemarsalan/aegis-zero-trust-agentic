// Phase A off-cluster fixture for ADR-0011 / ADR-0009 (provider_spiffe EPMM setns EPERM).
//
// Mirrors OpenShell crates/openshell-supervisor-process/src/process.rs
// create_supervisor_identity_mount_namespace() SYSCALL-FOR-SYSCALL:
//   1. open original mnt ns fd (/proc/thread-self/ns/mnt)
//   2. unshare(CLONE_NEWNS)
//   3. propagation step (MODE-dependent — this is the patch under test)
//   4. mount RDONLY tmpfs at the socket-parent (the "hide"), unchanged
//   5. open sanitized ns fd
//   6. setns(original)  <-- EPERM fires here on CRI-O today
//
// Topology reproduced (ADR-0011 root cause): the spire-spiffe-csi-driver DaemonSet
// mounts /var/lib/kubelet/pods Bidirectional (rshared), so CRI-O delivers the
// csi.spiffe.io Workload-API socket dir into the pod as a SHARED peer-group member.
// Structural correction (ADR-0011): `target` IS the csi.spiffe.io mountpoint itself
// (/spiffe-workload-api), not a dir merely containing it. So the CSI mountpoint is a
// shared mount, and the tmpfs overlays that same mountpoint.
//
// MODES:
//   buggy   : mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)      -- current code (expect EPERM)
//   private : mount(NULL,TARGET,NULL,MS_PRIVATE,NULL)          -- preferred fix (non-recursive)
//   slave   : mount(NULL,TARGET,NULL,MS_SLAVE,NULL)            -- fallback fix (non-recursive)
//   none    : no propagation change (control)
//
// Emits machine-greppable lines: "ASSERT <name> PASS|FAIL <detail>".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define HOST_CSI "/host-csi"            // master peer (the csi-driver's rshared source)
#define TARGET   "/spiffe-workload-api" // the csi.spiffe.io mountpoint inside the "pod"
#define SOCK     TARGET "/spire-agent.sock"
#define HOST_SOCK HOST_CSI "/spire-agent.sock"

static int g_fail = 0;

static void assert_line(const char *name, int pass, const char *fmt, ...) {
    char detail[512];
    va_list ap; va_start(ap, fmt); vsnprintf(detail, sizeof detail, fmt, ap); va_end(ap);
    printf("ASSERT %-34s %s %s\n", name, pass ? "PASS" : "FAIL", detail);
    fflush(stdout);
    if (!pass) g_fail = 1;
}

// TOPO=external (default, faithful CRI-O): the shared peer-group MASTER lives in the
// "host" ns (held alive by an fd); we then unshare into a "pod" ns where the CSI mount
// is a propagated member of that host-owned peer group, and run the supervisor sequence
// from inside the pod (this models kubelet rshared /var/lib/kubelet/pods -> pod).
// TOPO=local : master peer-group lives in the same ns the sequence runs in (weak model).
static const char *topo_mode(void) {
    const char *t = getenv("TOPO");
    return (t && *t) ? t : "external";
}

// Create a real listening unix socket at `path`.
static int make_listening_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr; memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 1) < 0) { close(fd); return -1; }
    return fd;
}

// Build the CRI-O-shaped shared-peer-group topology in the current (container root) mnt ns.
// Returns 0 on success.
static int setup_topology(void) {
    // HOST_CSI = the master peer (analogue of spiffe-csi-driver's mount on rshared kubelet tree).
    mkdir(HOST_CSI, 0755);
    if (mount("none", HOST_CSI, "tmpfs", 0, "mode=0755") != 0) {
        fprintf(stderr, "setup: mount tmpfs %s: %s\n", HOST_CSI, strerror(errno)); return -1;
    }
    if (mount(NULL, HOST_CSI, NULL, MS_SHARED, NULL) != 0) {
        fprintf(stderr, "setup: make-shared %s: %s\n", HOST_CSI, strerror(errno)); return -1;
    }
    // The real spire-agent.sock lives in the master peer.
    int s = make_listening_socket(HOST_SOCK);
    if (s < 0) { fprintf(stderr, "setup: socket %s: %s\n", HOST_SOCK, strerror(errno)); return -1; }
    // leak the fd intentionally (keep it listening for the whole run)

    // TARGET = the csi.spiffe.io mountpoint delivered INTO the pod. Because HOST_CSI is
    // shared, bind-mounting it makes TARGET a member of the SAME peer group (shared) ->
    // exactly "CRI-O delivers the socket as a shared peer-group member".
    mkdir(TARGET, 0755);
    if (mount(HOST_CSI, TARGET, NULL, MS_BIND, NULL) != 0) {
        fprintf(stderr, "setup: bind %s->%s: %s\n", HOST_CSI, TARGET, strerror(errno)); return -1;
    }
    return 0;
}

static int socket_visible_in_ns(int ns_fd) {
    // In a child: enter ns_fd, stat the socket. Returns 1 if visible, 0 if hidden.
    pid_t pid = fork();
    if (pid == 0) {
        if (setns(ns_fd, CLONE_NEWNS) != 0) { _exit(2); } // 2 = couldn't even enter
        struct stat st;
        _exit(stat(SOCK, &st) == 0 ? 1 : 0); // 1 = visible, 0 = hidden
    }
    int status; waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "buggy";
    const char *topo = topo_mode();
    printf("TOPO=%s MODE=%s\n", topo, mode);

    // Build the shared peer-group topology in the current ns (the "host"/init ns).
    if (setup_topology() != 0) { fprintf(stderr, "topology setup failed\n"); return 3; }

    // For the faithful CRI-O model, hold the HOST ns alive via an open fd, then unshare
    // into a "pod" ns. The CSI mount is now a propagated member of the host-owned peer
    // group, with the master living OUTSIDE this (pod) namespace.
    int host_ns = -1;
    if (!strcmp(topo, "external")) {
        host_ns = open("/proc/thread-self/ns/mnt", O_RDONLY); // keep open => keeps peer group's host home alive
        if (host_ns < 0) { perror("open host ns"); return 3; }
        if (unshare(CLONE_NEWNS) != 0) { perror("unshare pod ns"); return 3; }
        // We are now in the POD ns; TARGET here is a peer of the host's TARGET.
    }

    // Sanity: the socket IS visible at TARGET before any isolation.
    { struct stat st; int rc = stat(SOCK, &st);
      assert_line("pre.socket_visible", rc == 0, "stat(%s) %s", SOCK, rc == 0 ? "ok" : strerror(errno)); }

    // ---- mirror create_supervisor_identity_mount_namespace (run inside the POD ns) ----
    int original_ns = open("/proc/thread-self/ns/mnt", O_RDONLY);
    if (original_ns < 0) { perror("open original ns"); return 3; }

    if (unshare(CLONE_NEWNS) != 0) { perror("unshare"); return 3; }

    // (3) propagation step — THE PATCH UNDER TEST.
    int prop_rc = 0; const char *prop_what = "";
    if (!strcmp(mode, "buggy")) {
        prop_what = "MS_REC|MS_PRIVATE /";
        prop_rc = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
    } else if (!strcmp(mode, "private")) {
        prop_what = "MS_PRIVATE " TARGET " (non-rec)";
        prop_rc = mount(NULL, TARGET, NULL, MS_PRIVATE, NULL);
    } else if (!strcmp(mode, "slave")) {
        prop_what = "MS_SLAVE " TARGET " (non-rec)";
        prop_rc = mount(NULL, TARGET, NULL, MS_SLAVE, NULL);
    } else if (!strcmp(mode, "none")) {
        prop_what = "(none)";
    } else { fprintf(stderr, "unknown mode %s\n", mode); return 3; }
    assert_line("propagation_change", prop_rc == 0, "%s rc=%d %s",
        prop_what, prop_rc, prop_rc ? strerror(errno) : "ok");

    // (4) the hide — unchanged tmpfs overlay at the socket-parent (== TARGET).
    int tmpfs_rc = mount("tmpfs", TARGET, "tmpfs",
                         MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, "mode=0555,size=4k");
    assert_line("tmpfs_overlay", tmpfs_rc == 0, "%s", tmpfs_rc ? strerror(errno) : "ok");

    // (5) open sanitized ns fd
    int sanitized_ns = open("/proc/thread-self/ns/mnt", O_RDONLY);
    if (sanitized_ns < 0) { perror("open sanitized ns"); return 3; }

    // (6) setns back to original — THE EPERM SITE.
    int setns_rc = setns(original_ns, CLONE_NEWNS);
    int setns_errno = errno;
    assert_line("setns_restore", setns_rc == 0, "rc=%d %s",
        setns_rc, setns_rc ? strerror(setns_errno) : "ok (no EPERM)");

    // mustFix #1b: from inside the SANITIZED ns the real socket must NOT be visible.
    int vis = socket_visible_in_ns(sanitized_ns);
    assert_line("hide.socket_hidden_in_sanitized", vis == 0,
        "%s", vis == 1 ? "VISIBLE (leak!)" : vis == 0 ? "hidden" : "could-not-enter-ns");

    // mustFix #3: propagation re-leak. Trigger a mount AND unmount on the MASTER peer,
    // then assert the real socket does NOT reappear at TARGET inside the sanitized ns.
    // (We are back in the original ns now, so we can mutate HOST_CSI's peer group.)
    {
        // mount something new into the master peer group...
        mkdir(HOST_CSI "/extra", 0755);
        int m1 = mount("none", HOST_CSI "/extra", "tmpfs", 0, "mode=0755");
        int u1 = umount2(HOST_CSI "/extra", MNT_DETACH);
        (void)m1; (void)u1;
        int vis2 = socket_visible_in_ns(sanitized_ns);
        assert_line("releak.after_master_mutation", vis2 == 0,
            "%s (m=%d u=%d)", vis2 == 1 ? "RE-LEAKED" : vis2 == 0 ? "still-hidden" : "enter-fail",
            m1, u1);
    }

    close(original_ns); close(sanitized_ns);
    if (host_ns >= 0) close(host_ns);
    printf("RESULT topo=%s mode=%s overall=%s\n", topo, mode, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
