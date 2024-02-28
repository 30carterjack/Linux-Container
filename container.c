#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux_types.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <limits.h>
/*#include <linux/capability.h>*/

struct child_process_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
};

/* Define the capabilities, mounts, syscalls, resources, and child_process functions */

int choose_hostname(char *buff, size_t len) {
    static const char *suits[] = {"swords", "cups", "coins", "wands"};
    static const char *minor[] = {"ace", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
                                  "page", "knight", "queen", "king"};
    static const char *major[] = {"the fool", "the magician", "the high priestess", "the empress", "the emperor"};
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec % 78;
    if (ix < sizeof(major) / sizeof(*major)) {
        snprintf(buff, len, "%05lx-%s", now.tv_sec, major[ix]);
    } else {
        ix -= sizeof(major) / sizeof(*major);
        snprintf(buff, len, "%05lxc-%s-of-%s", now.tv_sec, minor[ix % (sizeof(minor) / sizeof(*minor))], suits[ix / (sizeof(minor) / sizeof(*minor))]);
    }
    return 0;
}

void cleanup_resources(int sockets[2], char *stack) {
    if (sockets[0]) close(sockets[0]);
    if (sockets[1]) close(sockets[1]);
    free(stack);
}

void error_cleanup(int sockets[2], char *stack) {
    cleanup_resources(sockets, stack);
    // Additional error handling and cleanup if needed
}

#define USERNS_OFFSET 100000
#define USERNS_COUNT 200000

int handle_child_process_uid_map(pid_t child_process_pid, int fd) {
    int uid_map = 0;
    int has_userns = -1;
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "Failed to read from child process: %s\n", strerror(errno));
        return -1;
    }
    if (has_userns) {
        char path[PATH_MAX] = {0};
        for (char **file = (char *[]) {"uid_map", "gid_map", 0}; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_process_pid, *file) < 0) {
                fprintf(stderr, "Failed to create path: %s\n", strerror(errno));
                return -1;
            }
            fprintf(stderr, "Writing to %s...\n", path);
            if ((uid_map = open(path, O_WRONLY)) < 0) {
                fprintf(stderr, "Failed to open: %s\n", path, strerror(errno));
                return -1;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "Failed to write to %s: %s\n", path, strerror(errno));
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }
    }
    if (write(fd, & (int) {0}, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "Failed to write to child process: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int userns(struct child_process_config *config) {
    fprintf(stderr, "Entering user namespace...\n");

    // Check if the operating system is macOS
    fprintf(stderr, "User namespaces are not supported on linux.\n");
    return -1;
    
    // On non-macOS systems (e.g., Linux), proceed with user namespace setup
    int has_userns = !unshare(CLONE_NEWUSER);
    if (write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "Failed to write to parent process: %s\n", strerror(errno));
        return -1;
    }
    int result = 0;
    if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "Failed to read from parent process: %s\n", strerror(errno));
        return -1;
    }
    if (result) return -1;
    if (has_userns) {
        fprintf(stderr, "Setting up user namespace...\n");
    } else {
        fprintf(stderr, "Failed to enter user namespace.\n");
    }
    fprintf(stderr, "=> switching to uid %d / gid %d...\n", config->uid, config->uid);
    if (setuid(config->uid) == -1 || setgid(config->uid) == -1) {
        fprintf(stderr, "Failed to switch to uid/gid %d: %s\n", config->uid, strerror(errno));
        return -1;
    }
    fprintf(stderr, "done\n");
    return 0;
}

int child_process(void *arg) {
    struct child_process_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname))
        || mounts(config)
        || userns(config)
        || capabilities(config)
        || syscalls(config)) {
            close(config->fd);
            return -1;
    }
    if (close(config->fd)) {
        fprintf(stderr, "Failed to close file descriptor: %s\n", strerror(errno));
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL)) {
        fprintf(stderr, "Failed to execute %s: %s\n", config->argv[0], strerror(errno));
        return -1;
    }
    return 0;
}

int capabilities() {
    fprintf(stderr, "Setting capabilities...\n");
}

int drop_capabilities[] = {
    CAP_AUDIT_CONTROL,
    CAP_AUDIT_WRITE,
    CAP_BLOCK_SUSPEND,
    CAP_DAC_READ_SEARCH,
    CAP_FSETID,
    CAP_IPC_LOCK,
    CAP_MAC_ADMIN,
    CAP_MAC_OVERRIDE,
    CAP_MKNOD,
    CAP_SETFCAP,
    CAP_SYSLOG,
    CAP_SYS_ADMIN,
    CAP_SYS_BOOT,
    CAP_SYS_MODULE,
    CAP_SYS_NICE,
    CAP_SYS_RAWIO,
    CAP_SYS_RESOURCE,
    CAP_SYS_TIME,
    CAP_WAKE_ALARM
};

int set_capabilities() {
    size_t num_caps = sizeof(drop_capabilities) / sizeof(*drop_capabilities);
    fprintf(stderr, "Dropping capabilities...\n");
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_capabilities[i], 0, 0, 0)) {
            fprintf(stderr, "Failed to drop capability %d: %s\n", drop_capabilities[i], strerror(errno));
            return 1;
        }
    }
    fprintf(stderr, "Capabilities dropped successfully\n");

    fprintf(stderr, "Setting inheritable capabilities...\n");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc()) ||
        cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_capabilities, CAP_CLEAR) ||
        cap_set_proc(caps)) {
        fprintf(stderr, "Failed to set inheritable capabilities: %s\n", strerror(errno));
        if (caps) cap_free(caps);
        return 1;
    }
    fprintf(stderr, "Inheritable capabilities set successfully\n");
    if (caps) cap_free(caps);
    return 0;
}

int mounts() {
    fprintf(stderr, "=> Remounting with MS_PRIVATE...\n");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "Failed to remount /: %s\n", strerror(errno));
        return -1;
    }
    fprintf(stderr, "Remounted / with MS_PRIVATE\n");

    fprintf(stderr, "=> Creating a temporary directory and bind mount...\n");
    char *tmpdir = "/tmp/container";
    if (mkdir(tmpdir, 0755) && errno != EEXIST) {
        fprintf(stderr, "Failed to create temporary directory: %s\n", strerror(errno));
        return -1;
    }

    char mount_dir[] = "/tmp/container/mount";
    if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "Failed to bind mount %s to %s: %s\n", config->mount_dir, tmpdir, strerror(errno));
        return -1;
    }
    fprintf(stderr, "=> Bind mounting %s to %s successful...\n", tmpdir, mount_dir);

    fprintf(stderr, "=> Pivoting root...\n");
    if (pivot_root(mount_dir, mount_dir)) {
        fprintf(stderr, "Failed to pivot root: %s\n", strerror(errno));
        return -1;
    }
    fprintf(stderr, "Pivoted root successfully\n");

    char old_root[sizeof(mount_dir) + 1];
    strcpy(old_root, mount_dir);

    fprintf(stderr, "=> Unmounting old root: %s...\n", old_root);
    if (chdir("/")) {
        fprintf(stderr, "Failed to change directory to /: %s\n", strerror(errno));
        return -1;
    }

    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "Failed to unmount old root: %s\n", strerror(errno));
        return -1;
    }

    if (rmdir(old_root)) {
        fprintf(stderr, "Failed to remove old root: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}




int main(int argc, char **argv) {
    struct child_process_config config = {0};
    int err = 0;
    int option = 0;
    int sockets[2] = {0};
    pid_t child_process_pid = 0;
    char *stack = NULL;

    while ((option = getopt(argc, argv, "c:m:u:")) != -1) {
        switch (option) {
            case 'c':
                config.argc = argc - optind;
                config.argv = &argv[optind];
                goto finish_options;
            case 'm':
                config.mount_dir = optarg;
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1) {
                    fprintf(stderr, "Invalid uid: %s\n", optarg);
                    goto usage;
                }
                break;
            default:
                goto usage;
        }
    }
finish_options:
    if (!config.argc || !config.mount_dir) {
        fprintf(stderr, "Missing arguments.\n");
        goto usage;
    }

    /* Validate macOS version */
    struct utsname host = {0};
    if (uname(&host) < 0) {
        fprintf(stderr, "Failed to get host information: %s\n", strerror(errno));
        goto cleanup;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%d.%d", &major, &minor) != 2) {
        fprintf(stderr, "Failed to parse host release: %s\n", host.release);
        goto cleanup;
    }
    if (major < 10) {
        fprintf(stderr, "Unsupported linux version: %s\n", host.release);
        goto cleanup;
    }
    fprintf(stderr, "%s on %s\n", host.release, host.sysname);

    char hostname[256] = {0};
    if (choose_hostname(hostname, sizeof(hostname)) < 0) {
        fprintf(stderr, "Failed to generate hostname.\n");
        goto cleanup;
    }
    config.hostname = hostname;

    /* Perform other operations (namespaces, etc.) */

    // Place your additional code here, such as creating namespaces, setting up resources, etc.

cleanup:
    cleanup_resources(sockets, stack);
    return err;

usage:
    fprintf(stderr, "Usage: %s -u -1 -m . -c /bin/sh ~\n", argv[0]);
    err = 1;
    goto cleanup;
}
