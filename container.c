#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct child_process_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
};

<<capabilities>>

<<mounts>>

<<syscalls>>

<<resources>>

<<child>>

<<choose-hostname>>

int main(int argc, char **argv) {
    struct child_process_config config = {0};

    printf("Hello, world!\n");
    return 0;
}