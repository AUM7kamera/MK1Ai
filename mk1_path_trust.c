#define _POSIX_C_SOURCE 200809L

#include "mk1_path_trust.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int entry_is_trusted(const char *path) {
    struct stat info;
    if (stat(path, &info) != 0) return 0;
    return info.st_uid == 0 && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int absolute_chain_is_trusted(const char *absolute) {
    char current[PATH_MAX];
    if (absolute[0] != '/' || strlen(absolute) >= sizeof(current)) return 0;
    if (snprintf(current, sizeof(current), "%s", absolute) >= (int)sizeof(current)) return 0;
    for (;;) {
        if (!entry_is_trusted(current)) return 0;
        if (strcmp(current, "/") == 0) return 1;
        char *slash = strrchr(current, '/');
        if (slash == NULL) return 0;
        if (slash == current) {
            current[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
}

int mk1_path_chain_is_root_trusted(const char *path) {
    if (path == NULL || path[0] == '\0') return 0;
    char lexical[PATH_MAX];
    if (path[0] == '/') {
        if (strlen(path) >= sizeof(lexical)) return 0;
        if (snprintf(lexical, sizeof(lexical), "%s", path) >= (int)sizeof(lexical)) return 0;
    } else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) return 0;
        if (snprintf(lexical, sizeof(lexical), "%s/%s", cwd, path) >= (int)sizeof(lexical)) return 0;
    }
    char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL) return 0;
    return absolute_chain_is_trusted(lexical) && absolute_chain_is_trusted(resolved);
}

int mk1_ensure_private_directory(const char *path) {
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return 0;
    }
    if (mkdir(path, S_IRWXU) != 0 && errno != EEXIST) return 0;

    int descriptor = open(
        path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_DIRECTORY
    );
    if (descriptor < 0) return 0;

    struct stat info;
    int result = 0;
    if (fstat(descriptor, &info) != 0) {
        goto done;
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid()) {
        errno = EPERM;
        goto done;
    }
    if (fchmod(descriptor, S_IRWXU) != 0) {
        goto done;
    }
    result = 1;

done:
    {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    return result;
}
