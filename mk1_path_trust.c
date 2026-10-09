#define _POSIX_C_SOURCE 200809L

#include "mk1_path_trust.h"

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
