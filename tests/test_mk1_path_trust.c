#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../mk1_path_trust.h"

static void test_invalid_inputs_fail_closed(void) {
    assert(mk1_path_chain_is_root_trusted(NULL) == 0);
    assert(mk1_path_chain_is_root_trusted("") == 0);
    assert(mk1_path_chain_is_root_trusted("/nonexistent/mk1/path") == 0);
}

static void test_system_binary_is_trusted(void) {
    assert(mk1_path_chain_is_root_trusted("/usr/bin/env") == 1);
}

static void test_group_and_world_writable_entries_are_untrusted(void) {
    char directory[] = "/tmp/mk1-path-trust-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    char file[256];
    snprintf(file, sizeof(file), "%s/script.py", directory);
    int fd = open(file, O_CREAT | O_WRONLY, 0644);
    assert(fd >= 0);
    close(fd);

    /* /tmp is world-writable, so nothing below it can be trusted. */
    assert(mk1_path_chain_is_root_trusted(file) == 0);
    assert(mk1_path_chain_is_root_trusted("/tmp") == 0);

    unlink(file);
    rmdir(directory);
}

static void test_private_directory_is_created_and_restricted(void) {
    char root[] = "/tmp/mk1-private-directory-XXXXXX";
    assert(mkdtemp(root) != NULL);
    char directory[256];
    snprintf(directory, sizeof(directory), "%s/data", root);

    assert(mk1_ensure_private_directory(directory) == 1);
    struct stat info;
    assert(stat(directory, &info) == 0);
    assert((info.st_mode & 0777) == 0700);

    assert(chmod(directory, 0775) == 0);
    assert(mk1_ensure_private_directory(directory) == 1);
    assert(stat(directory, &info) == 0);
    assert((info.st_mode & 0777) == 0700);

    assert(rmdir(directory) == 0);
    assert(rmdir(root) == 0);
}

static void test_private_directory_rejects_symlinks_and_regular_files(void) {
    char root[] = "/tmp/mk1-private-reject-XXXXXX";
    assert(mkdtemp(root) != NULL);
    char target[256];
    char link_path[256];
    char regular_file[256];
    char fifo_path[256];
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(link_path, sizeof(link_path), "%s/link", root);
    snprintf(regular_file, sizeof(regular_file), "%s/file", root);
    snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", root);

    assert(mkdir(target, 0700) == 0);
    assert(symlink(target, link_path) == 0);
    assert(mk1_ensure_private_directory(link_path) == 0);
    assert(rmdir(target) == 0);

    int descriptor = open(regular_file, O_CREAT | O_WRONLY, 0600);
    assert(descriptor >= 0);
    close(descriptor);
    assert(mk1_ensure_private_directory(regular_file) == 0);
    assert(mkfifo(fifo_path, 0600) == 0);
    assert(mk1_ensure_private_directory(fifo_path) == 0);

    unlink(regular_file);
    unlink(link_path);
    unlink(fifo_path);
    assert(rmdir(root) == 0);
}

int main(void) {
    test_invalid_inputs_fail_closed();
    test_system_binary_is_trusted();
    test_group_and_world_writable_entries_are_untrusted();
    test_private_directory_is_created_and_restricted();
    test_private_directory_rejects_symlinks_and_regular_files();
    puts("PASS mk1_path_trust");
    return 0;
}
