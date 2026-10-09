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

int main(void) {
    test_invalid_inputs_fail_closed();
    test_system_binary_is_trusted();
    test_group_and_world_writable_entries_are_untrusted();
    puts("PASS mk1_path_trust");
    return 0;
}
