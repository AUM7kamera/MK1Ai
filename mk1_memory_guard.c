#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "mk1_memory_guard.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

void mk1_memory_guard_zero_memory(void *address, size_t length) {
    if (address != NULL && length > 0) OPENSSL_cleanse(address, length);
}

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

static bool guard_enabled;
static bool guard_state_uncertain;
static int original_dumpable;
static struct rlimit original_core_limit;

static int restore_protected_state(int dumpable, const struct rlimit *core_limit) {
    int result = 0;
    struct rlimit protected_limit = *core_limit;
    protected_limit.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &protected_limit) != 0) result = errno;
    if (prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0) != 0 && result == 0) result = errno;
    return result;
}

bool mk1_memory_guard_is_enabled(void) {
    return guard_enabled || guard_state_uncertain;
}

int mk1_memory_guard_set_enabled(bool enabled) {
    if (guard_state_uncertain) return EIO;
    if (enabled == guard_enabled) return 0;
    if (enabled) {
        int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        if (dumpable < 0) return errno;
        struct rlimit core_limit;
        if (getrlimit(RLIMIT_CORE, &core_limit) != 0) return errno;
        struct rlimit protected_limit = core_limit;
        protected_limit.rlim_cur = 0;
        if (setrlimit(RLIMIT_CORE, &protected_limit) != 0) return errno;
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
            int saved_errno = errno;
            int rollback_error = setrlimit(RLIMIT_CORE, &core_limit) == 0 ? 0 : errno;
            if (rollback_error != 0) {
                original_dumpable = dumpable;
                original_core_limit = core_limit;
                guard_enabled = restore_protected_state(0, &core_limit) == 0;
                guard_state_uncertain = !guard_enabled;
                return rollback_error;
            }
            return saved_errno;
        }
        original_dumpable = dumpable;
        original_core_limit = core_limit;
        guard_enabled = true;
        return 0;
    }

    int result = 0;
    if (prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0) != 0) result = errno;
    if (setrlimit(RLIMIT_CORE, &original_core_limit) != 0 && result == 0) result = errno;
    if (result == 0) {
        guard_enabled = false;
        return 0;
    }
    int rollback_error = restore_protected_state(0, &original_core_limit);
    guard_state_uncertain = rollback_error != 0;
    guard_enabled = true;
    return rollback_error != 0 ? rollback_error : result;
}

int mk1_memory_guard_check_tracer(void) {
    if (guard_state_uncertain) return -EIO;
    if (!guard_enabled) return 0;
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL) return -errno;
    char line[128];
    bool found = false;
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "TracerPid:%d", &tracer_pid) == 1) {
            found = true;
            break;
        }
    }
    int close_result = fclose(status);
    if (!found || close_result != 0) return -EIO;
    if (tracer_pid > 0) {
        (void)kill(getpid(), SIGKILL);
        return 1;
    }
    return 0;
}

int mk1_memory_guard_lock_memory(void *address, size_t length) {
    if (address == NULL || length == 0) return EINVAL;
    long page_size_value = sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0) return errno ? errno : EINVAL;
    uintptr_t page_size = (uintptr_t)page_size_value;
    uintptr_t start = (uintptr_t)address;
    uintptr_t page_start = start - start % page_size;
    if (length > UINTPTR_MAX - start) return EOVERFLOW;
    uintptr_t end = start + length;
    uintptr_t page_end = end;
    uintptr_t remainder = end % page_size;
    if (remainder != 0) {
        uintptr_t padding = page_size - remainder;
        if (end > UINTPTR_MAX - padding) return EOVERFLOW;
        page_end += padding;
    }
    if (page_end < page_start || page_end - page_start > SIZE_MAX) return EOVERFLOW;
    size_t page_length = (size_t)(page_end - page_start);
    if (mlock(address, length) != 0) return errno;
    if (madvise((void *)page_start, page_length, MADV_DONTDUMP) != 0) {
        int saved_errno = errno;
        if (munlock(address, length) != 0) return errno;
        return saved_errno;
    }
    return 0;
}

int mk1_memory_guard_unlock_memory(void *address, size_t length) {
    if (address == NULL || length == 0) return EINVAL;
    return munlock(address, length) == 0 ? 0 : errno;
}

#else

bool mk1_memory_guard_is_enabled(void) {
    return false;
}

int mk1_memory_guard_set_enabled(bool enabled) {
    return enabled ? ENOTSUP : 0;
}

int mk1_memory_guard_check_tracer(void) {
    return -ENOTSUP;
}

int mk1_memory_guard_lock_memory(void *address, size_t length) {
    (void)address;
    (void)length;
    return ENOTSUP;
}

int mk1_memory_guard_unlock_memory(void *address, size_t length) {
    (void)address;
    (void)length;
    return ENOTSUP;
}

#endif
