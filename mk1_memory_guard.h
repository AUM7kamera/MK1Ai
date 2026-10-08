#ifndef MK1_MEMORY_GUARD_H
#define MK1_MEMORY_GUARD_H

#include <stdbool.h>
#include <stddef.h>

int mk1_memory_guard_set_enabled(bool enabled);
int mk1_memory_guard_check_tracer(void);
int mk1_memory_guard_lock_memory(void *address, size_t length);
int mk1_memory_guard_unlock_memory(void *address, size_t length);
void mk1_memory_guard_zero_memory(void *address, size_t length);
bool mk1_memory_guard_is_enabled(void);

#endif
