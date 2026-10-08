#include "../mk1_memory_guard.h"

#include <assert.h>

int main(void) {
#ifdef __linux__
    assert(!mk1_memory_guard_is_enabled());
    assert(mk1_memory_guard_set_enabled(true) == 0);
    assert(mk1_memory_guard_is_enabled());
    assert(mk1_memory_guard_check_tracer() == 0);
    assert(mk1_memory_guard_set_enabled(false) == 0);
    assert(!mk1_memory_guard_is_enabled());
#endif
    return 0;
}
