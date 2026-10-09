CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2
CPPFLAGS += -D_POSIX_C_SOURCE=200809L
WARNINGS = -std=c11 -Wall -Wextra -Werror
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl)
HAVE_LIBOQS := $(shell $(PKG_CONFIG) --exists liboqs && echo yes)
ifeq ($(HAVE_LIBOQS),yes)
OQS_CFLAGS := $(shell $(PKG_CONFIG) --cflags liboqs)
OQS_LIBS := $(shell $(PKG_CONFIG) --libs liboqs)
OQS_SOURCE := mk1_tunnel_oqs.c
OQS_RUNNER_FLAGS := -DMK1_HAVE_LIBOQS
else
OQS_CFLAGS :=
OQS_LIBS :=
OQS_SOURCE :=
OQS_RUNNER_FLAGS :=
endif
NCURSES_PACKAGE := $(shell if $(PKG_CONFIG) --exists ncursesw; then echo ncursesw; else echo ncurses; fi)
NCURSES_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(NCURSES_PACKAGE))
NCURSES_LIBS := $(shell $(PKG_CONFIG) --libs $(NCURSES_PACKAGE))
BUILD_DIR ?= .build

.PHONY: all panel test analyze check clean

all: panel

$(BUILD_DIR):
	mkdir -p "$@"

panel: $(BUILD_DIR)/mk1-panel

$(BUILD_DIR)/mk1-panel: mk1_panel.c mk1_memory_guard.c mk1_path_trust.c mk1_tunnel.c $(OQS_SOURCE) mk1_memory_guard.h mk1_tunnel.h mk1_tunnel_oqs.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -pthread $(NCURSES_CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) \
		mk1_panel.c mk1_memory_guard.c mk1_path_trust.c mk1_tunnel.c $(OQS_SOURCE) $(NCURSES_LIBS) $(OPENSSL_LIBS) $(OQS_LIBS) -o "$@"

$(BUILD_DIR)/mk1_test_runner: mk1_test_runner.c mk1_memory_guard.c mk1_tunnel.c $(OQS_SOURCE) mk1_memory_guard.h mk1_tunnel.h mk1_tunnel_oqs.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) $(OQS_RUNNER_FLAGS) -pthread \
		mk1_test_runner.c mk1_memory_guard.c mk1_tunnel.c $(OQS_SOURCE) \
		$(OPENSSL_LIBS) $(OQS_LIBS) -ldl -o "$@"

$(BUILD_DIR)/test_mk1_tunnel: tests/test_mk1_tunnel.c mk1_tunnel.c mk1_tunnel.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -pthread $(OPENSSL_CFLAGS) \
		tests/test_mk1_tunnel.c mk1_tunnel.c $(OPENSSL_LIBS) -o "$@"

$(BUILD_DIR)/test_mk1_memory_guard: tests/test_mk1_memory_guard.c mk1_memory_guard.c mk1_memory_guard.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(OPENSSL_CFLAGS) \
		tests/test_mk1_memory_guard.c mk1_memory_guard.c $(OPENSSL_LIBS) -o "$@"

$(BUILD_DIR)/test_mk1_path_trust: tests/test_mk1_path_trust.c mk1_path_trust.c mk1_path_trust.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -UNDEBUG tests/test_mk1_path_trust.c mk1_path_trust.c -o "$@"

test: $(BUILD_DIR)/mk1_test_runner $(BUILD_DIR)/test_mk1_tunnel $(BUILD_DIR)/test_mk1_memory_guard $(BUILD_DIR)/test_mk1_path_trust
	"$(BUILD_DIR)/mk1_test_runner"
	"$(BUILD_DIR)/test_mk1_tunnel"
	"$(BUILD_DIR)/test_mk1_memory_guard"
	"$(BUILD_DIR)/test_mk1_path_trust"

analyze: | $(BUILD_DIR)
	clang --analyze -Xanalyzer -analyzer-output=text $(CPPFLAGS) $(WARNINGS) -pthread $(NCURSES_CFLAGS) $(OPENSSL_CFLAGS) $(OQS_CFLAGS) \
		mk1_panel.c mk1_memory_guard.c mk1_path_trust.c mk1_tunnel.c $(OQS_SOURCE)

check: panel test analyze

clean:
	rm -rf "$(BUILD_DIR)"
