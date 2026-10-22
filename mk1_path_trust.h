#ifndef MK1_PATH_TRUST_H
#define MK1_PATH_TRUST_H

/*
 * Returns 1 only if the path (both as written and after symlink resolution)
 * and every ancestor directory are owned by root and not group/other writable.
 * Relative paths are interpreted against the current directory. Returns 0 on
 * any error or untrusted entry, so callers fail closed.
 */
int mk1_path_chain_is_root_trusted(const char *path);

/*
 * Creates the directory as owner-only when absent, then validates the opened
 * path without following a final symlink and enforces mode 0700. The directory
 * must be owned by the effective user; returns 0 on any error.
 */
int mk1_ensure_private_directory(const char *path);

#endif
