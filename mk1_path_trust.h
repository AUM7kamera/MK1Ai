#ifndef MK1_PATH_TRUST_H
#define MK1_PATH_TRUST_H

/*
 * Returns 1 only if the path (both as written and after symlink resolution)
 * and every ancestor directory are owned by root and not group/other writable.
 * Relative paths are interpreted against the current directory. Returns 0 on
 * any error or untrusted entry, so callers fail closed.
 */
int mk1_path_chain_is_root_trusted(const char *path);

#endif
