#define _POSIX_C_SOURCE 200809L

#include "mk1_memory_guard.h"
#include "mk1_tunnel.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dlfcn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#ifdef MK1_HAVE_LIBOQS
#include "mk1_tunnel_oqs.h"
#include <oqs/oqs.h>
#endif

#ifdef __linux__
#include <signal.h>
#include <sys/ptrace.h>
#endif

static bool read_byte_with_timeout(int descriptor, uint8_t *value) {
    struct pollfd item = {.fd = descriptor, .events = POLLIN};
    int result;
    do {
        result = poll(&item, 1, 5000);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || (item.revents & POLLIN) == 0) return false;
    ssize_t received;
    do {
        received = read(descriptor, value, sizeof(*value));
    } while (received < 0 && errno == EINTR);
    return received == (ssize_t)sizeof(*value);
}

static bool write_byte(int descriptor, uint8_t value) {
    ssize_t written;
    do {
        written = write(descriptor, &value, sizeof(value));
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)sizeof(value);
}

static int check_optional_library(const char *const *names, const char *label,
                                  const char *init_symbol) {
    void *handle = NULL;
    for (size_t i = 0; names[i] != NULL && handle == NULL; ++i) {
        handle = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
    }
    if (handle == NULL) {
        printf("SKIP %s: library is not installed\n", label);
        return 0;
    }

    void *symbol = dlsym(handle, init_symbol);
    if (symbol == NULL) {
        fprintf(stderr, "FAIL %s: required initialization symbol %s is missing\n",
                label, init_symbol);
        (void)dlclose(handle);
        return 1;
    }
    if (strcmp(label, "libsodium") == 0) {
        int (*sodium_init_fn)(void) = (int (*)(void))symbol;
        int result = sodium_init_fn();
        if (result < 0) {
            fprintf(stderr, "FAIL libsodium: sodium_init returned %d\n", result);
            (void)dlclose(handle);
            return 1;
        }
        void *wipe_symbol = dlsym(handle, "sodium_memzero");
        if (wipe_symbol == NULL) {
            fprintf(stderr, "FAIL libsodium: sodium_memzero is missing\n");
            (void)dlclose(handle);
            return 1;
        }
        void (*sodium_memzero_fn)(void *, size_t) =
            (void (*)(void *, size_t))wipe_symbol;
        uint8_t secret[32];
        memset(secret, 0xA5, sizeof(secret));
        sodium_memzero_fn(secret, sizeof(secret));
        for (size_t i = 0; i < sizeof(secret); ++i) {
            if (secret[i] != 0) {
                fprintf(stderr, "FAIL libsodium: sodium_memzero did not clear the buffer\n");
                (void)dlclose(handle);
                return 1;
            }
        }
    } else if (strcmp(label, "libbpf") == 0) {
        const char *(*version_fn)(void) = (const char *(*)(void))symbol;
        const char *version = version_fn();
        if (version == NULL || version[0] == '\0') {
            fprintf(stderr, "FAIL libbpf: libbpf_version_string returned no version\n");
            (void)dlclose(handle);
            return 1;
        }
    } else if (strcmp(label, "liboqs") == 0) {
        int (*oqs_init_fn)(void) = (int (*)(void))symbol;
        if (oqs_init_fn() != 0) {
            fprintf(stderr, "FAIL liboqs: OQS_init failed\n");
            (void)dlclose(handle);
            return 1;
        }
        void *(*kem_new_fn)(const char *) =
            (void *(*)(const char *))dlsym(handle, "OQS_KEM_new");
        void (*kem_free_fn)(void *) =
            (void (*)(void *))dlsym(handle, "OQS_KEM_free");
        if (kem_new_fn == NULL || kem_free_fn == NULL) {
            fprintf(stderr, "FAIL liboqs: ML-KEM-768 provider API is missing\n");
            (void)dlclose(handle);
            return 1;
        }
        void *kem = kem_new_fn("ML-KEM-768");
        if (kem == NULL) {
            fprintf(stderr, "FAIL liboqs: ML-KEM-768 algorithm is unavailable\n");
            (void)dlclose(handle);
            return 1;
        }
        kem_free_fn(kem);
    }
    if (strcmp(label, "libbpf") == 0) {
        puts("PASS libbpf: loaded and version API verified");
    } else {
        printf("PASS %s: loaded and initialized%s\n", label,
               strcmp(label, "liboqs") == 0 ? " (ML-KEM-768 available)" : "");
    }
    (void)dlclose(handle);
    return 0;
}

static int test_mlkem_tunnel(void) {
#ifdef MK1_HAVE_LIBOQS
    uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE] = {0};
    uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE] = {0};
    uint8_t kem_ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE] = {0};
    uint8_t plaintext[] = "ML-KEM-768 test message";
    uint8_t ciphertext[sizeof(plaintext)] = {0};
    uint8_t decrypted[sizeof(plaintext)] = {0};
    uint8_t aad[] = "test aad";
    uint8_t nonce[MK1_TUNNEL_NONCE_SIZE] = {0};
    uint8_t tag[MK1_TUNNEL_TAG_SIZE] = {0};
    size_t ciphertext_length = 0;
    size_t plaintext_length = 0;
    mk1_mlkem768_provider provider = {0};

    if (mk1_tunnel_oqs_provider_init(&provider) != 0) goto failure;
    OQS_KEM *kem = provider.context;
    if (OQS_KEM_keypair(kem, public_key, private_key) != OQS_SUCCESS
        || mk1_tunnel_set_enabled(true) != 0
        || mk1_tunnel_mlkem768_encapsulate(&provider, public_key, kem_ciphertext) != 0
        || mk1_tunnel_set_enabled(true) != 0
        || mk1_tunnel_mlkem768_decapsulate(&provider, private_key, kem_ciphertext) != 0
        || mk1_tunnel_encrypt(plaintext, sizeof(plaintext), aad, sizeof(aad),
                              nonce, ciphertext, sizeof(ciphertext),
                              &ciphertext_length, tag) != 0
        || mk1_tunnel_decrypt(ciphertext, ciphertext_length, aad, sizeof(aad),
                              nonce, tag, decrypted, sizeof(decrypted),
                              &plaintext_length) != 0
        || plaintext_length != sizeof(plaintext)
        || memcmp(plaintext, decrypted, sizeof(plaintext)) != 0) {
        goto failure;
    }

    (void)mk1_secure_key_wipe();
    mk1_tunnel_oqs_provider_cleanup(&provider);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    puts("PASS liboqs ML-KEM-768 + AES-256-GCM round trip");
    return 0;

failure:
    (void)mk1_secure_key_wipe();
    mk1_tunnel_oqs_provider_cleanup(&provider);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    fprintf(stderr, "FAIL liboqs ML-KEM-768 tunnel round trip\n");
    return 1;
#else
    puts("SKIP C ML-KEM-768 round trip: liboqs development package is unavailable");
    return 0;
#endif
}

#ifdef __linux__
static int test_ptrace_restriction(void) {
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    if (pipe(ready) != 0) {
        fprintf(stderr, "FAIL ptrace test: pipe: %s\n", strerror(errno));
        return 1;
    }
    if (pipe(release) != 0) {
        fprintf(stderr, "FAIL ptrace test: pipe: %s\n", strerror(errno));
        close(ready[0]);
        close(ready[1]);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "FAIL ptrace test: fork: %s\n", strerror(errno));
        close(ready[0]);
        close(ready[1]);
        close(release[0]);
        close(release[1]);
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        uint8_t result = mk1_memory_guard_set_enabled(true) == 0 ? 0 : 1;
        if (!write_byte(ready[1], result)) _exit(2);
        close(ready[1]);
        if (result != 0) _exit(3);
        uint8_t command = 0;
        ssize_t received;
        do {
            received = read(release[0], &command, sizeof(command));
        } while (received < 0 && errno == EINTR);
        close(release[0]);
        _exit(received == (ssize_t)sizeof(command) ? 0 : 4);
    }

    close(ready[1]);
    close(release[0]);
    uint8_t child_status = 1;
    bool ready_received = read_byte_with_timeout(ready[0], &child_status);
    close(ready[0]);
    if (!ready_received || child_status != 0) {
        fprintf(stderr, "FAIL ptrace test: child could not enable dump protection\n");
        close(release[1]);
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return 1;
    }

    errno = 0;
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == 0) {
        int status = 0;
        if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
            fprintf(stderr, "FAIL ptrace test: attached child did not stop\n");
            close(release[1]);
            (void)kill(child, SIGKILL);
            (void)waitpid(child, NULL, 0);
            return 1;
        }
        (void)ptrace(PTRACE_DETACH, child, NULL, NULL);
        printf("SKIP ptrace denial assertion: caller has ptrace override capability\n");
    } else if (errno == EPERM || errno == EACCES) {
        printf("PASS ptrace restriction: attaching to protected child was denied\n");
    } else {
        fprintf(stderr, "FAIL ptrace test: unexpected attach error: %s\n", strerror(errno));
        (void)write_byte(release[1], 1);
        close(release[1]);
        (void)waitpid(child, NULL, 0);
        return 1;
    }

    if (!write_byte(release[1], 1)) {
        fprintf(stderr, "FAIL ptrace test: could not release child\n");
        close(release[1]);
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return 1;
    }
    close(release[1]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "FAIL ptrace test: waitpid: %s\n", strerror(errno));
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL ptrace test: child exited unexpectedly\n");
        return 1;
    }
    return 0;
}
#else
static int test_ptrace_restriction(void) {
    printf("SKIP ptrace restriction test: Linux is required\n");
    return 0;
}
#endif

int main(void) {
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
        fprintf(stderr, "FAIL OpenSSL initialization\n");
        return 1;
    }
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (cipher == NULL) {
        fprintf(stderr, "FAIL OpenSSL AES-256-GCM provider initialization\n");
        return 1;
    }
    printf("PASS OpenSSL %s: AES-256-GCM loaded\n", OPENSSL_VERSION_TEXT);
    EVP_CIPHER_free(cipher);

    uint8_t secret[32];
    memset(secret, 0xA5, sizeof(secret));
    mk1_memory_guard_zero_memory(secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(secret); ++i) {
        if (secret[i] != 0) {
            fprintf(stderr, "FAIL OpenSSL cleanse assertion at byte %zu\n", i);
            return 1;
        }
    }
    puts("PASS OPENSSL_cleanse: secret buffer is zeroed");

    static const char *const sodium_names[] = {
        "libsodium.so.23", "libsodium.so", "libsodium.dylib", NULL,
    };
    static const char *const bpf_names[] = {
        "libbpf.so.1", "libbpf.so", "libbpf.dylib", NULL,
    };
    static const char *const oqs_names[] = {
        "liboqs.so.0", "liboqs.so", "liboqs.dylib", NULL,
    };
    if (check_optional_library(sodium_names, "libsodium", "sodium_init") != 0
        || check_optional_library(bpf_names, "libbpf", "libbpf_version_string") != 0
        || check_optional_library(oqs_names, "liboqs", "OQS_init") != 0) {
        return 1;
    }

    if (test_mlkem_tunnel() != 0) return 1;
    return test_ptrace_restriction();
}
