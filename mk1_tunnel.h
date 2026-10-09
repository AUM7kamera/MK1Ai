#ifndef MK1_TUNNEL_H
#define MK1_TUNNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MK1_TUNNEL_KEY_SIZE 32
#define MK1_TUNNEL_NONCE_SIZE 12
#define MK1_TUNNEL_TAG_SIZE 16
#define MK1_MLKEM768_PUBLIC_KEY_SIZE 1184
#define MK1_MLKEM768_PRIVATE_KEY_SIZE 2400
#define MK1_MLKEM768_CIPHERTEXT_SIZE 1088
#define MK1_MLKEM768_SHARED_SECRET_SIZE 32

typedef int (*mk1_mlkem768_encapsulate_fn)(
    void *context,
    const uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
);

typedef int (*mk1_mlkem768_decapsulate_fn)(
    void *context,
    const uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE],
    const uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
);

/* ML-KEM-768 establishes a shared secret but does not authenticate its peer;
 * callers must obtain and verify public keys through a trusted channel. */
typedef struct {
    void *context;
    mk1_mlkem768_encapsulate_fn encapsulate;
    mk1_mlkem768_decapsulate_fn decapsulate;
} mk1_mlkem768_provider;

bool mk1_tunnel_is_enabled(void);
int mk1_tunnel_set_enabled(bool enabled);
int mk1_secure_key_wipe(void);

int mk1_tunnel_mlkem768_encapsulate(
    const mk1_mlkem768_provider *provider,
    const uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE]
);
int mk1_tunnel_mlkem768_decapsulate(
    const mk1_mlkem768_provider *provider,
    const uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE],
    const uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE]
);

int mk1_tunnel_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_length,
    const uint8_t *aad,
    size_t aad_length,
    uint8_t nonce[MK1_TUNNEL_NONCE_SIZE],
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length,
    uint8_t tag[MK1_TUNNEL_TAG_SIZE]
);
int mk1_tunnel_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t nonce[MK1_TUNNEL_NONCE_SIZE],
    const uint8_t tag[MK1_TUNNEL_TAG_SIZE],
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length
);

#endif
