#include "../mk1_tunnel.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static int test_encapsulate(
    void *context,
    const uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
) {
    (void)context;
    (void)public_key;
    memset(ciphertext, 0xA5, MK1_MLKEM768_CIPHERTEXT_SIZE);
    memset(shared_secret, 0x5A, MK1_MLKEM768_SHARED_SECRET_SIZE);
    return 0;
}

static int test_decapsulate(
    void *context,
    const uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE],
    const uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
) {
    (void)context;
    (void)private_key;
    (void)ciphertext;
    memset(shared_secret, 0x5A, MK1_MLKEM768_SHARED_SECRET_SIZE);
    return 0;
}

int main(void) {
    static const uint8_t plaintext[] = "private test payload";
    static const uint8_t aad[] = "POST /test";
    uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE] = {0};
    uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE] = {0};
    uint8_t kem_ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE] = {0};
    uint8_t ciphertext[sizeof(plaintext)] = {0};
    uint8_t decrypted[sizeof(plaintext)] = {0};
    uint8_t nonce[MK1_TUNNEL_NONCE_SIZE] = {0};
    uint8_t tag[MK1_TUNNEL_TAG_SIZE] = {0};
    size_t ciphertext_length = 0;
    size_t plaintext_length = 0;
    mk1_mlkem768_provider provider = {
        .encapsulate = test_encapsulate,
        .decapsulate = test_decapsulate,
    };

    assert(mk1_tunnel_mlkem768_encapsulate(
        &provider, public_key, kem_ciphertext
    ) == -1);
    assert(errno == EACCES);

    assert(mk1_tunnel_set_enabled(true) == 0);
    assert(mk1_tunnel_mlkem768_encapsulate(
        &provider, public_key, kem_ciphertext
    ) == 0);
    assert(mk1_tunnel_encrypt(
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, ciphertext, sizeof(ciphertext), &ciphertext_length, tag
    ) == 0);
    assert(ciphertext_length == sizeof(plaintext));

    assert(mk1_tunnel_set_enabled(false) == 0);
    assert(!mk1_tunnel_is_enabled());
    assert(mk1_tunnel_mlkem768_decapsulate(
        &provider, private_key, kem_ciphertext
    ) == -1);
    assert(errno == EACCES);

    assert(mk1_tunnel_set_enabled(true) == 0);
    assert(mk1_tunnel_mlkem768_decapsulate(
        &provider, private_key, kem_ciphertext
    ) == 0);
    assert(mk1_tunnel_decrypt(
        ciphertext, ciphertext_length, aad, sizeof(aad),
        nonce, tag, decrypted, sizeof(decrypted), &plaintext_length
    ) == 0);
    assert(plaintext_length == sizeof(plaintext));
    assert(memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);

    tag[0] ^= 1;
    memset(decrypted, 0xFF, sizeof(decrypted));
    assert(mk1_tunnel_decrypt(
        ciphertext, ciphertext_length, aad, sizeof(aad),
        nonce, tag, decrypted, sizeof(decrypted), &plaintext_length
    ) == -1);
    assert(errno == EBADMSG);
    assert(plaintext_length == 0);
    for (size_t i = 0; i < sizeof(decrypted); ++i) assert(decrypted[i] == 0);

    assert(mk1_secure_key_wipe() == 0);
    assert(!mk1_tunnel_is_enabled());
    assert(mk1_tunnel_encrypt(
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, ciphertext, sizeof(ciphertext), &ciphertext_length, tag
    ) == -1);
    assert(errno == EACCES);
    return 0;
}
