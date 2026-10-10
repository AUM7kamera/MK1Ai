#include "mk1_tunnel_oqs.h"

#include <errno.h>
#include <stdlib.h>

#include <oqs/oqs.h>

static int oqs_encapsulate(
    void *context,
    const uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
) {
    OQS_KEM *kem = context;
    if (kem == NULL) return -1;
    return OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS
        ? 0
        : -1;
}

static int oqs_decapsulate(
    void *context,
    const uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE],
    const uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]
) {
    OQS_KEM *kem = context;
    if (kem == NULL) return -1;
    return OQS_KEM_decaps(kem, shared_secret, ciphertext, private_key) == OQS_SUCCESS
        ? 0
        : -1;
}

int mk1_tunnel_oqs_provider_init(mk1_mlkem768_provider *provider) {
    if (provider == NULL) {
        errno = EINVAL;
        return -1;
    }
    provider->context = NULL;
    provider->encapsulate = NULL;
    provider->decapsulate = NULL;
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (kem == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    if (kem->length_public_key != MK1_MLKEM768_PUBLIC_KEY_SIZE
        || kem->length_secret_key != MK1_MLKEM768_PRIVATE_KEY_SIZE
        || kem->length_ciphertext != MK1_MLKEM768_CIPHERTEXT_SIZE
        || kem->length_shared_secret != MK1_MLKEM768_SHARED_SECRET_SIZE) {
        OQS_KEM_free(kem);
        errno = EPROTO;
        return -1;
    }

    provider->context = kem;
    provider->encapsulate = oqs_encapsulate;
    provider->decapsulate = oqs_decapsulate;
    return 0;
}

void mk1_tunnel_oqs_provider_cleanup(mk1_mlkem768_provider *provider) {
    if (provider == NULL) return;
    if (provider->context != NULL) OQS_KEM_free(provider->context);
    provider->context = NULL;
    provider->encapsulate = NULL;
    provider->decapsulate = NULL;
}
