#define _POSIX_C_SOURCE 200809L

#include "mk1_tunnel.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

static pthread_mutex_t tunnel_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t session_key[MK1_TUNNEL_KEY_SIZE];
static bool tunnel_enabled;
static bool session_key_ready;
static uint64_t tunnel_generation;

static void wipe_bytes(void *buffer, size_t length) {
    if (buffer != NULL) OPENSSL_cleanse(buffer, length);
}

static void wipe_key_locked(void) {
    wipe_bytes(session_key, sizeof(session_key));
    session_key_ready = false;
}

static int lock_tunnel(void) {
    int result = pthread_mutex_lock(&tunnel_lock);
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}

static int unlock_tunnel(void) {
    int result = pthread_mutex_unlock(&tunnel_lock);
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}

bool mk1_tunnel_is_enabled(void) {
    if (lock_tunnel() != 0) return false;
    bool enabled = tunnel_enabled;
    if (unlock_tunnel() != 0) return false;
    return enabled;
}

int mk1_tunnel_set_enabled(bool enabled) {
    if (lock_tunnel() != 0) return -1;
    ++tunnel_generation;
    tunnel_enabled = enabled;
    if (!enabled) wipe_key_locked();
    return unlock_tunnel();
}

int mk1_secure_key_wipe(void) {
    if (lock_tunnel() != 0) return -1;
    ++tunnel_generation;
    tunnel_enabled = false;
    wipe_key_locked();
    return unlock_tunnel();
}

static int derive_session_key(const uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE],
                              uint8_t key[MK1_TUNNEL_KEY_SIZE]) {
    static const uint8_t salt[] = "MK1-ML-KEM-768-AES-256-GCM-v1";
    static const uint8_t info[] = "MK1 encrypted tunnel session key";
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t key_length = MK1_TUNNEL_KEY_SIZE;
    int result = -1;

    if (context == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (EVP_PKEY_derive_init(context) > 0
        && EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0
        && EVP_PKEY_CTX_set1_hkdf_salt(context, salt, sizeof(salt) - 1) > 0
        && EVP_PKEY_CTX_set1_hkdf_key(
            context, shared_secret, MK1_MLKEM768_SHARED_SECRET_SIZE
        ) > 0
        && EVP_PKEY_CTX_add1_hkdf_info(context, info, sizeof(info) - 1) > 0
        && EVP_PKEY_derive(context, key, &key_length) > 0
        && key_length == MK1_TUNNEL_KEY_SIZE) {
        result = 0;
    } else {
        errno = EIO;
        wipe_bytes(key, MK1_TUNNEL_KEY_SIZE);
    }
    EVP_PKEY_CTX_free(context);
    return result;
}

typedef int (*key_exchange_fn)(void *context, uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]);

typedef struct {
    const mk1_mlkem768_provider *provider;
    const uint8_t *input_key;
    const uint8_t *ciphertext;
    uint8_t *ciphertext_output;
    bool encapsulate;
} key_exchange_args;

static int exchange_key(void *opaque, uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE]) {
    key_exchange_args *args = opaque;
    if (args->encapsulate) {
        return args->provider->encapsulate(
            args->provider->context,
            args->input_key,
            args->ciphertext_output,
            shared_secret
        );
    }
    return args->provider->decapsulate(
        args->provider->context,
        args->input_key,
        args->ciphertext,
        shared_secret
    );
}

static int establish_session_key(key_exchange_fn exchange, void *context) {
    uint8_t shared_secret[MK1_MLKEM768_SHARED_SECRET_SIZE] = {0};
    uint8_t derived_key[MK1_TUNNEL_KEY_SIZE] = {0};
    uint64_t generation;
    int result = -1;

    if (lock_tunnel() != 0) return -1;
    if (!tunnel_enabled) {
        if (unlock_tunnel() != 0) return -1;
        errno = EACCES;
        return -1;
    }
    generation = ++tunnel_generation;
    unlock_tunnel();

    if (exchange(context, shared_secret) != 0
        || derive_session_key(shared_secret, derived_key) != 0) {
        if (lock_tunnel() == 0) {
            if (tunnel_generation == generation) {
                ++tunnel_generation;
                tunnel_enabled = false;
                wipe_key_locked();
            }
            (void)unlock_tunnel();
        }
        errno = EIO;
        goto cleanup;
    }

    if (lock_tunnel() != 0) goto cleanup;
    if (!tunnel_enabled || tunnel_generation != generation) {
        errno = ECANCELED;
    } else {
        wipe_key_locked();
        memcpy(session_key, derived_key, sizeof(session_key));
        session_key_ready = true;
        result = 0;
    }
    if (unlock_tunnel() != 0) result = -1;

cleanup:
    wipe_bytes(shared_secret, sizeof(shared_secret));
    wipe_bytes(derived_key, sizeof(derived_key));
    return result;
}

int mk1_tunnel_mlkem768_encapsulate(
    const mk1_mlkem768_provider *provider,
    const uint8_t public_key[MK1_MLKEM768_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE]
) {
    if (provider == NULL || provider->encapsulate == NULL
        || public_key == NULL || ciphertext == NULL) {
        errno = EINVAL;
        return -1;
    }
    key_exchange_args args = {
        .provider = provider,
        .input_key = public_key,
        .ciphertext_output = ciphertext,
        .encapsulate = true,
    };
    if (establish_session_key(exchange_key, &args) != 0) {
        wipe_bytes(ciphertext, MK1_MLKEM768_CIPHERTEXT_SIZE);
        return -1;
    }
    return 0;
}

int mk1_tunnel_mlkem768_decapsulate(
    const mk1_mlkem768_provider *provider,
    const uint8_t private_key[MK1_MLKEM768_PRIVATE_KEY_SIZE],
    const uint8_t ciphertext[MK1_MLKEM768_CIPHERTEXT_SIZE]
) {
    if (provider == NULL || provider->decapsulate == NULL
        || private_key == NULL || ciphertext == NULL) {
        errno = EINVAL;
        return -1;
    }
    key_exchange_args args = {
        .provider = provider,
        .input_key = private_key,
        .ciphertext = ciphertext,
    };
    return establish_session_key(exchange_key, &args);
}

static bool buffers_valid(const void *input, size_t input_length,
                          const void *aad, size_t aad_length,
                          void *output, size_t output_capacity,
                          size_t *output_length) {
    return (input != NULL || input_length == 0)
        && (aad != NULL || aad_length == 0)
        && (output != NULL || output_capacity == 0)
        && output_length != NULL
        && input_length <= INT_MAX
        && aad_length <= INT_MAX
        && output_capacity <= INT_MAX;
}

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
) {
    EVP_CIPHER_CTX *context = NULL;
    int output_length = 0;
    int final_length = 0;
    int result = -1;

    if (!buffers_valid(plaintext, plaintext_length, aad, aad_length,
                       ciphertext, ciphertext_capacity, ciphertext_length)
        || ciphertext == NULL || nonce == NULL || tag == NULL
        || ciphertext_capacity < plaintext_length) {
        errno = EINVAL;
        return -1;
    }
    *ciphertext_length = 0;
    if (lock_tunnel() != 0) {
        wipe_bytes(ciphertext, ciphertext_capacity);
        wipe_bytes(nonce, MK1_TUNNEL_NONCE_SIZE);
        wipe_bytes(tag, MK1_TUNNEL_TAG_SIZE);
        return -1;
    }
    if (!tunnel_enabled || !session_key_ready) {
        errno = EACCES;
        goto cleanup;
    }
    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }
    if (RAND_bytes(nonce, MK1_TUNNEL_NONCE_SIZE) != 1
        || EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, MK1_TUNNEL_NONCE_SIZE, NULL) != 1
        || EVP_EncryptInit_ex(context, NULL, NULL, session_key, nonce) != 1
        || (aad_length > 0 && EVP_EncryptUpdate(context, NULL, &output_length, aad, (int)aad_length) != 1)
        || (plaintext_length > 0
            && EVP_EncryptUpdate(context, ciphertext, &output_length, plaintext, (int)plaintext_length) != 1)
        || output_length < 0
        || (size_t)output_length > ciphertext_capacity
        || EVP_EncryptFinal_ex(context, ciphertext + output_length, &final_length) != 1
        || final_length < 0
        || (size_t)final_length > ciphertext_capacity - (size_t)output_length
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, MK1_TUNNEL_TAG_SIZE, tag) != 1) {
        errno = EIO;
        goto cleanup;
    }
    *ciphertext_length = (size_t)(output_length + final_length);
    result = 0;

cleanup:
    if (result != 0) {
        wipe_bytes(ciphertext, ciphertext_capacity);
        wipe_bytes(nonce, MK1_TUNNEL_NONCE_SIZE);
        wipe_bytes(tag, MK1_TUNNEL_TAG_SIZE);
    }
    EVP_CIPHER_CTX_free(context);
    if (unlock_tunnel() != 0) {
        wipe_bytes(ciphertext, ciphertext_capacity);
        wipe_bytes(nonce, MK1_TUNNEL_NONCE_SIZE);
        wipe_bytes(tag, MK1_TUNNEL_TAG_SIZE);
        *ciphertext_length = 0;
        result = -1;
    }
    return result;
}

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
) {
    EVP_CIPHER_CTX *context = NULL;
    int output_length = 0;
    int final_length = 0;
    int result = -1;

    if (!buffers_valid(ciphertext, ciphertext_length, aad, aad_length,
                       plaintext, plaintext_capacity, plaintext_length)
        || plaintext == NULL || nonce == NULL || tag == NULL
        || plaintext_capacity < ciphertext_length) {
        errno = EINVAL;
        return -1;
    }
    *plaintext_length = 0;
    if (lock_tunnel() != 0) {
        wipe_bytes(plaintext, plaintext_capacity);
        return -1;
    }
    if (!tunnel_enabled || !session_key_ready) {
        errno = EACCES;
        goto cleanup;
    }
    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, MK1_TUNNEL_NONCE_SIZE, NULL) != 1
        || EVP_DecryptInit_ex(context, NULL, NULL, session_key, nonce) != 1
        || (aad_length > 0 && EVP_DecryptUpdate(context, NULL, &output_length, aad, (int)aad_length) != 1)
        || (ciphertext_length > 0
            && EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext, (int)ciphertext_length) != 1)
        || output_length < 0
        || (size_t)output_length > plaintext_capacity
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, MK1_TUNNEL_TAG_SIZE, (void *)tag) != 1
        || EVP_DecryptFinal_ex(context, plaintext + output_length, &final_length) != 1
        || final_length < 0
        || (size_t)final_length > plaintext_capacity - (size_t)output_length) {
        errno = EBADMSG;
        goto cleanup;
    }
    *plaintext_length = (size_t)(output_length + final_length);
    result = 0;

cleanup:
    if (result != 0) wipe_bytes(plaintext, plaintext_capacity);
    EVP_CIPHER_CTX_free(context);
    if (unlock_tunnel() != 0) {
        wipe_bytes(plaintext, plaintext_capacity);
        *plaintext_length = 0;
        result = -1;
    }
    return result;
}
