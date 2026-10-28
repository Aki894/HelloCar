#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include "ec_local.h"
#include "hichain.h"

void ED25519_public_from_private(uint8_t *public_key, const uint8_t *seed)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    size_t size = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key, public_key, &size) == 1 && size == 32;
    EVP_PKEY_free(key);
    if (!ok) abort(); /* The legacy void API has no error return. */
}

int ED25519_sign(uint8_t *signature, const uint8_t *message, size_t length,
                 const uint8_t *public_key, const uint8_t *private_key)
{
    uint8_t derived[32];
    ED25519_public_from_private(derived, private_key);
    if (memcmp(derived, public_key, 32)) return 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t size = 64;
    int ok = key && context && EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1
             && EVP_DigestSign(context, signature, &size, message, length) == 1 && size == 64;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return ok;
}

int ED25519_verify(const uint8_t *message, size_t length,
                   const uint8_t *signature, const uint8_t *public_key)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int ok = key && context && EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1
             && EVP_DigestVerify(context, signature, 64, message, length) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return ok;
}

size_t carlink_abi_size(const char *name)
{
#define ABI_SIZE(type) if (!strcmp(name, #type)) return sizeof(struct type)
    ABI_SIZE(session_identity);
    ABI_SIZE(hc_call_back);
    ABI_SIZE(operation_parameter);
    ABI_SIZE(hc_pin);
    ABI_SIZE(hc_session_key);
    ABI_SIZE(uint8_buff);
    return 0;
}
