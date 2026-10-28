/* Adapt legacy HUKS Ed25519 calls to the public OpenSSL EVP API. */
#ifndef CARLINK_ED25519_COMPAT_H
#define CARLINK_ED25519_COMPAT_H
#include <stddef.h>
#include <stdint.h>
void ED25519_public_from_private(uint8_t *public_key, const uint8_t *seed);
int ED25519_sign(uint8_t *signature, const uint8_t *message, size_t length,
                 const uint8_t *public_key, const uint8_t *private_key);
int ED25519_verify(const uint8_t *message, size_t length,
                   const uint8_t *signature, const uint8_t *public_key);
#endif
