#ifndef KEY_H_INCLUDED
#define KEY_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include "context.h"

#include <openssl/ec.h>

    // schnorr public key
    typedef struct
    {
        EC_POINT *A;
    } schnorr_pubkey;

    // schnorr private key
    typedef struct
    {
        schnorr_pubkey *pub;
        BIGNUM *a;
    } schnorr_key;

    schnorr_key *schnorr_key_new(const schnorr_context *ctx);
    void schnorr_key_free(schnorr_key *key);

#ifdef __cplusplus
}
#endif

#endif
