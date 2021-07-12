#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/ec.h>

#include "key.h"

    // schnorr signature
    typedef struct
    {
        EC_POINT *R;
        BIGNUM *s;
    } schnorr_sig;

    int schnorr_sign(const schnorr_context *ctx,
                     schnorr_sig **dest,
                     const schnorr_key *key,
                     const unsigned char *msg,
                     const size_t len);

    int schnorr_verify(const schnorr_context *ctx,
                       const schnorr_sig *sig,
                       const schnorr_pubkey *pubkey,
                       const unsigned char *msg,
                       const size_t len);

    void schnorr_sig_free(schnorr_sig *sig);

    int gen_h(const schnorr_context *ctx,
              const unsigned char *msg,
              const size_t len,
              const EC_POINT *R,
              BIGNUM *out);

    int hash(unsigned char *out, const unsigned char *in, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
