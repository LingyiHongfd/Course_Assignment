#include "signature.h"

#include <string.h>

#include <openssl/obj_mac.h>
#include <openssl/sha.h>

// hash function using sha256
int hash(unsigned char *out, const unsigned char *in, const size_t len)
{
    SHA256_CTX sha256CTX;

    if (!SHA256_Init(&sha256CTX))
    {
        return 0;
    }

    if (!SHA256_Update(&sha256CTX, in, len))
    {
        return 0;
    }

    if (!SHA256_Final(out, &sha256CTX))
    {
        return 0;
    }

    return SHA256_DIGEST_LENGTH;
}

// schnorr signature
int schnorr_sign(const schnorr_context *ctx,
                 schnorr_sig **dest,
                 const schnorr_key *key,
                 const unsigned char *msg,
                 const size_t len)
{
    BIGNUM *k = NULL;
    EC_POINT *R = NULL;
    BIGNUM *BNh = NULL;
    BIGNUM *s = NULL;
    int error = 1;

    *dest = malloc(sizeof(schnorr_sig));
    if (*dest == NULL)
    {
        goto cleanup;
    }
    (*dest)->s = NULL;

    k = BN_new();
    if (k == NULL)
    {
        goto cleanup;
    }

    // generate random k
    if (BN_rand(k, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1)
    {
        goto cleanup;
    }

    (*dest)->R = EC_POINT_new(ctx->group);
    if ((*dest)->R == NULL)
    {
        goto cleanup;
    }

    // calculate R=K*G
    if (EC_POINT_mul(ctx->group, (*dest)->R, NULL, ctx->G, k, ctx->bn_ctx) == 0)
    {
        goto cleanup;
    }

    BNh = BN_new();
    if (BNh == NULL)
    {
        goto cleanup;
    }

    // hash
    // generate H(m || R || P)
    if (gen_h(ctx, msg, len, (*dest)->R, BNh) == 0)
    {
        goto cleanup;
    }

    s = BN_new();
    if (s == NULL)
    {
        goto cleanup;
    }

    // calculate H(m || R || P)*x
    if (BN_mod_mul(s, BNh, key->a, ctx->order, ctx->bn_ctx) == 0)
    {
        goto cleanup;
    }

    // generate the final signature
    // s = k + H(m || R || P)*x
    if (BN_mod_sub(s, k, s, ctx->order, ctx->bn_ctx) == 0)
    {
        goto cleanup;
    }

    (*dest)->s = s;

    error = 0;

cleanup:
    BN_free(BNh);
    BN_free(k);
    if (error)
    {
        if (*dest != NULL)
        {
            BN_free((*dest)->s);
        }

        free(*dest);

        return 0;
    }

    return 1;
}

// free schnorr signature
void schnorr_sig_free(schnorr_sig *sig)
{
    if (sig != NULL)
    {
        BN_free(sig->s);
        free(sig);
    }
}

// verify schnorr signature
int schnorr_verify(const schnorr_context *ctx,
                   const schnorr_sig *sig,
                   const schnorr_pubkey *pubkey,
                   const unsigned char *msg,
                   const size_t len)
{
    BIGNUM *BNh = NULL;
    EC_POINT *R = NULL;
    int retval = 0;

    if (BN_cmp(sig->s, ctx->order) != -1)
    {
        retval = -1;
        goto cleanup;
    }

    BNh = BN_new();
    if (BNh == NULL)
    {
        goto cleanup;
    }

    const int genRes = gen_h(ctx, msg, len, sig->R, BNh);
    if (genRes != 1)
    {
        retval = genRes;
        goto cleanup;
    }

    R = EC_POINT_new(ctx->group);
    if (R == NULL)
    {
        goto cleanup;
    }

    
    if (EC_POINT_mul(ctx->group, R, sig->s, pubkey->A, BNh, ctx->bn_ctx) == 0)
    {
        goto cleanup;
    }

    // compare sG = R + H(m || R || P)P ?
    // if equal, verify success, else fail
    if (EC_POINT_is_at_infinity(ctx->group, R) == 1)
    {
        retval = -1;
        goto cleanup;
    }
    const int ret = EC_POINT_cmp(ctx->group, R, sig->R, ctx->bn_ctx);

    retval = 1;

cleanup:
    EC_POINT_free(R);
    BN_free(BNh);

    if (retval != 1)
    {
        return retval;
    }

    if (ret == 0)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

int gen_h(const schnorr_context *ctx,
          const unsigned char *msg,
          const size_t len,
          const EC_POINT *R,
          BIGNUM *out)
{
    unsigned char msgHash[32];
    if (hash((unsigned char *)&msgHash, msg, len) == 0)
    {
        return 0;
    }

    unsigned char payload[65];
    if (EC_POINT_point2oct(ctx->group, R, POINT_CONVERSION_COMPRESSED, payload, 33, ctx->bn_ctx) < 33)
    {
        return 0;
    }
    memcpy(((unsigned char *)&payload) + 33, msgHash, 32);

    unsigned char h[32];
    if (hash((unsigned char *)&h, payload, 65) == 0)
    {
        return 0;
    }

    if (BN_bin2bn((unsigned char *)&h, 32, out) == NULL)
    {
        return 0;
    }

    if (BN_is_zero(out) == 1)
    {
        return -1;
    }

    if (BN_cmp(out, ctx->order) != -1)
    {
        return -1;
    }

    return 1;
}
