#include "key.h"
#include "signature.h"

#include <openssl/obj_mac.h>

// generate a new schnorr private key
schnorr_key *schnorr_key_new(const schnorr_context *ctx)
{
    schnorr_key *dest = NULL;
    schnorr_pubkey *pub = NULL;
    int error = 1;


    // malloc a new schnorr private key
    dest = malloc(sizeof(schnorr_key));
    if (dest == NULL)
    {
        goto cleanup;
    }
    dest->a = NULL;

    dest->a = BN_new();
    if (dest->a == NULL)
    {
        goto cleanup;
    }

    // random generate private key a
    if (BN_rand(dest->a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1)
    {
        goto cleanup;
    }

    if (BN_is_zero(dest->a))
    {
        goto cleanup;
    }

    pub = malloc(sizeof(schnorr_pubkey));
    if (pub == NULL)
    {
        goto cleanup;
    }
    pub->A = NULL;

    pub->A = EC_POINT_new(ctx->group);
    if (pub->A == NULL)
    {
        goto cleanup;
    }

    // generate corresponding public key
    // pub=aG
    if (EC_POINT_mul(ctx->group, pub->A, NULL, ctx->G, dest->a, ctx->bn_ctx) == 0)
    {
        goto cleanup;
    }

    dest->pub = pub;

    error = 0;

cleanup:
    if (error)
    {
        if (pub != NULL)
        {
            EC_POINT_free(pub->A);
        }
        free(pub);

        if (dest != NULL)
        {
            BN_free(dest->a);
        }

        free(dest);

        return NULL;
    }

    return dest;
}



// free schnorr key
void schnorr_key_free(schnorr_key *key)
{
    if (key != NULL)
    {
        EC_POINT_free(key->pub->A);
        free(key->pub);
        BN_free(key->a);
        free(key);
    }
}
