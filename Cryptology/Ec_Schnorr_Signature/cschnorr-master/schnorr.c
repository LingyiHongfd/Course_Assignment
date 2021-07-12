#include "src/signature.h"
#include "src/multisig.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/opensslconf.h>
#include <openssl/asn1.h>
#include <openssl/symhacks.h>
#include <openssl/ecerr.h>

// I adopt secpk1 as ec schnorr curve, the parameter of ec curve is listed as following:
// p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
// a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
// b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
// G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141

static __inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc"
                         : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

// code for single ec schnorr process
// include private key generation, sign and verify three part
// ec curve is secpk1
int run()
{
    // init ec curve
    schnorr_context *ctx = schnorr_context_new();
    if (ctx == NULL)
    {
        return -1;
    }

    printf("Single EC Schnorr Sign.\n");
    printf("Initialize EC Schnorr Curve.\n");
    printf("Using secpk1 curve.\n");
    printf("EC Curve Order:\n");
    BN_print_fp(stdout, ctx->order);
    printf("\n");

    // generate private key
    schnorr_key *key = schnorr_key_new(ctx);
    if (key == NULL)
    {
        return -1;
    }

    printf("Generate Private Key.\n");
    printf("Public Key:\n");
    BN_print_fp(stdout, key->a);
    printf("\n");

    // sign message
    schnorr_sig *sig;
    if (schnorr_sign(ctx, &sig, key, "hello", strlen("hello")) == 0)
    {
        return -1;
    }

    printf("Sign Message.\n");
    printf("Message: %s\n", "hello");
    printf("Signature: \n");
    BN_print_fp(stdout, sig->s);
    printf("\n");

    // verify signature
    if (schnorr_verify(ctx, sig, key->pub, "hello", strlen("hello")) != 1)
    {
        return -1;
    }

    schnorr_sig_free(sig);
    schnorr_key_free(key);
    schnorr_context_free(ctx);

    return 0;
}

// multiple sign and batch verify
int multi_run()
{
    // init ec curve
    schnorr_context *ctx = schnorr_context_new();

    printf("Multi EC Schnorr Sign.\n");
    printf("Initialize EC Schnorr Curve.\n");
    printf("Using secpk1 curve.\n");
    printf("EC Curve Order:\n");
    BN_print_fp(stdout, ctx->order);
    printf("\n");

    // generate private key1
    musig_key *key1 = musig_key_new(ctx);

    printf("Generate Private Key 1.\n");
    printf("Public Key1:\n");
    BN_print_fp(stdout, key1->a);
    printf("\n");

    // generate private key2
    musig_key *key2 = musig_key_new(ctx);
    printf("Generate Private Key 2.\n");
    printf("Public Key2:\n");
    BN_print_fp(stdout, key2->a);
    printf("\n");

    musig_key *keys[2];
    keys[0] = key1;
    keys[1] = key2;

    musig_pubkey *pubkeys[2];
    pubkeys[0] = key1->pub;
    pubkeys[1] = key2->pub;

    musig_sig *sig1;
    musig_sig *sig2;
    musig_pubkey *pub;
    // sign message with private key1
    if (musig_sign(ctx, &sig1, &pub, keys[0], pubkeys, 2, "hello", strlen("hello")) == 0)
    {
        return -1;
    }

    printf("Sign Message.\n");
    printf("Message: %s\n", "hello");
    printf("Signature1:\n");
    BN_print_fp(stdout, sig1->s);
    printf("\n");

    // sign message with private key2
    if (musig_sign(ctx, &sig2, &pub, keys[1], pubkeys, 2, "hello", strlen("hello")) == 0)
    {
        return -1;
    }
    printf("Signature2:\n");
    BN_print_fp(stdout, sig2->s);
    printf("\n");

    musig_sig *sigs[2];
    sigs[0] = sig1;
    sigs[1] = sig2;

    // verify signature
    musig_sig *sigAgg;
    if (musig_aggregate(ctx, &sigAgg, sigs, 2) == 0)
    {
        return -1;
    }

    if (musig_verify(ctx, sigAgg, pub, "hello", strlen("hello")) != 1)
    {
        return -1;
    }

    musig_sig_free(sig1);
    musig_sig_free(sig2);
    musig_sig_free(sigAgg);
    musig_key_free(key1);
    musig_key_free(key2);
    schnorr_context_free(ctx);

    return 0;
}

// generate random string as message
char *random_string_generate()
{
    int random_len = rand() % 10;
    char *rstring = (char *)malloc(random_len * sizeof(char));
    int flag;
    for (int i = 0; i < random_len - 1; i++)
    {
        flag = rand() % 3;
        switch (flag)
        {
        case 0:
            rstring[i] = 'A' + rand() % 26;
            break;
        case 1:
            rstring[i] = 'a' + rand() % 26;
            break;
        case 2:
            rstring[i] = '0' + rand() % 10;
            break;
        default:
            rstring[i] = 'x';
            break;
        }
    }
    return rstring;
}

int main(int argc, char *argv[])
{
    // flag for different mode: 0 1 2
    // 0: single sign and verify
    // 1: measure the average tick and time for 10000 iters
    // 2: multiple sign and batch verify
    int mode_flag = atoi(argv[1]);

    // code for single process
    if (mode_flag == 0)
    {
        int result;
        result = run();
        if (result == 0)
        {
            printf("Single Success\n");
        }
        else
        {
            printf("Single Fail\n");
        }
    }

    // code for average tick and time measure
    if (mode_flag == 1)
    {
        // init shnorr context and generate a new pirvate key
        schnorr_context *ctx = schnorr_context_new();

        schnorr_key *key = schnorr_key_new(ctx);

        unsigned long long int begin, end, total = 0;

        clock_t start, endt, totalt = 0;

        schnorr_sig *sig;

        // loop for measure the effiency
        int total_iter = 10000;
        for (int i = 0; i < total_iter; i++)
        {
            char *input_string;
            input_string = random_string_generate();
            int str_len = strlen(input_string);
            start = clock();
            begin = rdtsc();
            schnorr_sign(ctx, &sig, key, input_string, str_len);
            schnorr_verify(ctx, sig, key->pub, input_string, str_len);
            end = rdtsc();
            endt = clock();
            total = total + end - begin;
            totalt = totalt + endt - start;
        }
        total = total / total_iter;
        printf("tick %lld\n", total);
        printf("time %f\n", (double)((double)totalt / CLOCKS_PER_SEC / total_iter));

        schnorr_sig_free(sig);
        schnorr_key_free(key);
        schnorr_context_free(ctx);
    }

    // code for multiple sign and batch verify
    if (mode_flag == 2)
    {
        int result;
        result = multi_run();
        if (result == 0)
        {
            printf("Multi Success\n");
        }
        else
        {
            printf("Multi Fail\n");
        }
    }

    return 0;
}
