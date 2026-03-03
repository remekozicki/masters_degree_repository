#include "../throughput_and_latency/perf_shared.h"

#if defined(ASCON_AEAD_RATE)
#include "ascon.h"
#include "permutations.h"
#define MICRO_PRIMITIVE_LABEL "ascon-p12"
enum { MICRO_PRIMITIVE_ROUNDS = 12 };

typedef state_t micro_primitive_state_t;

static void micro_primitive_init(micro_primitive_state_t *state)
{
    rand_bytes((unsigned char*)state, sizeof *state);
}

static void micro_primitive_apply(micro_primitive_state_t *state)
{
    P12(state);
}

static unsigned long long micro_primitive_fold(const micro_primitive_state_t *state)
{
    const uint64_t folded = state->x0 ^ state->x1 ^ state->x2 ^ state->x3 ^ state->x4;
    return (unsigned long long)folded;
}

#elif (CRYPTO_NPUBBYTES == 12)
#include "elephant_200.h"
#define MICRO_PRIMITIVE_LABEL "keccak-p200-18"
enum { MICRO_PRIMITIVE_ROUNDS = 18 };

typedef struct {
    BYTE bytes[BLOCK_SIZE];
} micro_primitive_state_t;

static void micro_primitive_init(micro_primitive_state_t *state)
{
    rand_bytes(state->bytes, sizeof state->bytes);
}

static void micro_primitive_apply(micro_primitive_state_t *state)
{
    permutation(state->bytes);
}

static unsigned long long micro_primitive_fold(const micro_primitive_state_t *state)
{
    unsigned long long folded = 0ULL;
    for (size_t i = 0; i < 8u; i++) {
        folded = (folded << 8) ^ (unsigned long long)state->bytes[i];
    }
    return folded;
}

#else
#include "gift128.h"
#define MICRO_PRIMITIVE_LABEL "gift-128-40"
enum { MICRO_PRIMITIVE_ROUNDS = 40 };

typedef struct {
    uint8_t plaintext[16];
    uint8_t key[16];
    uint8_t ciphertext[16];
} micro_primitive_state_t;

static void micro_primitive_init(micro_primitive_state_t *state)
{
    rand_bytes(state->plaintext, sizeof state->plaintext);
    rand_bytes(state->key, sizeof state->key);
    memset(state->ciphertext, 0, sizeof state->ciphertext);
}

static void micro_primitive_apply(micro_primitive_state_t *state)
{
    giftb128(state->plaintext, state->key, state->ciphertext);
    memcpy(state->plaintext, state->ciphertext, sizeof state->plaintext);
    state->key[0] ^= state->ciphertext[7];
    state->key[5] ^= state->ciphertext[13];
}

static unsigned long long micro_primitive_fold(const micro_primitive_state_t *state)
{
    unsigned long long folded = 0ULL;
    for (size_t i = 0; i < sizeof state->ciphertext; i++) {
        folded ^= (unsigned long long)state->ciphertext[i] << ((i % 8u) * 8u);
    }
    return folded;
}
#endif

enum {
    MICRO_SAMPLES = 5,
    MICRO_WARMUP_OPS = 512,
    MICRO_PRIMITIVE_WARMUP_OPS = 2048,
    MICRO_AAD_LEN = 1024,
    MICRO_MSG_LEN = 1024
};

static const unsigned long long MICRO_TARGET_WORK_BYTES = 8ULL * 1024ULL * 1024ULL;
static const size_t MICRO_PRIMITIVE_ITERS = 300000u;

static volatile unsigned long long micro_sink = 0ULL;

static size_t micro_iters_for_case(size_t mlen, size_t adlen)
{
    const unsigned long long work =
        (unsigned long long)mlen + (unsigned long long)adlen + (unsigned long long)CRYPTO_ABYTES;

    if (work == 0ULL) {
        return 100000u;
    }

    unsigned long long iters = MICRO_TARGET_WORK_BYTES / work;
    if (iters < 256ULL) {
        iters = 256ULL;
    }
    if (iters > 200000ULL) {
        iters = 200000ULL;
    }
    return (size_t)iters;
}

static int micro_measure_primitive(double *ns_per_call, double *ns_per_round)
{
    double samples[MICRO_SAMPLES];
    memset(samples, 0, sizeof samples);

    for (size_t sample = 0; sample < MICRO_SAMPLES; sample++) {
        micro_primitive_state_t state;
        micro_primitive_init(&state);

        for (size_t i = 0; i < MICRO_PRIMITIVE_WARMUP_OPS; i++) {
            micro_primitive_apply(&state);
        }

        const double t0 = perf_timer_seconds();
        for (size_t i = 0; i < MICRO_PRIMITIVE_ITERS; i++) {
            micro_primitive_apply(&state);
        }
        const double t1 = perf_timer_seconds();

        samples[sample] = ((t1 - t0) * 1e9) / (double)MICRO_PRIMITIVE_ITERS;
        micro_sink ^= micro_primitive_fold(&state);
    }

    *ns_per_call = perf_average(samples, MICRO_SAMPLES);
    *ns_per_round = *ns_per_call / (double)MICRO_PRIMITIVE_ROUNDS;
    return 1;
}

static int micro_measure_encrypt_case(size_t mlen, size_t adlen, size_t iters, double *ns_per_op)
{
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub_base[CRYPTO_NPUBBYTES];
    rand_bytes(key, sizeof key);
    rand_bytes(npub_base, sizeof npub_base);

    unsigned char *msg = (unsigned char*)xmalloc(mlen ? mlen : 1u);
    unsigned char *ad = (unsigned char*)xmalloc(adlen ? adlen : 1u);
    unsigned char *ct = (unsigned char*)xmalloc(mlen + CRYPTO_ABYTES);

    rand_bytes(msg, mlen);
    rand_bytes(ad, adlen);

    unsigned char *dec = (unsigned char*)xmalloc(mlen ? mlen : 1u);
    if (!perf_one_shot_encrypt_decrypt_ok(msg, mlen, ad, adlen, key, npub_base, ct, dec)) {
        free(msg);
        free(ad);
        free(ct);
        free(dec);
        return 0;
    }
    free(dec);

    const unsigned long long expected_clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    double samples[MICRO_SAMPLES];
    memset(samples, 0, sizeof samples);

    for (size_t sample = 0; sample < MICRO_SAMPLES; sample++) {
        unsigned char npub[CRYPTO_NPUBBYTES];
        memcpy(npub, npub_base, sizeof npub);
        for (size_t k = 0; k < sample; k++) {
            perf_bump_nonce(npub, sizeof npub);
        }

        if (!perf_warmup_encrypt(msg, mlen, ad, adlen, key, npub, ct, MICRO_WARMUP_OPS)) {
            free(msg);
            free(ad);
            free(ct);
            return 0;
        }

        const double t0 = perf_timer_seconds();
        for (size_t i = 0; i < iters; i++) {
            unsigned long long clen = expected_clen;
            int ret = crypto_aead_encrypt(ct, &clen,
                                          msg, (unsigned long long)mlen,
                                          ad, (unsigned long long)adlen,
                                          NULL, npub, key);
            if (ret != 0 || clen != expected_clen) {
                free(msg);
                free(ad);
                free(ct);
                return 0;
            }
            perf_bump_nonce(npub, sizeof npub);
        }
        const double t1 = perf_timer_seconds();

        samples[sample] = ((t1 - t0) * 1e9) / (double)iters;
        micro_sink ^= (unsigned long long)ct[(size_t)(expected_clen - 1ULL)];
    }

    *ns_per_op = perf_average(samples, MICRO_SAMPLES);
    free(msg);
    free(ad);
    free(ct);
    return 1;
}

static int micro_measure_tag_only_verify(size_t iters, double *ns_per_op)
{
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char msg_dummy[1] = {0};
    unsigned char ad_dummy[1] = {0};
    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);

    unsigned char ct[CRYPTO_ABYTES];
    unsigned long long clen = CRYPTO_ABYTES;
    int enc_ret = crypto_aead_encrypt(ct, &clen,
                                      msg_dummy, 0ULL,
                                      ad_dummy, 0ULL,
                                      NULL, npub, key);
    if (enc_ret != 0 || clen != (unsigned long long)CRYPTO_ABYTES) {
        return 0;
    }

    unsigned char dec_dummy[1] = {0};
    double samples[MICRO_SAMPLES];
    memset(samples, 0, sizeof samples);

    for (size_t sample = 0; sample < MICRO_SAMPLES; sample++) {
        if (!perf_warmup_decrypt(ct, clen, ad_dummy, 0u, key, npub, dec_dummy, MICRO_WARMUP_OPS)) {
            return 0;
        }

        const double t0 = perf_timer_seconds();
        for (size_t i = 0; i < iters; i++) {
            unsigned long long out_mlen = 0ULL;
            int ret = crypto_aead_decrypt(dec_dummy, &out_mlen, NULL,
                                          ct, clen,
                                          ad_dummy, 0ULL,
                                          npub, key);
            if (ret != 0 || out_mlen != 0ULL) {
                return 0;
            }
            micro_sink ^= (unsigned long long)dec_dummy[0];
        }
        const double t1 = perf_timer_seconds();

        samples[sample] = ((t1 - t0) * 1e9) / (double)iters;
    }

    *ns_per_op = perf_average(samples, MICRO_SAMPLES);
    return 1;
}

static int run_micro_internal(FILE *csv, int pin_ok)
{
    printf("=== Internal micro benchmark (breakdown) ===\n");
    printf("Primitive under test: %s\n", MICRO_PRIMITIVE_LABEL);
    printf("Workload points: full=(mlen=%d, adlen=%d), aad-only, payload-only, tag-only-verify\n",
           MICRO_MSG_LEN, MICRO_AAD_LEN);

    if (csv) {
        fprintf(csv, "metric,primitive,samples,iters_per_sample,mlen,adlen,ns_per_op,ns_per_round,aad_share_pct,msg_share_pct,glue_overhead_ns,pinning_core0,warmup_ops,notes\n");
    }

    const size_t full_iters = micro_iters_for_case(MICRO_MSG_LEN, MICRO_AAD_LEN);
    const size_t aad_iters = micro_iters_for_case(0u, MICRO_AAD_LEN);
    const size_t payload_iters = micro_iters_for_case(MICRO_MSG_LEN, 0u);
    const size_t tag_verify_iters = micro_iters_for_case(0u, 0u);

    double primitive_ns_call = 0.0;
    double primitive_ns_round = 0.0;
    double full_ns = 0.0;
    double aad_only_ns = 0.0;
    double payload_only_ns = 0.0;
    double tag_verify_ns = 0.0;

    if (!micro_measure_primitive(&primitive_ns_call, &primitive_ns_round)) {
        fprintf(stderr, "Primitive micro measurement failed\n");
        return 1;
    }
    if (!micro_measure_encrypt_case(MICRO_MSG_LEN, MICRO_AAD_LEN, full_iters, &full_ns)) {
        fprintf(stderr, "Full AEAD measurement failed\n");
        return 1;
    }
    if (!micro_measure_encrypt_case(0u, MICRO_AAD_LEN, aad_iters, &aad_only_ns)) {
        fprintf(stderr, "AAD-only measurement failed\n");
        return 1;
    }
    if (!micro_measure_encrypt_case(MICRO_MSG_LEN, 0u, payload_iters, &payload_only_ns)) {
        fprintf(stderr, "Payload-only measurement failed\n");
        return 1;
    }
    if (!micro_measure_tag_only_verify(tag_verify_iters, &tag_verify_ns)) {
        fprintf(stderr, "Tag-only verify measurement failed\n");
        return 1;
    }

    const double denominator = aad_only_ns + payload_only_ns;
    const double aad_share = (denominator > 0.0) ? (100.0 * aad_only_ns / denominator) : 0.0;
    const double msg_share = (denominator > 0.0) ? (100.0 * payload_only_ns / denominator) : 0.0;
    const double glue_overhead_ns = full_ns - aad_only_ns - payload_only_ns;

    printf("primitive      : %.3f ns/call, %.3f ns/round (rounds=%d)\n",
           primitive_ns_call, primitive_ns_round, MICRO_PRIMITIVE_ROUNDS);
    printf("aead full      : %.3f ns/op (iters=%zu)\n", full_ns, full_iters);
    printf("aead aad-only  : %.3f ns/op (mlen=0, adlen=%d, iters=%zu)\n",
           aad_only_ns, MICRO_AAD_LEN, aad_iters);
    printf("aead payload   : %.3f ns/op (mlen=%d, adlen=0, iters=%zu)\n",
           payload_only_ns, MICRO_MSG_LEN, payload_iters);
    printf("tag-only verify: %.3f ns/op (empty msg/ad, iters=%zu)\n", tag_verify_ns, tag_verify_iters);
    printf("aad-vs-msg share (aad_only + payload_only model): AAD=%.2f%%, MSG=%.2f%%\n",
           aad_share, msg_share);
    printf("glue overhead  : %.3f ns/op (full - aad_only - payload_only)\n", glue_overhead_ns);

    if (csv) {
        fprintf(csv, "primitive_call,%s,%d,%zu,,,%.6f,,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, MICRO_PRIMITIVE_ITERS,
                primitive_ns_call, pin_ok, MICRO_PRIMITIVE_WARMUP_OPS, "ns_per_call");
        fprintf(csv, "primitive_round,%s,%d,%zu,,,,%.6f,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, MICRO_PRIMITIVE_ITERS,
                primitive_ns_round,
                pin_ok, MICRO_PRIMITIVE_WARMUP_OPS, "derived_from_call");
        fprintf(csv, "aead_full_encrypt,%s,%d,%zu,%d,%d,%.6f,,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, full_iters,
                MICRO_MSG_LEN, MICRO_AAD_LEN, full_ns,
                pin_ok, MICRO_WARMUP_OPS, "ns_per_op");
        fprintf(csv, "aead_aad_only_encrypt,%s,%d,%zu,%d,%d,%.6f,,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, aad_iters,
                0, MICRO_AAD_LEN, aad_only_ns,
                pin_ok, MICRO_WARMUP_OPS, "ns_per_op");
        fprintf(csv, "aead_payload_only_encrypt,%s,%d,%zu,%d,%d,%.6f,,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, payload_iters,
                MICRO_MSG_LEN, 0, payload_only_ns,
                pin_ok, MICRO_WARMUP_OPS, "ns_per_op");
        fprintf(csv, "aead_tag_only_verify,%s,%d,%zu,%d,%d,%.6f,,,,,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES, tag_verify_iters,
                0, 0, tag_verify_ns,
                pin_ok, MICRO_WARMUP_OPS, "decrypt_empty_message");
        fprintf(csv, "aead_aad_vs_msg_share,%s,%d,,%d,%d,,,%.6f,%.6f,%.6f,%d,%d,%s\n",
                MICRO_PRIMITIVE_LABEL, MICRO_SAMPLES,
                MICRO_MSG_LEN, MICRO_AAD_LEN,
                aad_share, msg_share, glue_overhead_ns,
                pin_ok, MICRO_WARMUP_OPS, "share_from_aad_only_and_payload_only");
    }

    (void)micro_sink;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [CSV_FILE]\n", prog);
}

int main(int argc, char **argv)
{
    if (argc > 2) {
        usage(argv[0]);
        return 1;
    }

    FILE *csv = NULL;
    if (argc == 2) {
        csv = fopen(argv[1], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
    }

    int pin_ok = perf_pin_to_single_core();
    perf_print_stabilization_info(pin_ok);

    const int rc = run_micro_internal(csv, pin_ok);
    if (csv) {
        fclose(csv);
    }
    return rc;
}
