/* PBRP diagnostic counters and exit report. */
#include "qemu/osdep.h"
#include "exec/pbrp-log.h"
#include "qemu/atomic.h"

#define PBRP_DEPTH_BUCKETS 8

typedef struct PBRPLog {
    uint64_t pre_translate_calls;
    uint64_t pre_translate_steps;
    uint64_t pre_translate_hits;
    uint64_t pre_translate_misses;
    uint64_t pre_translate_max_depth;
    uint64_t pre_translate_depth[PBRP_DEPTH_BUCKETS];
    uint64_t patch_attempts;
    uint64_t patch_successes;
    uint64_t patch_skips;
    uint64_t patch_resets;
    uint64_t ret_attempts;
    uint64_t ret_hits;
    uint64_t ret_misses;
} PBRPLog;

static PBRPLog pbrp_log;

static unsigned pbrp_depth_bucket(uint64_t depth)
{
    if (depth <= 3) {
        return depth;
    }
    if (depth < 8) {
        return 4;
    }
    if (depth < 16) {
        return 5;
    }
    if (depth < 32) {
        return 6;
    }
    return 7;
}

static void pbrp_log_max(uint64_t *field, uint64_t value)
{
    uint64_t current = qatomic_read(field);

    while (value > current) {
        if (qatomic_cmpxchg(field, current, value) == current) {
            break;
        }
        current = qatomic_read(field);
    }
}

void pbrp_log_pre_translate(uint64_t depth, uint64_t hits)
{
    qatomic_inc(&pbrp_log.pre_translate_calls);
    qatomic_add(&pbrp_log.pre_translate_steps, depth);
    qatomic_add(&pbrp_log.pre_translate_hits, hits);
    qatomic_add(&pbrp_log.pre_translate_misses, depth - hits);
    qatomic_inc(&pbrp_log.pre_translate_depth[pbrp_depth_bucket(depth)]);
    pbrp_log_max(&pbrp_log.pre_translate_max_depth, depth);
}

void pbrp_log_patch_attempt(void)
{
    qatomic_inc(&pbrp_log.patch_attempts);
}

void pbrp_log_patch_success(void)
{
    qatomic_inc(&pbrp_log.patch_successes);
}

void pbrp_log_patch_skip(void)
{
    qatomic_inc(&pbrp_log.patch_skips);
}

void pbrp_log_patch_reset(void)
{
    qatomic_inc(&pbrp_log.patch_resets);
}

void pbrp_log_ret(bool hit)
{
    qatomic_inc(&pbrp_log.ret_attempts);
    if (hit) {
        qatomic_inc(&pbrp_log.ret_hits);
    } else {
        qatomic_inc(&pbrp_log.ret_misses);
    }
}

void pbrp_log_dump(void)
{
    static const char * const labels[PBRP_DEPTH_BUCKETS] = {
        "0", "1", "2", "3", "4-7", "8-15", "16-31", "32+",
    };
    uint64_t calls = qatomic_read(&pbrp_log.pre_translate_calls);
    uint64_t steps = qatomic_read(&pbrp_log.pre_translate_steps);
    uint64_t hits = qatomic_read(&pbrp_log.pre_translate_hits);
    uint64_t attempts = qatomic_read(&pbrp_log.ret_attempts);
    uint64_t ret_hits = qatomic_read(&pbrp_log.ret_hits);

    fprintf(stderr,
            "\n=== PBRP Log ===\n"
            "[pre-translate]\n"
            "  calls             : %" PRIu64 "\n"
            "  steps             : %" PRIu64 "\n"
            "  average depth     : %.2f\n"
            "  maximum depth     : %" PRIu64 "\n"
            "  lookup hits       : %" PRIu64 "\n"
            "  lookup misses     : %" PRIu64 "\n"
            "  lookup hit rate   : %.2f%%\n",
            calls, steps, calls ? (double)steps / calls : 0.0,
            qatomic_read(&pbrp_log.pre_translate_max_depth), hits,
            qatomic_read(&pbrp_log.pre_translate_misses),
            steps ? (double)hits / steps * 100.0 : 0.0);

    fprintf(stderr, "  depth histogram   :");
    for (unsigned i = 0; i < PBRP_DEPTH_BUCKETS; i++) {
        fprintf(stderr, " %s=%" PRIu64, labels[i],
                qatomic_read(&pbrp_log.pre_translate_depth[i]));
    }
    fprintf(stderr,
            "\n[patch]\n"
            "  attempts          : %" PRIu64 "\n"
            "  successes         : %" PRIu64 "\n"
            "  skips             : %" PRIu64 "\n"
            "  resets            : %" PRIu64 "\n"
            "[fast-ret]\n"
            "  attempts          : %" PRIu64 "\n"
            "  hits              : %" PRIu64 "\n"
            "  misses            : %" PRIu64 "\n"
            "  hit rate          : %.2f%%\n"
            "================\n",
            qatomic_read(&pbrp_log.patch_attempts),
            qatomic_read(&pbrp_log.patch_successes),
            qatomic_read(&pbrp_log.patch_skips),
            qatomic_read(&pbrp_log.patch_resets), attempts, ret_hits,
            qatomic_read(&pbrp_log.ret_misses),
            attempts ? (double)ret_hits / attempts * 100.0 : 0.0);
    fflush(stderr);
}
