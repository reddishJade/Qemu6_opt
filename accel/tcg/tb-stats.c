/*
 * Translation Block Statistics Implementation
 *
 * High-performance statistics collection for TB operations
 */
#include "qemu/osdep.h"
#include "exec/tb-stats.h"
#include "qemu/log.h"
#include <stdio.h>

/* Global statistics instance */
TBLookupStats g_tb_stats = {0};

#if TB_STATS_ENABLED

/* Initialize statistics system */
void tb_stats_init(void)
{
    tb_stats_reset();
}

/* Reset all statistics counters */
void tb_stats_reset(void)
{
    memset(&g_tb_stats, 0, sizeof(g_tb_stats));
}

/* Get current statistics snapshot (atomic reads) */
TBLookupStats tb_stats_get(void)
{
    TBLookupStats stats;
    int i;

    stats.lookup_count   = qatomic_read(&g_tb_stats.lookup_count);
    stats.lookup_success = qatomic_read(&g_tb_stats.lookup_success);
    stats.lookup_miss    = qatomic_read(&g_tb_stats.lookup_miss);

    stats.hit_count_tb_jmp_cache = qatomic_read(&g_tb_stats.hit_count_tb_jmp_cache);
    stats.hit_count_qht          = qatomic_read(&g_tb_stats.hit_count_qht);
    stats.fallback_to_dispatcher = qatomic_read(&g_tb_stats.fallback_to_dispatcher);

    stats.tb_gen_count           = qatomic_read(&g_tb_stats.tb_gen_count);
    stats.tb_pre_translate_count = qatomic_read(&g_tb_stats.tb_pre_translate_count);
    stats.tb_exec_count          = qatomic_read(&g_tb_stats.tb_exec_count);

    stats.pre_translate_calls       = qatomic_read(&g_tb_stats.pre_translate_calls);
    stats.pre_translate_depth_sum   = qatomic_read(&g_tb_stats.pre_translate_depth_sum);
    stats.pre_translate_depth_max   = qatomic_read(&g_tb_stats.pre_translate_depth_max);
    stats.pre_translate_lookup_hit  = qatomic_read(&g_tb_stats.pre_translate_lookup_hit);
    stats.pre_translate_lookup_miss = qatomic_read(&g_tb_stats.pre_translate_lookup_miss);

    for (i = 0; i < TB_PRETRANS_DEPTH_BUCKETS; i++) {
        stats.pre_translate_depth_buckets[i] =
            qatomic_read(&g_tb_stats.pre_translate_depth_buckets[i]);
    }

    return stats;
}

/* Calculate lookup success rate */
double tb_lookup_success_rate(void)
{
    uint64_t calls   = qatomic_read(&g_tb_stats.lookup_count);
    uint64_t success = qatomic_read(&g_tb_stats.lookup_success);

    return calls > 0 ? (double)success / calls : 0.0;
}

/* Calculate tb_lookup cache hit rate */
double tb_cache_hit_rate(void)
{
    uint64_t total = qatomic_read(&g_tb_stats.hit_count_tb_jmp_cache) +
                     qatomic_read(&g_tb_stats.hit_count_qht) +
                     qatomic_read(&g_tb_stats.fallback_to_dispatcher);
    uint64_t hits  = qatomic_read(&g_tb_stats.hit_count_tb_jmp_cache) +
                     qatomic_read(&g_tb_stats.hit_count_qht);

    return total > 0 ? (double)hits / total : 0.0;
}

/* Calculate average pre-translation chain depth */
double tb_pre_translate_avg_depth(void)
{
    uint64_t calls = qatomic_read(&g_tb_stats.pre_translate_calls);
    uint64_t sum   = qatomic_read(&g_tb_stats.pre_translate_depth_sum);

    return calls > 0 ? (double)sum / calls : 0.0;
}

/*
 * Calculate pre-translation per-step cache hit rate.
 * hit_rate = hits / (hits + misses)
 * A high rate means most chained TBs were already cached;
 * a low rate means pre-translation is doing heavy ahead-of-time work.
 */
double tb_pre_translate_hit_rate(void)
{
    uint64_t hit  = qatomic_read(&g_tb_stats.pre_translate_lookup_hit);
    uint64_t miss = qatomic_read(&g_tb_stats.pre_translate_lookup_miss);
    uint64_t total = hit + miss;

    return total > 0 ? (double)hit / total : 0.0;
}

/* ASCII bar for a percentage value (max 20 chars wide) */
static void print_bar(FILE *f, double pct)
{
    int filled = (int)(pct / 5.0 + 0.5); /* 1 char per 5% */
    int i;
    fprintf(f, " |");
    for (i = 0; i < 20; i++) {
        fputc(i < filled ? '#' : ' ', f);
    }
    fprintf(f, "|");
}

/* Bucket label strings, parallel to tb_pretrans_depth_bucket_idx() */
static const char * const bucket_labels[TB_PRETRANS_DEPTH_BUCKETS] = {
    "depth = 0      (noop)",
    "depth = 1      ",
    "depth = 2      ",
    "depth = 3      ",
    "depth = 4 ~ 7  ",
    "depth = 8 ~ 15 ",
    "depth = 16 ~ 31",
    "depth >= 32    ",
};

/* Dump statistics to stderr */
void tb_stats_dump(void)
{
    TBLookupStats stats = tb_stats_get();
    uint64_t cache_total = stats.hit_count_tb_jmp_cache +
                           stats.hit_count_qht +
                           stats.fallback_to_dispatcher;
    uint64_t pt_steps    = stats.pre_translate_lookup_hit +
                           stats.pre_translate_lookup_miss;

    fprintf(stderr, "\n=== TB Statistics ===\n");
    fprintf(stderr, "TB_STATS_ENABLED: %d  |  Global stats addr: %p\n",
            TB_STATS_ENABLED, (void *)&g_tb_stats);

#if TB_STATS_LOOKUP
    fprintf(stderr,
            "\n--- [LOOKUP] lookup_tb_ptr ---\n"
            "  Total Calls   : %lu\n"
            "  Found TB      : %lu (%.2f%%)\n"
            "  Not Found     : %lu (%.2f%%) -> exit to epilogue\n",
            (unsigned long)stats.lookup_count,
            (unsigned long)stats.lookup_success,
            tb_lookup_success_rate() * 100.0,
            (unsigned long)stats.lookup_miss,
            stats.lookup_count > 0
                ? (double)stats.lookup_miss / stats.lookup_count * 100.0
                : 0.0);
#else
    fprintf(stderr, "\n--- [LOOKUP] disabled (TB_STATS_LOOKUP=0) ---\n");
#endif

#if TB_STATS_CACHE
    fprintf(stderr,
            "\n--- [CACHE] tb_lookup detail ---\n"
            "  tb_jmp_cache Hits      : %lu (%.2f%%) - fast path\n"
            "  Hash Table Hits        : %lu (%.2f%%) - slow path\n"
            "  Fallback to Dispatcher : %lu (%.2f%%) - need translation\n"
            "  Total tb_lookup calls  : %lu\n"
            "  Overall cache hit rate : %.2f%%\n",
            (unsigned long)stats.hit_count_tb_jmp_cache,
            cache_total > 0
                ? (double)stats.hit_count_tb_jmp_cache / cache_total * 100.0
                : 0.0,
            (unsigned long)stats.hit_count_qht,
            cache_total > 0
                ? (double)stats.hit_count_qht / cache_total * 100.0
                : 0.0,
            (unsigned long)stats.fallback_to_dispatcher,
            cache_total > 0
                ? (double)stats.fallback_to_dispatcher / cache_total * 100.0
                : 0.0,
            (unsigned long)cache_total,
            tb_cache_hit_rate() * 100.0);
#else
    fprintf(stderr, "\n--- [CACHE] disabled (TB_STATS_CACHE=0) ---\n");
#endif

#if TB_STATS_GEN
    fprintf(stderr,
            "\n--- [GEN] TB Generation & Execution ---\n"
            "  TB Generated (tb_gen_code) : %lu\n"
            "  TB Pre-translated          : %lu\n"
            "  TB Executed (dispatcher)   : %lu\n",
            (unsigned long)stats.tb_gen_count,
            (unsigned long)stats.tb_pre_translate_count,
            (unsigned long)stats.tb_exec_count);
#else
    fprintf(stderr, "\n--- [GEN] disabled (TB_STATS_GEN=0) ---\n");
#endif

#if TB_STATS_DEPTH
    {
        int i;
        uint64_t bucket_total = 0;

        for (i = 0; i < TB_PRETRANS_DEPTH_BUCKETS; i++) {
            bucket_total += stats.pre_translate_depth_buckets[i];
        }

        fprintf(stderr,
                "\n--- [DEPTH] Pre-translation Chain Depth ---\n"
                "  Invocations   : %lu\n"
                "  Total steps   : %lu  (hit + miss)\n"
                "  Avg depth     : %.2f  steps/call\n"
                "  Max depth     : %lu\n"
                "\n"
                "  Per-step cache hit rate : %.2f%%"
                "  (%lu hits / %lu misses)\n"
                "  -> hit  = next TB already in cache (no tb_gen_code)\n"
                "  -> miss = next TB had to be freshly compiled\n",
                (unsigned long)stats.pre_translate_calls,
                (unsigned long)pt_steps,
                tb_pre_translate_avg_depth(),
                (unsigned long)stats.pre_translate_depth_max,
                tb_pre_translate_hit_rate() * 100.0,
                (unsigned long)stats.pre_translate_lookup_hit,
                (unsigned long)stats.pre_translate_lookup_miss);

        fprintf(stderr, "\n  Depth histogram (%lu invocations):\n",
                (unsigned long)bucket_total);
        for (i = 0; i < TB_PRETRANS_DEPTH_BUCKETS; i++) {
            uint64_t cnt = stats.pre_translate_depth_buckets[i];
            double   pct = bucket_total > 0
                           ? (double)cnt / bucket_total * 100.0
                           : 0.0;
            fprintf(stderr, "  [%d] %s : %8lu (%5.1f%%)",
                    i, bucket_labels[i], (unsigned long)cnt, pct);
            print_bar(stderr, pct);
            fprintf(stderr, "\n");
        }
    }
#else
    fprintf(stderr, "\n--- [DEPTH] disabled (TB_STATS_DEPTH=0) ---\n");
#endif

    fprintf(stderr, "=====================\n");
    fflush(stderr);
}
#endif /* TB_STATS_ENABLED */
