/*
 * Generic Translation Block statistics implementation.
 */
#include "qemu/osdep.h"
#include "exec/tcg-stats.h"

TCGStats g_tcg_stats;

#if TCG_STATS_ENABLED
void tcg_stats_init(void)
{
    tcg_stats_reset();
}

void tcg_stats_reset(void)
{
    memset(&g_tcg_stats, 0, sizeof(g_tcg_stats));
}

TCGStats tcg_stats_get(void)
{
    TCGStats stats;

    stats.lookup_count = qatomic_read(&g_tcg_stats.lookup_count);
    stats.lookup_success = qatomic_read(&g_tcg_stats.lookup_success);
    stats.lookup_miss = qatomic_read(&g_tcg_stats.lookup_miss);

    stats.hit_count_tb_jmp_cache =
        qatomic_read(&g_tcg_stats.hit_count_tb_jmp_cache);
    stats.hit_count_qht = qatomic_read(&g_tcg_stats.hit_count_qht);
    stats.fallback_to_dispatcher =
        qatomic_read(&g_tcg_stats.fallback_to_dispatcher);

    stats.tb_gen_count = qatomic_read(&g_tcg_stats.tb_gen_count);
    stats.tb_exec_count = qatomic_read(&g_tcg_stats.tb_exec_count);
    return stats;
}

double tcg_lookup_success_rate(void)
{
    uint64_t calls = qatomic_read(&g_tcg_stats.lookup_count);
    uint64_t success = qatomic_read(&g_tcg_stats.lookup_success);

    return calls ? (double)success / calls : 0.0;
}

double tcg_cache_hit_rate(void)
{
    uint64_t total = qatomic_read(&g_tcg_stats.hit_count_tb_jmp_cache) +
                     qatomic_read(&g_tcg_stats.hit_count_qht) +
                     qatomic_read(&g_tcg_stats.fallback_to_dispatcher);
    uint64_t hits = qatomic_read(&g_tcg_stats.hit_count_tb_jmp_cache) +
                    qatomic_read(&g_tcg_stats.hit_count_qht);

    return total ? (double)hits / total : 0.0;
}

void tcg_stats_dump(void)
{
    TCGStats stats = tcg_stats_get();
    uint64_t cache_total = stats.hit_count_tb_jmp_cache +
                           stats.hit_count_qht +
                           stats.fallback_to_dispatcher;

    fprintf(stderr,
            "\n=== TCG Statistics ===\n"
            "[lookup_tb_ptr]\n"
            "  calls             : %" PRIu64 "\n"
            "  hits              : %" PRIu64 " (%.2f%%)\n"
            "  misses            : %" PRIu64 "\n",
            stats.lookup_count, stats.lookup_success,
            tcg_lookup_success_rate() * 100.0, stats.lookup_miss);

    fprintf(stderr,
            "[tb_lookup]\n"
            "  jump-cache hits   : %" PRIu64 "\n"
            "  hash-table hits   : %" PRIu64 "\n"
            "  dispatcher misses : %" PRIu64 "\n"
            "  total             : %" PRIu64 "\n"
            "  hit rate          : %.2f%%\n",
            stats.hit_count_tb_jmp_cache, stats.hit_count_qht,
            stats.fallback_to_dispatcher, cache_total,
            tcg_cache_hit_rate() * 100.0);

    fprintf(stderr,
            "[translation]\n"
            "  TB generated      : %" PRIu64 "\n"
            "  TB executed       : %" PRIu64 "\n"
            "======================\n",
            stats.tb_gen_count, stats.tb_exec_count);
    fflush(stderr);
}
#endif /* TCG_STATS_ENABLED */
