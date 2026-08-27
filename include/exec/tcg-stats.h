/*
 * Generic Translation Block statistics collection.
 */
#ifndef EXEC_TCG_STATS_H
#define EXEC_TCG_STATS_H

#include "qemu/osdep.h"
#include "qemu/atomic.h"

#ifndef TCG_STATS_LOOKUP
#define TCG_STATS_LOOKUP 1
#endif

#ifndef TCG_STATS_CACHE
#define TCG_STATS_CACHE 1
#endif

#ifndef TCG_STATS_GEN
#define TCG_STATS_GEN 1
#endif

typedef struct TCGStats {
    uint64_t lookup_count;
    uint64_t lookup_success;
    uint64_t lookup_miss;

    uint64_t hit_count_tb_jmp_cache;
    uint64_t hit_count_qht;
    uint64_t fallback_to_dispatcher;

    uint64_t tb_gen_count;
    uint64_t tb_exec_count;
} TCGStats;

#if defined(CONFIG_TCG_STATS)
#define TCG_STATS_ENABLED 1
#else
#define TCG_STATS_ENABLED 0
#endif

#if TCG_STATS_ENABLED
#define TCG_STAT_INC(field) qatomic_inc(&g_tcg_stats.field)
#else
#define TCG_STAT_INC(field) do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_LOOKUP
#define TCG_STAT_LOOKUP_INC(field) TCG_STAT_INC(field)
#else
#define TCG_STAT_LOOKUP_INC(field) do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_CACHE
#define TCG_STAT_CACHE_INC(field) TCG_STAT_INC(field)
#else
#define TCG_STAT_CACHE_INC(field) do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_GEN
#define TCG_STAT_GEN_INC(field) TCG_STAT_INC(field)
#else
#define TCG_STAT_GEN_INC(field) do { } while (0)
#endif

extern TCGStats g_tcg_stats;

#if TCG_STATS_ENABLED
void tcg_stats_init(void);
void tcg_stats_reset(void);
TCGStats tcg_stats_get(void);
void tcg_stats_dump(void);
double tcg_lookup_success_rate(void);
double tcg_cache_hit_rate(void);
#else
static inline void tcg_stats_init(void) {}
static inline void tcg_stats_reset(void) {}
static inline TCGStats tcg_stats_get(void)
{
    TCGStats empty = { 0 };
    return empty;
}
static inline void tcg_stats_dump(void) {}
static inline double tcg_lookup_success_rate(void) { return 0.0; }
static inline double tcg_cache_hit_rate(void) { return 0.0; }
#endif

#endif /* EXEC_TCG_STATS_H */
