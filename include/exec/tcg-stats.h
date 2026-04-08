/*
 * Translation Block Statistics Collection
 *
 * Provides performance statistics for TB lookup operations
 */
#ifndef EXEC_TCG_STATS_H
#define EXEC_TCG_STATS_H

#include "qemu/osdep.h"
#include "qemu/atomic.h"

/* TB lookup statistics structure */
typedef struct TCGStats
{
    uint64_t lookup_tb_ptr_count; /* Total lookup_tb_ptr calls */
    uint64_t lookup_tb_ptr_hit;   /* lookup_tb_ptr hits */
    uint64_t lookup_tb_ptr_miss;  /* lookup_tb_ptr misses */
    uint64_t tb_lookup_hit;       /* tb_lookup hits (cpu-exec path) */
    uint64_t tb_lookup_miss;      /* tb_lookup misses (cpu-exec path) */
    uint64_t tb_gen_count;        /* Total TB generation count (tb_gen_code calls) */
    uint64_t tb_icount_sum;       /* Sum of TB icount (non-PLT) */
    uint64_t tb_exec_count;       /* TB execution count (via dispatcher) */
} TCGStats;

/* Configuration flags - Force enable for testing */
#if defined(CONFIG_TCG_STATS)
#define TCG_STATS_ENABLED 1
#else
#define TCG_STATS_ENABLED 0
#endif

/* Statistics macros for zero-overhead in release builds */
#if TCG_STATS_ENABLED
#define TCG_STAT_INC(field) qatomic_inc(&g_tcg_stats.field)
#define TCG_STAT_ADD(field, val) qatomic_add(&g_tcg_stats.field, val)
#else
#define TCG_STAT_INC(field) \
    do                      \
    {                       \
    } while (0)
#define TCG_STAT_ADD(field, val) \
    do                           \
    {                            \
    } while (0)
#endif

/* Global statistics instance */
extern TCGStats g_tcg_stats;

/* API functions */
#if TCG_STATS_ENABLED
void tcg_stats_init(void);
void tcg_stats_reset(void);
TCGStats tcg_stats_get(void);
void tcg_stats_dump(void);
#else
static inline void tcg_stats_init(void) {}
static inline void tcg_stats_reset(void) {}
static inline TCGStats tcg_stats_get(void)
{
    TCGStats empty = {0};
    return empty;
}
static inline void tcg_stats_dump(void) {}
#endif

#endif /* EXEC_TCG_STATS_H */
