/*
 * Translation Block Statistics Collection
 *
 * Consolidates general TCG statistics and RET_OPT pre-translation data.
 */
#ifndef EXEC_TCG_STATS_H
#define EXEC_TCG_STATS_H

#include "qemu/osdep.h"
#include "qemu/atomic.h"

/*
 * Fine-grained statistics category switches.
 * The RET_OPT-specific depth data remains separately controllable so
 * CONFIG_TCG_STATS can stay on without forcing pre_translate logging.
 */
#ifndef TCG_STATS_LOOKUP
#define TCG_STATS_LOOKUP  0
#endif

#ifndef TCG_STATS_CACHE
#define TCG_STATS_CACHE   0
#endif

#ifndef TCG_STATS_GEN
#define TCG_STATS_GEN     0
#endif

#ifndef TCG_STATS_DEPTH
#define TCG_STATS_DEPTH 1
#endif

#if defined(CONFIG_PRE_TRANSLATE_LOG)
/*
 * Pre-translation depth histogram bucket count.
 * Buckets:
 *   [0] depth  = 0
 *   [1] depth  = 1
 *   [2] depth  = 2
 *   [3] depth  = 3
 *   [4] depth  = 4-7
 *   [5] depth  = 8-15
 *   [6] depth  = 16-31
 *   [7] depth >= 32
 */
#define TCG_PRETRANS_DEPTH_BUCKETS  8

static inline unsigned tcg_pretrans_depth_bucket_idx(uint64_t depth)
{
    if (depth <= 3) {
        return (unsigned)depth;
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
#endif

typedef struct TCGStats {
    /* --- lookup category --- */
    uint64_t lookup_count;
    uint64_t lookup_success;
    uint64_t lookup_miss;

    /* --- cache category --- */
    uint64_t hit_count_tb_jmp_cache;
    uint64_t hit_count_qht;
    uint64_t fallback_to_dispatcher;

    /* --- gen category --- */
    uint64_t tb_gen_count;
    uint64_t tb_exec_count;

#if defined(CONFIG_PRE_TRANSLATE_LOG)
    /*
     * --- Pre-translation category ---
     * Enabled only when CONFIG_PRE_TRANSLATE_LOG is also set.
     */
    uint64_t tb_pre_translate_count;
    uint64_t pre_translate_calls;
    uint64_t pre_translate_depth_sum;
    uint64_t pre_translate_depth_max;
    uint64_t pre_translate_lookup_hit;
    uint64_t pre_translate_lookup_miss;
    uint64_t pre_translate_depth_buckets[TCG_PRETRANS_DEPTH_BUCKETS];
#endif
} TCGStats;

#if defined(CONFIG_TCG_STATS)
#define TCG_STATS_ENABLED 1
#else
#define TCG_STATS_ENABLED 0
#endif

#if TCG_STATS_ENABLED && defined(CONFIG_PRE_TRANSLATE_LOG)
#define TCG_STATS_DEPTH_ENABLED 1
#else
#define TCG_STATS_DEPTH_ENABLED 0
#endif

#if TCG_STATS_ENABLED
#define TCG_STAT_INC(field)          qatomic_inc(&g_tcg_stats.field)
#define TCG_STAT_ADD(field, val)     qatomic_add(&g_tcg_stats.field, val)
#define TCG_STAT_MAX(field, val)                                             \
    do {                                                                     \
        uint64_t _cur = qatomic_read(&g_tcg_stats.field);                    \
        uint64_t _new = (uint64_t)(val);                                     \
        while (_new > _cur) {                                                \
            if (qatomic_cmpxchg(&g_tcg_stats.field, _cur, _new) == _cur) {   \
                break;                                                       \
            }                                                                \
            _cur = qatomic_read(&g_tcg_stats.field);                         \
        }                                                                    \
    } while (0)
#else
#define TCG_STAT_INC(field)          do { } while (0)
#define TCG_STAT_ADD(field, val)     do { } while (0)
#define TCG_STAT_MAX(field, val)     do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_LOOKUP
#define TCG_STAT_LOOKUP_INC(f)       TCG_STAT_INC(f)
#else
#define TCG_STAT_LOOKUP_INC(f)       do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_CACHE
#define TCG_STAT_CACHE_INC(f)        TCG_STAT_INC(f)
#else
#define TCG_STAT_CACHE_INC(f)        do { } while (0)
#endif

#if TCG_STATS_ENABLED && TCG_STATS_GEN
#define TCG_STAT_GEN_INC(f)          TCG_STAT_INC(f)
#else
#define TCG_STAT_GEN_INC(f)          do { } while (0)
#endif

#if TCG_STATS_DEPTH_ENABLED && TCG_STATS_DEPTH
#define TCG_STAT_DEPTH_INC(f)        TCG_STAT_INC(f)
#define TCG_STAT_DEPTH_ADD(f, v)     TCG_STAT_ADD(f, v)
#define TCG_STAT_DEPTH_MAX(f, v)     TCG_STAT_MAX(f, v)
#define TCG_STAT_DEPTH_BUCKET(d) \
    TCG_STAT_DEPTH_INC(pre_translate_depth_buckets[tcg_pretrans_depth_bucket_idx(d)])
#else
#define TCG_STAT_DEPTH_INC(f)        do { } while (0)
#define TCG_STAT_DEPTH_ADD(f, v)     do { } while (0)
#define TCG_STAT_DEPTH_MAX(f, v)     do { } while (0)
#define TCG_STAT_DEPTH_BUCKET(d)     do { } while (0)
#endif

extern TCGStats g_tcg_stats;

#if TCG_STATS_ENABLED
void tcg_stats_init(void);
void tcg_stats_reset(void);
TCGStats tcg_stats_get(void);
void tcg_stats_dump(void);
double tcg_lookup_success_rate(void);
double tcg_cache_hit_rate(void);
#if defined(CONFIG_PRE_TRANSLATE_LOG)
double tcg_pre_translate_avg_depth(void);
double tcg_pre_translate_hit_rate(void);
#endif
#else
static inline void tcg_stats_init(void) {}
static inline void tcg_stats_reset(void) {}
static inline TCGStats tcg_stats_get(void)
{
    TCGStats empty = {0};
    return empty;
}
static inline void tcg_stats_dump(void) {}
static inline double tcg_lookup_success_rate(void) { return 0.0; }
static inline double tcg_cache_hit_rate(void) { return 0.0; }
#if defined(CONFIG_PRE_TRANSLATE_LOG)
static inline double tcg_pre_translate_avg_depth(void) { return 0.0; }
static inline double tcg_pre_translate_hit_rate(void) { return 0.0; }
#endif
#endif

#endif /* EXEC_TCG_STATS_H */
