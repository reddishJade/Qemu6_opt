/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef EXEC_TB_LOOKUP_H
#define EXEC_TB_LOOKUP_H

#ifdef NEED_CPU_H
#include "cpu.h"
#else
#include "exec/poison.h"
#endif

#include "exec/exec-all.h"
#include "exec/tb-hash.h"

#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
#include "exec/tcg-stats.h"
#endif

/* Might cause an exception, so have a longjmp destination ready */
static inline TranslationBlock *tb_lookup(CPUState *cpu, target_ulong pc,
                                          target_ulong cs_base,
                                          uint32_t flags, uint32_t cflags)
{
    TranslationBlock *tb;
    uint32_t hash;

    /* we should never be trying to look up an INVALID tb */
    tcg_debug_assert(!(cflags & CF_INVALID));

    hash = tb_jmp_cache_hash_func(pc);
    tb = qatomic_rcu_read(&cpu->tb_jmp_cache[hash]);

    if (likely(tb &&
               tb->pc == pc &&
               tb->cs_base == cs_base &&
               tb->flags == flags &&
               tb->trace_vcpu_dstate == *cpu->trace_dstate &&
               tb_cflags(tb) == cflags)) {
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
        TCG_STAT_CACHE_INC(hit_count_tb_jmp_cache);
#endif
        return tb;
    }
    tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
        TCG_STAT_CACHE_INC(fallback_to_dispatcher);
#endif
        return NULL;
    }
    qatomic_set(&cpu->tb_jmp_cache[hash], tb);
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
        TCG_STAT_CACHE_INC(hit_count_qht);
#endif
    return tb;
}

#endif /* EXEC_TB_LOOKUP_H */
