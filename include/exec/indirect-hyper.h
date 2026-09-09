#ifndef EXEC_INDIRECT_HYPER_H
#define EXEC_INDIRECT_HYPER_H

#include "qemu/osdep.h"
#include "exec/cpu-defs.h"

struct CPUState;

#ifndef INDIRECT_HYPER_MAX_TARGETS
#define INDIRECT_HYPER_MAX_TARGETS 3
#endif

typedef enum IndirectHyperPlan {
    INDIRECT_HYPER_DISABLED,
    INDIRECT_HYPER_OBSERVE,
    INDIRECT_HYPER_LINKED,
} IndirectHyperPlan;

#if defined(CONFIG_RFICH)
IndirectHyperPlan indirect_hyperchain_get_plan(uint64_t site_pc,
                                               target_ulong targets[],
                                               unsigned *count,
                                               uintptr_t *observe_site);
void indirect_hyperchain_record(struct CPUState *cpu, uint64_t site_pc,
                                target_ulong target);
void indirect_hyperchain_record_cached(struct CPUState *cpu, void *site,
                                       target_ulong target);
#else
static inline IndirectHyperPlan
indirect_hyperchain_get_plan(uint64_t site_pc,
                             target_ulong targets[], unsigned *count,
                             uintptr_t *observe_site)
{
    (void)site_pc;
    (void)targets;
    (void)observe_site;
    *count = 0;
    return INDIRECT_HYPER_DISABLED;
}

static inline void indirect_hyperchain_record(struct CPUState *cpu,
                                              uint64_t site_pc,
                                              target_ulong target)
{
    (void)cpu;
    (void)site_pc;
    (void)target;
}

static inline void indirect_hyperchain_record_cached(struct CPUState *cpu,
                                                     void *site,
                                                     target_ulong target)
{
    (void)cpu;
    (void)site;
    (void)target;
}
#endif
#if defined(CONFIG_RFICH_LOG)
void rfich_log_tb_init(void);
void rfich_log_translation(unsigned target_count);
void rfich_log_tb_invalidate(unsigned target_count);
void rfich_log_prepare_call(void);
void rfich_log_prepare_self(void);
void rfich_log_prepare_lookup_hit(void);
void rfich_log_prepare_lookup_miss(void);
void rfich_log_prepare_skip(void);
#else
static inline void rfich_log_tb_init(void) {}
static inline void rfich_log_translation(unsigned target_count)
{
    (void)target_count;
}
static inline void rfich_log_tb_invalidate(unsigned target_count)
{
    (void)target_count;
}
static inline void rfich_log_prepare_call(void) {}
static inline void rfich_log_prepare_self(void) {}
static inline void rfich_log_prepare_lookup_hit(void) {}
static inline void rfich_log_prepare_lookup_miss(void) {}
static inline void rfich_log_prepare_skip(void) {}
#endif

#if defined(CONFIG_RFICH_LOG)
void rfich_log_linked_attempt(uint64_t site_pc);
void rfich_log_linked_miss(uint64_t site_pc);
void rfich_log_patch_attempt(void);
void rfich_log_patch_success(void);
void rfich_log_patch_skip(void);
void rfich_log_patch_reset(void);
#else
static inline void rfich_log_linked_attempt(uint64_t site_pc)
{
    (void)site_pc;
}
static inline void rfich_log_linked_miss(uint64_t site_pc)
{
    (void)site_pc;
}
static inline void rfich_log_patch_attempt(void) {}
static inline void rfich_log_patch_success(void) {}
static inline void rfich_log_patch_skip(void) {}
static inline void rfich_log_patch_reset(void) {}
#endif

#if defined(CONFIG_RFICH_LOG)
void rfich_log_dump(void);
#else
static inline void rfich_log_dump(void) {}
#endif

#endif
