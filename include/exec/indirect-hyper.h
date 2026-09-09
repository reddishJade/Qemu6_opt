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
                                               unsigned *count);
void indirect_hyperchain_record(struct CPUState *cpu, uint64_t site_pc,
                                target_ulong target);
#else
static inline IndirectHyperPlan
indirect_hyperchain_get_plan(uint64_t site_pc,
                             target_ulong targets[], unsigned *count)
{
    (void)site_pc;
    (void)targets;
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
#endif

#if defined(CONFIG_RFICH_LOG)
void rfich_log_linked_attempt(uint64_t site_pc);
void rfich_log_linked_miss(uint64_t site_pc);
void rfich_log_patch_attempt(void);
void rfich_log_patch_success(void);
void rfich_log_patch_skip(void);
void rfich_log_patch_reset(void);
void rfich_log_dump(void);
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
static inline void rfich_log_dump(void) {}
#endif

#endif
