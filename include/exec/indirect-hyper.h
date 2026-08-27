#ifndef EXEC_INDIRECT_HYPER_H
#define EXEC_INDIRECT_HYPER_H

#include "qemu/osdep.h"
#include "exec/cpu-defs.h"

struct CPUState;

#ifndef INDIRECT_HYPER_MAX_TARGETS
#define INDIRECT_HYPER_MAX_TARGETS 4
#endif

enum {
    INDIRECT_HYPER_CALL = 1,
    INDIRECT_HYPER_JMP = 2,
};

typedef enum IndirectHyperPlan {
    INDIRECT_HYPER_DISABLED,
    INDIRECT_HYPER_OBSERVE,
    INDIRECT_HYPER_LINKED,
} IndirectHyperPlan;

#if defined(CONFIG_RFICH)
IndirectHyperPlan indirect_hyperchain_get_plan(uint64_t site_pc,
                                               uint32_t type,
                                               target_ulong targets[],
                                               unsigned *count);
void indirect_hyperchain_record(struct CPUState *cpu, uint64_t site_pc,
                                target_ulong target, uint32_t type);
void indirect_hyperchain_dump(void);
#else
static inline IndirectHyperPlan
indirect_hyperchain_get_plan(uint64_t site_pc, uint32_t type,
                             target_ulong targets[], unsigned *count)
{
    (void)site_pc;
    (void)type;
    (void)targets;
    *count = 0;
    return INDIRECT_HYPER_DISABLED;
}

static inline void indirect_hyperchain_record(struct CPUState *cpu,
                                              uint64_t site_pc,
                                              target_ulong target,
                                              uint32_t type)
{
    (void)cpu;
    (void)site_pc;
    (void)target;
    (void)type;
}

static inline void indirect_hyperchain_dump(void)
{
}
#endif

#endif
