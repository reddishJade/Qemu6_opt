#ifndef EXEC_INDIRECT_PROFILE_H
#define EXEC_INDIRECT_PROFILE_H

#include "qemu/osdep.h"

enum {
    INDIRECT_PROFILE_CALL = 1,
    INDIRECT_PROFILE_JMP = 2,
    INDIRECT_PROFILE_RET = 3,
};

#if defined(CONFIG_INDIRECT_PROFILE)
void indirect_profile_record(uint64_t site_pc, uint64_t target, uint32_t type);
void indirect_profile_dump(void);
#else
static inline void indirect_profile_dump(void) {}
#endif

#endif
