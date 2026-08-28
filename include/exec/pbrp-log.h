#ifndef EXEC_PBRP_LOG_H
#define EXEC_PBRP_LOG_H

#include "qemu/osdep.h"

#if defined(CONFIG_PBRP_LOG)
void pbrp_log_pre_translate(uint64_t depth, uint64_t hits);
void pbrp_log_patch_attempt(void);
void pbrp_log_patch_success(void);
void pbrp_log_patch_skip(void);
void pbrp_log_patch_reset(void);
void pbrp_log_ret(bool hit);
void pbrp_log_dump(void);
#else
static inline void pbrp_log_pre_translate(uint64_t depth, uint64_t hits)
{
    (void)depth;
    (void)hits;
}
static inline void pbrp_log_patch_attempt(void) {}
static inline void pbrp_log_patch_success(void) {}
static inline void pbrp_log_patch_skip(void) {}
static inline void pbrp_log_patch_reset(void) {}
static inline void pbrp_log_ret(bool hit) { (void)hit; }
static inline void pbrp_log_dump(void) {}
#endif

#endif /* EXEC_PBRP_LOG_H */
