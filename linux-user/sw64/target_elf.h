/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation, or (at your option) any
 * later version. See the COPYING file in the top-level directory.
 */

#ifndef SW64_TARGET_ELF_H
#define SW64_TARGET_ELF_H
static inline const char *cpu_get_model(uint32_t eflags)
{
#ifdef CONFIG_TARGET_SW64_CPU_CORE3
    return "core3";
#elif CONFIG_TARGET_SW64_CPU_CORE4
    return "core4";
#else
    return "any";
#endif
}
#endif
