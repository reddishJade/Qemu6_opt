/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "exec/indirect-profile.h"
#include "exec/indirect-hyper.h"
#ifdef CONFIG_GPROF
#include <sys/gmon.h>
#endif

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
#include "x86binary_analysis.h"
#endif

#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
#include "exec/tcg-stats.h"
#endif
#if defined(CONFIG_PBRP_LOG) && defined(__sw_64__)
#include "exec/pbrp-log.h"
#endif

void preexit_cleanup(CPUArchState *env, int code)
{
#ifdef CONFIG_GPROF
        _mcleanup();
#endif
#ifdef CONFIG_GCOV
        __gcov_dump();
#endif
#if defined(CONFIG_INDIRECT_PROFILE)
        indirect_profile_dump();
#endif
#if defined(CONFIG_RFICH_LOG)
        rfich_log_dump();
#endif
#if defined(CONFIG_PBRP_LOG) && defined(__sw_64__)
        pbrp_log_dump();
#endif
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
        tcg_stats_dump();
#endif
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
        x86binary_analysis_dump_stats();
#endif
        gdb_exit(code);
        qemu_plugin_atexit_cb();
}
