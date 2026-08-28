/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "exec/tb-lookup.h"

#if defined(CONFIG_INDIRECT_PROFILE)
#include "exec/indirect-profile.h"
#endif
#if defined(CONFIG_RFICH)
#include "exec/indirect-hyper.h"
#endif

#if defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
#include "x86binary_analysis.h"
#include "include/qapi/error.h"
#include "include/qemu/log.h"
#endif

#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
#include "exec/tcg-stats.h"
#endif
#if defined(CONFIG_PBRP_LOG) && defined(__sw_64__)
#include "exec/pbrp-log.h"
#endif

/* 32-bit helpers */

int32_t HELPER(div_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 / arg2;
}

int32_t HELPER(rem_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 % arg2;
}

uint32_t HELPER(divu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 / arg2;
}

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

/* 64-bit helpers */

uint64_t HELPER(shl_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 << arg2;
}

uint64_t HELPER(shr_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(sar_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(div_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 / arg2;
}

int64_t HELPER(rem_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(divu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 / arg2;
}

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

const void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
    FunctionMetadata *meta = find_function_metadata_by_address(pc + cs_base);
    if (meta)
    {
        native_libs_write_to_file(pc + cs_base,meta);
    }
#endif

    tb = tb_lookup(cpu, pc, cs_base, flags, curr_cflags(cpu));
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
    TCG_STAT_LOOKUP_INC(lookup_count);
#endif

    if (tb == NULL) {
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
      TCG_STAT_LOOKUP_INC(lookup_miss);
#endif
      return tcg_code_gen_epilogue;
    }
#if defined(CONFIG_TCG_STATS) && defined(__sw_64__)
    TCG_STAT_LOOKUP_INC(lookup_success);
#endif

    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
}

#if defined(CONFIG_INDIRECT_PROFILE)
void HELPER(profile_indirect)(target_ulong site_pc, target_ulong target,
                              uint32_t type)
{
    indirect_profile_record(site_pc, target, type);
}
#endif
#if defined(CONFIG_RFICH)
void HELPER(hyperchain_observe)(CPUArchState *env, target_ulong site_pc,
                                target_ulong target, uint32_t type)
{
    indirect_hyperchain_record(env_cpu(env), site_pc, target, type);
}
#endif
#if defined(CONFIG_RFICH_LOG)
void HELPER(rfich_linked_attempt)(target_ulong site_pc, uint32_t type)
{
    rfich_log_linked_attempt(site_pc, type);
}
#endif
#if defined(CONFIG_PBRP_DEBUG) || defined(CONFIG_PBRP_LOG)
void HELPER(pbrp_ret_observe)(CPUArchState *env, target_ulong target)
{
    bool hit = target == env->gpc;

#if defined(CONFIG_PBRP_LOG)
    pbrp_log_ret(hit);
#endif
#if defined(CONFIG_PBRP_DEBUG)
    fprintf(stderr,
            "PBRP-DEBUG ret target=0x" TARGET_FMT_lx
            " expected=0x" TARGET_FMT_lx " hit=%d\n",
            target, env->gpc, hit);
#endif
}
#endif
#if defined(CONFIG_NATIVE_LIBS)
#define SAVE_ENV_REGISTER() \
    __asm__("FILLCS  0($17)" :::); \
    __asm__("subl $sp, 8*7, $sp" :::); \
    __asm__("stl $25, 8*2($sp)" :::); \
    __asm__("stl $26, 8*3($sp)" :::); \
    __asm__("stl $29, 8*4($sp)" :::); \
    __asm__("stl $16, 8*5($sp)" :::); \
    __asm__("bis %0, $31, $27" ::"r"(host_addr) :);
#define RESTORE_ENV_REGISTER() \
    __asm__("call $26,($27), 0" :::); \
    __asm__("ldl $25, 8*2($sp)" :::); \
    __asm__("ldl $26, 8*3($sp)" :::); \
    __asm__("ldl $29, 8*4($sp)" :::); \
    __asm__("ldl $16, 8*5($sp)" :::); \
    __asm__("bis $0, $31, %0" : "=r"(env->regs[R_EAX])::); \
    __asm__("addl $sp, 8*7, $sp" :::);
#define RESTORE_ENV_REGISTER_FPR() \
    __asm__("call $26,($27), 0" :::); \
    __asm__("ldl $25, 8*2($sp)" :::); \
    __asm__("ldl $26, 8*3($sp)" :::); \
    __asm__("ldl $29, 8*4($sp)" :::); \
    __asm__("ldl $16, 8*5($sp)" :::); \
    __asm__("fcpys $f0, $f0, %0" : "=f"(env->xmm_regs[0]._d_ZMMReg[0])::); \
    __asm__("addl $sp, 8*7, $sp" :::);

#define SAVE_ENV_REGISTER_VOID()       \
    __asm__("FILLCS  0($17)" :::); \
    __asm__("subl $sp, 8*7, $sp" :::); \
    __asm__("stl $25, 8*2($sp)" :::);  \
    __asm__("stl $26, 8*3($sp)" :::);  \
    __asm__("stl $29, 8*4($sp)" :::);  \
    __asm__("bis %0, $31, $27" ::"r"(host_addr) :);
#define RESTORE_ENV_REGISTER_VOID()   \
    __asm__("call $26,($27), 0" :::); \
    __asm__("ldl $25, 8*2($sp)" :::); \
    __asm__("ldl $26, 8*3($sp)" :::); \
    __asm__("ldl $29, 8*4($sp)" :::); \
    __asm__("addl $sp, 8*7, $sp" :::);

#define LOAD_ARGS_GPR(n) _LOAD_ARGS_GPR_##n()

#define _LOAD_ARGS_GPR_0() // 无参数，无需操作

#define _LOAD_ARGS_GPR_1() \
    __asm__("bis %0, $31, $16" ::"r"(env->regs[R_EDI]) :);

#define _LOAD_ARGS_GPR_2() \
    __asm__("bis %0, $31, $17" ::"r"(env->regs[R_ESI]) :); \
    _LOAD_ARGS_GPR_1()

#define _LOAD_ARGS_GPR_3() \
    __asm__("bis %0, $31, $18" ::"r"(env->regs[R_EDX]) :); \
    _LOAD_ARGS_GPR_2()

#define _LOAD_ARGS_GPR_4() \
    __asm__("bis %0, $31, $19" ::"r"(env->regs[R_ECX]) :); \
    _LOAD_ARGS_GPR_3()

#define _LOAD_ARGS_GPR_5() \
    __asm__("bis %0, $31, $20" ::"r"(env->regs[R_R8]) :); \
    _LOAD_ARGS_GPR_4()

#define _LOAD_ARGS_GPR_6() \
    __asm__("bis %0, $31, $21" ::"r"(env->regs[R_R9]) :); \
    _LOAD_ARGS_GPR_5()

#define _LOAD_ARGS_GPR_7() \
    __asm__("stl %0, 0($sp)" ::"r"(*((abi_ulong *)env->regs[R_ESP] + 8 / (sizeof(abi_ulong *)))) :); \
    _LOAD_ARGS_GPR_6()

#define _LOAD_ARGS_GPR_8() \
    __asm__("stl %0, 8($sp)" ::"r"(*((abi_ulong *)env->regs[R_ESP] + 16 / (sizeof(abi_ulong *)))) :); \
    _LOAD_ARGS_GPR_7()

#define LOAD_ARGS_FPR(n) _LOAD_ARGS_FPR_##n()

#define _LOAD_ARGS_FPR_0() // 无参数，无需操作

#define _LOAD_ARGS_FPR_1() \
    __asm__("fcpys %0, %0, $f16" :: "f"(env->xmm_regs[0]._d_ZMMReg[0]):);

#define _LOAD_ARGS_FPR_2() \
    __asm__("fcpys %0, %0, $f17" :: "f"(env->xmm_regs[1]._d_ZMMReg[0]):);  \
    _LOAD_ARGS_FPR_1()

#define _LOAD_ARGS_FPR_3() \
    __asm__("fcpys %0, %0, $f18" :: "f"(env->xmm_regs[2]._d_ZMMReg[0]):);  \
    _LOAD_ARGS_FPR_2()

#define _LOAD_ARGS_FPR_4() \
    __asm__("fcpys %0, %0, $f19" :: "f"(env->xmm_regs[3]._d_ZMMReg[0]):);  \
    _LOAD_ARGS_FPR_3()

#define _LOAD_ARGS_FPR_5() \
    __asm__("fcpys %0, %0, $f20" :: "f"(env->xmm_regs[4]._d_ZMMReg[0]):);  \
    _LOAD_ARGS_FPR_4()

#define _LOAD_ARGS_FPR_6() \
    __asm__("fcpys %0, %0, $f21" :: "f"(env->xmm_regs[5]._d_ZMMReg[0]):);  \
    _LOAD_ARGS_FPR_5()

#define LOAD_ARGS_FPR_GPR(n) _LOAD_ARGS_FPR_GPR_##n()

#define _LOAD_ARGS_FPR_GPR_0() // 无参数，无需操作
#define _LOAD_ARGS_FPR_GPR_1() //float, equal _LOAD_ARGS_FPR_1
#define _LOAD_ARGS_FPR_GPR_2() //float int

//float int int
#define _LOAD_ARGS_FPR_GPR_3() \
    __asm__("fcpys %0, %0, $f16" :: "f"(env->xmm_regs[0]._d_ZMMReg[0]):); \
    __asm__("bis %0, $31, $17" ::"r"(env->regs[R_EDI]) :);\
    __asm__("bis %0, $31, $18" ::"r"(env->regs[R_ESI]) :);

//float float int int
#define _LOAD_ARGS_FPR_GPR_4() \
    __asm__("fcpys %0, %0, $f16" :: "f"(env->xmm_regs[0]._d_ZMMReg[0]):); \
    __asm__("fcpys %0, %0, $f17" :: "f"(env->xmm_regs[1]._d_ZMMReg[0]):);  \
    __asm__("bis %0, $31, $18" ::"r"(env->regs[R_EDI]) :);\
    __asm__("bis %0, $31, $19" ::"r"(env->regs[R_ESI]) :);

#define helper_call_native_lib_GPR(env, host_address, n) \
__attribute__((naked)) void HELPER(call_native_lib_GPR_##n)(CPUArchState *env, uint64_t host_addr) \
{   \
    SAVE_ENV_REGISTER()     \
    LOAD_ARGS_GPR(n)    \
    RESTORE_ENV_REGISTER()  \
}

#define helper_call_native_lib_GPR_VOID(env, host_address, n)                                                \
__attribute__((naked)) void HELPER(call_native_lib_GPR_VOID_##n)(CPUArchState * env, uint64_t host_addr) \
{                                                                                                        \
    SAVE_ENV_REGISTER_VOID()                                                                             \
    LOAD_ARGS_GPR(n)                                                                                     \
    RESTORE_ENV_REGISTER_VOID()                                                                          \
}

#define helper_call_native_lib_FPR(env, host_address, n) \
__attribute__((naked)) void HELPER(call_native_lib_FPR_##n)(CPUArchState *env, uint64_t host_addr) \
{   \
    SAVE_ENV_REGISTER()     \
    LOAD_ARGS_FPR(n)    \
    RESTORE_ENV_REGISTER_FPR()  \
}

#define helper_call_native_lib_FPR_VOID(env, host_address, n)                                                \
__attribute__((naked)) void HELPER(call_native_lib_FPR_VOID_##n)(CPUArchState * env, uint64_t host_addr) \
{                                                                                                        \
    SAVE_ENV_REGISTER_VOID()                                                                             \
    LOAD_ARGS_FPR(n)                                                                                     \
    RESTORE_ENV_REGISTER_VOID()                                                                          \
}

#define helper_call_native_lib_FPR_GPR(env, host_address, n)                                                \
__attribute__((naked)) void HELPER(call_native_lib_FPR_GPR_##n)(CPUArchState * env, uint64_t host_addr) \
{                                                                                                        \
    SAVE_ENV_REGISTER()                                                                                  \
    LOAD_ARGS_FPR_GPR(n)                                                                                     \
    RESTORE_ENV_REGISTER()                                                                           \
}

#define helper_call_native_lib_FPR_GPR_VOID(env, host_address, n)                                                \
__attribute__((naked)) void HELPER(call_native_lib_FPR_GPR_VOID_##n)(CPUArchState * env, uint64_t host_addr) \
{                                                                                                        \
    SAVE_ENV_REGISTER_VOID()                                                                             \
    LOAD_ARGS_FPR_GPR(n)                                                                                 \
    RESTORE_ENV_REGISTER_VOID()                                                                          \
}

helper_call_native_lib_GPR(env, host_address, 0)
helper_call_native_lib_GPR(env, host_address, 1)
helper_call_native_lib_GPR(env, host_address, 2)
helper_call_native_lib_GPR(env, host_address, 3)
helper_call_native_lib_GPR(env, host_address, 4)
helper_call_native_lib_GPR(env, host_address, 5)
helper_call_native_lib_GPR(env, host_address, 6)
helper_call_native_lib_GPR(env, host_address, 7)
helper_call_native_lib_GPR(env, host_address, 8)

helper_call_native_lib_GPR_VOID(env, host_address, 0)
helper_call_native_lib_GPR_VOID(env, host_address, 1)
helper_call_native_lib_GPR_VOID(env, host_address, 2)
helper_call_native_lib_GPR_VOID(env, host_address, 3)
helper_call_native_lib_GPR_VOID(env, host_address, 4)
helper_call_native_lib_GPR_VOID(env, host_address, 5)
helper_call_native_lib_GPR_VOID(env, host_address, 6)
helper_call_native_lib_GPR_VOID(env, host_address, 7)
helper_call_native_lib_GPR_VOID(env, host_address, 8)

helper_call_native_lib_FPR(env, host_address, 0)
helper_call_native_lib_FPR(env, host_address, 1)
helper_call_native_lib_FPR(env, host_address, 2)
helper_call_native_lib_FPR(env, host_address, 3)
helper_call_native_lib_FPR(env, host_address, 4)
helper_call_native_lib_FPR(env, host_address, 5)
helper_call_native_lib_FPR(env, host_address, 6)

helper_call_native_lib_FPR_VOID(env, host_address, 0)
helper_call_native_lib_FPR_VOID(env, host_address, 1)
helper_call_native_lib_FPR_VOID(env, host_address, 2)
helper_call_native_lib_FPR_VOID(env, host_address, 3)
helper_call_native_lib_FPR_VOID(env, host_address, 4)
helper_call_native_lib_FPR_VOID(env, host_address, 5)
helper_call_native_lib_FPR_VOID(env, host_address, 6)

helper_call_native_lib_FPR_GPR(env, host_address, 0)
helper_call_native_lib_FPR_GPR(env, host_address, 1)
helper_call_native_lib_FPR_GPR(env, host_address, 2)
helper_call_native_lib_FPR_GPR(env, host_address, 3)
helper_call_native_lib_FPR_GPR(env, host_address, 4)

helper_call_native_lib_FPR_GPR_VOID(env, host_address, 0)
helper_call_native_lib_FPR_GPR_VOID(env, host_address, 1)
helper_call_native_lib_FPR_GPR_VOID(env, host_address, 2)
helper_call_native_lib_FPR_GPR_VOID(env, host_address, 3)
helper_call_native_lib_FPR_GPR_VOID(env, host_address, 4)
#endif
void HELPER(exit_atomic)(CPUArchState *env)
{
    cpu_loop_exit_atomic(env_cpu(env), GETPC());
}
