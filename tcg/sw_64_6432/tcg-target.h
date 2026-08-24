/*
 * Initial TCG Implementation for sw_64
 *
 */

#ifndef SW_64_TCG_TARGET_H
#define SW_64_TCG_TARGET_H

#define TCG_TARGET_INSN_UNIT_SIZE  4
#define TCG_TARGET_TLB_DISPLACEMENT_BITS 16 
#define TCG_TARGET_REG_BITS 64

typedef enum {
    TCG_REG_X0, TCG_REG_X1, TCG_REG_X2, TCG_REG_X3,
    TCG_REG_X4, TCG_REG_X5, TCG_REG_X6, TCG_REG_X7,
    TCG_REG_X8, TCG_REG_X9, TCG_REG_X10, TCG_REG_X11,
    TCG_REG_X12, TCG_REG_X13, TCG_REG_X14, TCG_REG_X15,
    TCG_REG_X16, TCG_REG_X17, TCG_REG_X18, TCG_REG_X19,
    TCG_REG_X20, TCG_REG_X21, TCG_REG_X22, TCG_REG_X23,
    TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27,
    TCG_REG_X28, TCG_REG_X29, TCG_REG_X30, TCG_REG_X31, 

    TCG_REG_F0=32, TCG_REG_F1, TCG_REG_F2, TCG_REG_F3,
    TCG_REG_F4, TCG_REG_F5, TCG_REG_F6, TCG_REG_F7,
    TCG_REG_F8, TCG_REG_F9, TCG_REG_F10, TCG_REG_F11,
    TCG_REG_F12, TCG_REG_F13, TCG_REG_F14, TCG_REG_F15,
    TCG_REG_F16, TCG_REG_F17, TCG_REG_F18, TCG_REG_F19,
    TCG_REG_F20, TCG_REG_F21, TCG_REG_F22, TCG_REG_F23,
    TCG_REG_F24, TCG_REG_F25, TCG_REG_F26, TCG_REG_F27,
    TCG_REG_F28, TCG_REG_F29, TCG_REG_F30, TCG_REG_F31,

    /* Aliases.  */
    TCG_REG_FP = TCG_REG_X15,
    TCG_REG_RA = TCG_REG_X26,
    TCG_REG_GP = TCG_REG_X29,
    TCG_REG_SP = TCG_REG_X30,
    TCG_REG_ZERO = TCG_REG_X31,
    TCG_AREG0  = TCG_REG_X9,
} TCGReg;

#define TCG_TARGET_NB_REGS 64

/* used for function call generation */
#define TCG_REG_CALL_STACK              TCG_REG_SP
#define TCG_TARGET_STACK_ALIGN          16
#define TCG_TARGET_CALL_ALIGN_ARGS      1
#define TCG_TARGET_CALL_STACK_OFFSET    0
#define TCG_TARGET_HAS_direct_jump      1
#define TCG_TARGET_HAS_goto_ptr         1
#if defined(CONFIG_RET_OPT) && defined(__sw_64__)
#define TCG_TARGET_HAS_ret 1
#endif
#define TCG_TARGET_HAS_qemu_st8_i32     0
#define TCG_TARGET_HAS_div_i32          1
#define TCG_TARGET_HAS_movcond_i32      1
#define TCG_TARGET_HAS_movcond_i64	1
#define TCG_TARGET_HAS_rem_i32		1
#define TCG_TARGET_HAS_add2_i32		0
#define TCG_TARGET_HAS_sub2_i32		0
#define TCG_TARGET_HAS_mulu2_i32	0
#define TCG_TARGET_HAS_muluh_i32	0
#define	TCG_TARGET_HAS_muls2_i32 	0
#define TCG_TARGET_HAS_mulsh_i32	0
#define TCG_TARGET_HAS_andc_i32		1
#define TCG_TARGET_HAS_eqv_i32 		1
#define TCG_TARGET_HAS_nand_i32 	0	// no need, will be translated to 2 insn
#define TCG_TARGET_HAS_nor_i32		0	// no need, will be translated to 2 insn
#define TCG_TARGET_HAS_ctpop_i32	1 //cout 1
#define TCG_TARGET_HAS_div_i64		1
#define TCG_TARGET_HAS_rem_i64		1
#if defined(CONFIG_FUNC_OPT24) && defined(__sw_64__)
#define TCG_TARGET_HAS_udivl_i64        1
#define TCG_TARGET_HAS_ureml_i64        1
#endif
#define TCG_TARGET_HAS_div2_i64		0
#define TCG_TARGET_HAS_rot_i32		1
#define TCG_TARGET_HAS_rot_i64		1
#define TCG_TARGET_HAS_orc_i32		1
#define TCG_TARGET_HAS_orc_i64		1
#define TCG_TARGET_HAS_neg_i32          1
#define TCG_TARGET_HAS_neg_i64          1
#define TCG_TARGET_HAS_extract_i32	1
#define TCG_TARGET_HAS_extract_i64	1
#define TCG_TARGET_HAS_deposit_i32 	1
#define TCG_TARGET_HAS_deposit_i64	1
#define TCG_TARGET_HAS_sextract_i32	1
#define TCG_TARGET_HAS_extract2_i32	1
#define TCG_TARGET_HAS_sextract_i64	1
#define TCG_TARGET_HAS_extract2_i64	1
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
#define TCG_TARGET_HAS_extrl_i64_i32    1
#define TCG_TARGET_HAS_extrh_i64_i32    1
#else
#define TCG_TARGET_HAS_extrl_i64_i32	0
#define TCG_TARGET_HAS_extrh_i64_i32	0
#endif
#define TCG_TARGET_HAS_ext8s_i32	1
#define TCG_TARGET_HAS_ext16s_i32	1
#define TCG_TARGET_HAS_ext8u_i32 	1
#define TCG_TARGET_HAS_ext16u_i32 	1
#define TCG_TARGET_HAS_ext8s_i64	1
#define TCG_TARGET_HAS_ext16s_i64	1
#define TCG_TARGET_HAS_ext32s_i64	1
#define TCG_TARGET_HAS_ext8u_i64	1
#define TCG_TARGET_HAS_ext16u_i64	1
#define TCG_TARGET_HAS_ext32u_i64	1
#define TCG_TARGET_HAS_bswap16_i32 	1
#define TCG_TARGET_HAS_bswap32_i32 	1
#define TCG_TARGET_HAS_bswap16_i64	1
#define TCG_TARGET_HAS_bswap32_i64	1
#define TCG_TARGET_HAS_bswap64_i64	1
#define	TCG_TARGET_HAS_not_i32		1
#define TCG_TARGET_HAS_not_i64		1
#define TCG_TARGET_HAS_andc_i64		1
#define TCG_TARGET_HAS_eqv_i64		1 // equivalence,true
#define TCG_TARGET_HAS_nand_i64		0 // result = ~(x1 & x2)
#define TCG_TARGET_HAS_nor_i64		0 //nor x3, x1, x2   // x3 = ~(x1 | x2)   (Bitwise NOR)
#define TCG_TARGET_HAS_clz_i32 		1
#define TCG_TARGET_HAS_ctz_i32 		1
#define TCG_TARGET_HAS_clz_i64		1
#define TCG_TARGET_HAS_ctz_i64		1
#define TCG_TARGET_HAS_ctpop_i64	1
#define TCG_TARGET_HAS_add2_i64		0
#define TCG_TARGET_HAS_sub2_i64		0
#define TCG_TARGET_HAS_mulu2_i64	0
#define TCG_TARGET_HAS_muls2_i64	0
#define TCG_TARGET_HAS_muluh_i64	1
#define TCG_TARGET_HAS_mulsh_i64	1
#define TCG_TARGET_DEFAULT_MO (0)
#if defined(CONFIG_INDIRECT_ORACLE_TOP1)
#define TCG_TARGET_HAS_oracle_top1      1
#endif
#if defined(CONFIG_INDIRECT_ORACLE_TOP2)
#define TCG_TARGET_HAS_oracle_top2      1
#endif
#if defined(CONFIG_INDIRECT_HYPERCHAIN)
#define TCG_TARGET_HAS_hyperchain      1
#endif
#define TCG_TARGET_HAS_MEMORY_BSWAP     0
/* optional instructions */
void tb_target_set_jmp_target(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
#if defined(CONFIG_RET_OPT) && defined(__sw_64__)
void patch_pbrp(TranslationBlock *tb, TranslationBlock *next_tb);
void patch_pbrp_reset(TranslationBlock *tb);
#endif
#if defined(CONFIG_INDIRECT_ORACLE_TOP1)
void patch_oracle_top1(TranslationBlock *tb, TranslationBlock *target_tb);
#endif
#if defined(CONFIG_INDIRECT_ORACLE_TOP2)
void patch_oracle_top2(TranslationBlock *tb, TranslationBlock *target_tb,
                       int index);
#endif
#if defined(CONFIG_INDIRECT_HYPERCHAIN)
void patch_hyperchain(TranslationBlock *tb, TranslationBlock *target_tb,
                      int index);
void patch_hyperchain_reset(TranslationBlock *tb, int index);
#endif
#ifdef CONFIG_SOFTMMU
#define TCG_TARGET_NEED_LDST_LABELS
#endif
#define TCG_TARGET_NEED_POOL_LABELS
#endif /* SW_64_TCG_TARGET_H */
