/*
 * Initial TCG Implementation for sw_64
 *
 */

#include "../tcg-pool.c.inc"
#include "qemu/bitops.h"

/* We're going to re-use TCGType in setting of the SF bit, which controls
   the size of the operation performed.  If we know the values match, it
   makes things much cleaner.  */
QEMU_BUILD_BUG_ON(TCG_TYPE_I32 != 0 || TCG_TYPE_I64 != 1);

#ifdef CONFIG_DEBUG_TCG
static const char * const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
    "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
    "X8", "X9", "X10", "X11", "X12", "X13", "X14", "fp",
    "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
    "X24", "X25", "X26", "X27", "X28", "X29", "Xsp", "X31",

    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
};
#endif /* CONFIG_DEBUG_TCG */

static const int tcg_target_reg_alloc_order[] = {
    /* TCG_REG_X9 qemu saved for AREG0*/
#if defined(CONFIG_REG_OPT)
    TCG_REG_X22, TCG_REG_X23, /* TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27, */
    TCG_REG_X0, TCG_REG_X1, TCG_REG_X2, TCG_REG_X3, TCG_REG_X4,
    TCG_REG_X5, /*TCG_REG_X6, TCG_REG_X7,*/
#else
    TCG_REG_X10, TCG_REG_X11, TCG_REG_X12, TCG_REG_X13, TCG_REG_X14,
    TCG_REG_X0, TCG_REG_X1, TCG_REG_X2, TCG_REG_X3, TCG_REG_X4, 
    TCG_REG_X5, TCG_REG_X6, TCG_REG_X7, TCG_REG_X8,

    TCG_REG_X22, TCG_REG_X23, /* TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27, */
#endif
    /* TCG_REG_SP=TCG_REG_X15 saved for system*/
    TCG_REG_X16, TCG_REG_X17, TCG_REG_X18, TCG_REG_X19, TCG_REG_X20, TCG_REG_X21, TCG_REG_X28, /* TCG_REG_X29, TCG_REG_X30, TCG_REG_X31 */

    /* TCG_REG_TMP=TCG_REG_X27 reserved as temporary register */
    /* TCG_REG_TMP2=TCG_REG_X25 reserved as temporary register */
    /* TCG_REG_TMP3=TCG_REG_X24 reserved as temporary register */
    /* TCG_REG_RA=TCG_REG_X26 reserved as temporary */
    /* TCG_REG_GP=TCG_REG_X29 gp saved for system*/
    /* TCG_REG_SP=TCG_REG_X30 sp saved for system*/
    /* TCG_REG_ZERO=TCG_REG_X31 zero saved for system*/

    TCG_REG_F2, TCG_REG_F3, TCG_REG_F4, TCG_REG_F5, TCG_REG_F6, TCG_REG_F7, TCG_REG_F8, TCG_REG_F9,  /* f2-f9 saved registers */
    /* TCG_VEC_TMP=TCG_REG_F10, TCG_VEC_TMP2=TCG_REG_F11, are saved as temporary */ 
    TCG_REG_F12, TCG_REG_F13, TCG_REG_F14, TCG_REG_F15,  /* f10-f15 temporary registers */
    
    TCG_REG_F22, TCG_REG_F23, TCG_REG_F24, TCG_REG_F25, TCG_REG_F26, TCG_REG_F27, TCG_REG_F28, TCG_REG_F29, TCG_REG_F30,  /* f22-f30 temporary registers */
    /* TCG_REG_F31, zero saved for system */
    
    TCG_REG_F16, TCG_REG_F17, TCG_REG_F18, TCG_REG_F19, TCG_REG_F20, TCG_REG_F21,  /* input args */
    
    TCG_REG_F0, TCG_REG_F1, /*output args */
};

static const int tcg_target_call_iarg_regs[6] = {
    TCG_REG_X16, TCG_REG_X17, TCG_REG_X18, TCG_REG_X19, TCG_REG_X20, TCG_REG_X21, 
};
static const int tcg_target_call_oarg_regs[1] = {
    TCG_REG_X0,
};

#define TCG_REG_TMP TCG_REG_X27
#define TCG_REG_TMP2 TCG_REG_X25
#define TCG_REG_TMP3 TCG_REG_X24
#define TCG_FLOAT_TMP TCG_REG_F10
#define TCG_FLOAT_TMP2 TCG_REG_F11

#define tcg_out_insn_jump tcg_out_insn_ldst
#define tcg_out_insn_bitReg tcg_out_insn_simpleReg
#define zeroExt 0
#define sigExt  1
#define noPara 0//represent this parament of function isnot needed.

#ifndef CONFIG_SOFTMMU
    #define USE_GUEST_BASE  (guest_base != 0 || TARGET_LONG_BITS == 32)
    #define TCG_REG_GUEST_BASE TCG_REG_X14
#endif

static bool reloc_pc21(tcg_insn_unit *src_rw, const tcg_insn_unit *target)
{
    const tcg_insn_unit *src_rx = tcg_splitwx_to_rx(src_rw);
    ptrdiff_t offset = target - src_rx -1;

    if (offset == sextract64(offset, 0, 21)) {
        /* read instruction, mask away previous PC_REL21 parameter contents,
           set the proper offset, then write back the instruction. */
        *src_rw = deposit32(*src_rw, 0, 21, offset);
        return true;
    }
    // TCG_MAX_INSNS = 512 TCG_MAX_TEMPS = 512
    // tcg_op_buf_full  tcg_ctx->nb_ops is 4000
    printf("%s %s error, TCG_MAX_INSNS is too large\n",__FILE__,__func__);
    exit(-1);
    return false;
}


static bool patch_reloc(tcg_insn_unit *code_ptr, int type, intptr_t value, intptr_t addend)
{
    tcg_debug_assert(addend == 0);
    switch (type) {
    case R_SW_64_BRADDR:
        value = value;
        return reloc_pc21(code_ptr, (const tcg_insn_unit *)value);
    default:
        g_assert_not_reached();
    }
}

/*
* refer to mips
* contact with "tcg-target-con-str.h"
*/
#define TCG_CT_CONST_ZERO 0x100
#define TCG_CT_CONST_LONG 0x200
#define TCG_CT_CONST_MONE 0x400
#define TCG_CT_CONST_ORRI 0x800
#define TCG_CT_CONST_WORD 0X1000
#define TCG_CT_CONST_U8 0x2000
#define TCG_CT_CONST_S8 0X4000

#if defined(CONFIG_AND_OPT)
#define TCG_CT_CONST_S9 0x10
#endif
#if defined(CONFIG_ADD1_OPT)
#define TCG_CT_CONST_U8_2 0x20
#endif
#if defined(__sw_64__)
#define TCG_CT_CONST_S16 0x8000
#endif

#define ALL_GENERAL_REGS  0xffffffffu
#define ALL_VECTOR_REGS   0xffffffff00000000ull


#ifdef CONFIG_SOFTMMU
    #define ALL_QLDST_REGS \
        (ALL_GENERAL_REGS & ~((1 << TCG_REG_X0) | (1 << TCG_REG_X1) | \
                          (1 << TCG_REG_X2) | (1 << TCG_REG_X3)))
#else
    #define ALL_QLDST_REGS   ALL_GENERAL_REGS
#endif

/* sw test if a constant matches the constraint */
static int tcg_target_const_match(tcg_target_long val, TCGType type,
                                  const TCGArgConstraint *arg_ct)
{
    int ct = arg_ct->ct;

    if (ct & TCG_CT_CONST) {
        return 1;
    }
    if (type == TCG_TYPE_I32) {
        val = (int32_t)val;
    }
    if ((ct & TCG_CT_CONST_U8) && 0 <= val && val <= 255) {
        return 1;
    }
#if defined(CONFIG_AND_OPT)
    if ((ct & TCG_CT_CONST_S9) && -256 <= val && val <= 255) {
        return 1;
    }
#endif
#if defined(CONFIG_ADD1_OPT)
    if ((ct & TCG_CT_CONST_U8_2) && -255 <= val && val <= 255) {
        return 1;
    }
#endif
#if defined(CONFIG_ADD2_OPT)
    if ((ct & TCG_CT_CONST_S16) && -0x8000 <= val && val <= 0x7fff) {
        return 1;
    }
#endif
#if defined(TARGET_SW64)
    if ((ct & TCG_CT_CONST_S16) ) {
        return 1;
    }
#endif
    if ((ct & TCG_CT_CONST_LONG) ) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_MONE) ) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_ORRI) ) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_WORD) ) {
        return 1;
    }
    if ((ct & TCG_CT_CONST_ZERO) && val == 0) {
        return 1;
    }
    return 0;
}


/* We encode the format of the insn into the beginning of the name, so that
   we can have the preprocessor help "typecheck" the insn vs the output
   function.  Arm didn't provide us with nice names for the formats, so we
   use the section number of the architecture reference manual in which the
   instruction group is described.  */
#define OPC_OP(x)     ((( x ) & 0x3f) << 26)
#define OPC_FUNC(x)   ((( x ) & 0xff) << 5)
#define OPC_FUNC_COMPLEX(x)   ((( x ) & 0xff) << 10)
typedef enum {
    OPC_NOP       =0X43ff075f,
    OPC_SYS_CALL  =OPC_OP(0x00),
    OPC_CALL      =OPC_OP(0x01),
    OPC_RET       =OPC_OP(0x02),
    OPC_JMP       =OPC_OP(0x03),
    OPC_BR        =OPC_OP(0x04),
    OPC_BSR       =OPC_OP(0x05),
    OPC_PRI_RET   =OPC_OP(0x07),
    OPC_LDWE      =OPC_OP(0x09),
    OPC_LDSE      =OPC_OP(0x0A),
    OPC_LDDE      =OPC_OP(0x0B),
    OPC_VLDS      =OPC_OP(0x0C),
    OPC_VLDD      =OPC_OP(0x0D),
    OPC_VSTS      =OPC_OP(0x0E),
    OPC_VSTD      =OPC_OP(0x0F),
    
    OPC_LDBU      =OPC_OP(0x20),
    OPC_LDHU      =OPC_OP(0x21),
    OPC_LDW       =OPC_OP(0x22),
    OPC_LDL       =OPC_OP(0x23),
    OPC_LDL_U     =OPC_OP(0x24),
    OPC_FLDS      =OPC_OP(0X26),
    OPC_PRI_LD    =OPC_OP(0x25),
    OPC_FLDD      =OPC_OP(0X27),
    OPC_STB       =OPC_OP(0X28),
    OPC_STH       =OPC_OP(0x29),
    OPC_STW       =OPC_OP(0x2a),
    OPC_STL       =OPC_OP(0x2B),
    OPC_STL_U     =OPC_OP(0x2C),
    OPC_PRI_ST    =OPC_OP(0x2D),
    OPC_FSTS      =OPC_OP(0x2E),
    OPC_FSTD      =OPC_OP(0x2F),
    
    OPC_BEQ       =OPC_OP(0x30),
    OPC_BNE       =OPC_OP(0x31),
    OPC_BLT       =OPC_OP(0x32),
    OPC_BLE       =OPC_OP(0x33),
    OPC_BGT       =OPC_OP(0x34),
    OPC_BGE       =OPC_OP(0x35),
    OPC_BLBC      =OPC_OP(0x36),
    OPC_BLBS      =OPC_OP(0x37),
    
    OPC_FBEQ      =OPC_OP(0x38),
    OPC_FBNE      =OPC_OP(0x39),
    OPC_FBLT      =OPC_OP(0x3A),
    OPC_FBLE      =OPC_OP(0x3B),
    OPC_FBGT      =OPC_OP(0x3C),
    OPC_FBGE      =OPC_OP(0x3D),
    OPC_LDI       =OPC_OP(0x3E),
    OPC_LDIH      =OPC_OP(0x3F),
     
    OPC_ADDW        =(OPC_OP(0x10) | OPC_FUNC(0x0)),
    OPC_ADDW_I      =(OPC_OP(0x12) | OPC_FUNC(0x0)),
    OPC_SUBW        =(OPC_OP(0x10) | OPC_FUNC(0x1)),
    OPC_SUBW_I      =(OPC_OP(0x12) | OPC_FUNC(0x1)),
    OPC_S4ADDW      =(OPC_OP(0x10) | OPC_FUNC(0x02)),
    OPC_S4ADDW_I    =(OPC_OP(0x12) | OPC_FUNC(0x02)),
    OPC_S4SUBW      =(OPC_OP(0x10) | OPC_FUNC(0x03)),
    OPC_S4SUBW_I    =(OPC_OP(0x12) | OPC_FUNC(0x03)),
    
    OPC_S8ADDW      =(OPC_OP(0x10) | OPC_FUNC(0x04)),
    OPC_S8ADDW_I    =(OPC_OP(0x12) | OPC_FUNC(0x04)),
    OPC_S8SUBW      =(OPC_OP(0x10) | OPC_FUNC(0x05)),
    OPC_S8SUBW_I    =(OPC_OP(0x12) | OPC_FUNC(0x05)),
    
    OPC_ADDL        =(OPC_OP(0x10) | OPC_FUNC(0x8)),
    OPC_ADDL_I      =(OPC_OP(0x12) | OPC_FUNC(0x8)),
    OPC_SUBL        =(OPC_OP(0x10) | OPC_FUNC(0x9)),
    OPC_SUBL_I      =(OPC_OP(0x12) | OPC_FUNC(0x9)),
    
    OPC_S4ADDL      =(OPC_OP(0x10) | OPC_FUNC(0xA)),
    OPC_S4ADDL_I    =(OPC_OP(0x12) | OPC_FUNC(0xA)),
    OPC_S4SUBL      =(OPC_OP(0x10) | OPC_FUNC(0xB)),
    OPC_S4SUBL_I    =(OPC_OP(0x12) | OPC_FUNC(0xB)),
    
    OPC_S8ADDL      =(OPC_OP(0x10) | OPC_FUNC(0xC)),
    OPC_S8ADDL_I    =(OPC_OP(0x12) | OPC_FUNC(0xC)),
    OPC_S8SUBL      =(OPC_OP(0x10) | OPC_FUNC(0xD)),
    OPC_S8SUBL_I    =(OPC_OP(0x12) | OPC_FUNC(0xD)),
    
    OPC_MULW        =(OPC_OP(0x10) | OPC_FUNC(0x10)),
    OPC_MULW_I      =(OPC_OP(0x12) | OPC_FUNC(0x10)),
    OPC_MULL        =(OPC_OP(0x10) | OPC_FUNC(0x18)),
    OPC_MULL_I      =(OPC_OP(0x12) | OPC_FUNC(0x18)),
    
    OPC_UMULH       =(OPC_OP(0x10) | OPC_FUNC(0x19)), 
    OPC_UMULH_I     =(OPC_OP(0x12) | OPC_FUNC(0x19)),
    
    OPC_CTPOP       =(OPC_OP(0x10) | OPC_FUNC(0x58)), 
    OPC_CTLZ        =(OPC_OP(0x10) | OPC_FUNC(0x59)), 
    OPC_CTTZ        =(OPC_OP(0x10) | OPC_FUNC(0x5A)), 
    
    OPC_ZAP         =(OPC_OP(0x10) | OPC_FUNC(0x68)),
    OPC_ZAP_I       =(OPC_OP(0x12) | OPC_FUNC(0x68)),
    OPC_ZAPNOT      =(OPC_OP(0x10) | OPC_FUNC(0x69)),
    OPC_ZAPNOT_I    =(OPC_OP(0x12) | OPC_FUNC(0x69)),
    
    OPC_SEXTB       =(OPC_OP(0x10) | OPC_FUNC(0x6A)),
    OPC_SEXTB_I     =(OPC_OP(0x12) | OPC_FUNC(0x6A)),
    OPC_SEXTH       =(OPC_OP(0x10) | OPC_FUNC(0x6B)),
    OPC_SEXTH_I     =(OPC_OP(0x12) | OPC_FUNC(0x6B)),
    
    OPC_CMPEQ       =(OPC_OP(0x10) | OPC_FUNC(0x28)),
    OPC_CMPEQ_I     =(OPC_OP(0x12) | OPC_FUNC(0x28)),
    
    OPC_CMPLT       =(OPC_OP(0x10) | OPC_FUNC(0x29)),
    OPC_CMPLT_I     =(OPC_OP(0x12) | OPC_FUNC(0x29)),
    OPC_CMPLE       =(OPC_OP(0x10) | OPC_FUNC(0x2A)),
    OPC_CMPLE_I     =(OPC_OP(0x12) | OPC_FUNC(0x2A)),
    
    OPC_CMPULT      =(OPC_OP(0x10) | OPC_FUNC(0x2B)),
    OPC_CMPULT_I    =(OPC_OP(0x12) | OPC_FUNC(0x2B)),
    OPC_CMPULE      =(OPC_OP(0x10) | OPC_FUNC(0x2C)),
    OPC_CMPULE_I    =(OPC_OP(0x12) | OPC_FUNC(0x2C)),
    
    OPC_AND         =(OPC_OP(0x10) | OPC_FUNC(0x38)),
    OPC_BIC         =(OPC_OP(0x10) | OPC_FUNC(0x39)),
    OPC_BIS         =(OPC_OP(0x10) | OPC_FUNC(0x3A)),
    OPC_ORNOT       =(OPC_OP(0x10) | OPC_FUNC(0x3B)),
    OPC_XOR         =(OPC_OP(0x10) | OPC_FUNC(0x3C)),
    OPC_EQV         =(OPC_OP(0x10) | OPC_FUNC(0x3D)),

    OPC_AND_I       =(OPC_OP(0x12) | OPC_FUNC(0x38)),
    OPC_BIC_I       =(OPC_OP(0x12) | OPC_FUNC(0x39)),
    OPC_BIS_I       =(OPC_OP(0x12) | OPC_FUNC(0x3A)),
    OPC_ORNOT_I     =(OPC_OP(0x12) | OPC_FUNC(0x3B)),
    OPC_XOR_I       =(OPC_OP(0x12) | OPC_FUNC(0x3C)),
    OPC_EQV_I       =(OPC_OP(0x12) | OPC_FUNC(0x3D)),
    
    OPC_SLL         =(OPC_OP(0x10) | OPC_FUNC(0x48)),
    OPC_SRL         =(OPC_OP(0x10) | OPC_FUNC(0x49)),
    OPC_SRA         =(OPC_OP(0x10) | OPC_FUNC(0x4A)),
    OPC_SLL_I       =(OPC_OP(0x12) | OPC_FUNC(0x48)),
    OPC_SRL_I       =(OPC_OP(0x12) | OPC_FUNC(0x49)),
    OPC_SRA_I       =(OPC_OP(0x12) | OPC_FUNC(0x4A)),
    
    OPC_SELEQ       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x00)),
    OPC_SELGE       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x01)),
    OPC_SELGT       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x02)),
    OPC_SELLE       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x03)),
    OPC_SELLT       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x04)),
    OPC_SELNE       =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x05)),
    OPC_SELLBC      =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x06)),
    OPC_SELLBS      =(OPC_OP(0x11) | OPC_FUNC_COMPLEX(0x07)),
    OPC_SELEQ_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x00)),
    OPC_SELGE_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x01)),
    OPC_SELGT_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x02)),
    OPC_SELLE_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x03)),
    OPC_SELLT_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x04)),
    OPC_SELNE_I     =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x05)),
    OPC_SELLBC_I    =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x06)),
    OPC_SELLBS_I    =(OPC_OP(0x13) | OPC_FUNC_COMPLEX(0x07)),
     
    OPC_INS0B       =(OPC_OP(0x10) | OPC_FUNC(0x40)),
    OPC_INS1B       =(OPC_OP(0x10) | OPC_FUNC(0x41)),
    OPC_INS2B       =(OPC_OP(0x10) | OPC_FUNC(0x42)),
    OPC_INS3B       =(OPC_OP(0x10) | OPC_FUNC(0x43)),
    OPC_INS4B       =(OPC_OP(0x10) | OPC_FUNC(0x44)),
    OPC_INS5B       =(OPC_OP(0x10) | OPC_FUNC(0x45)),
    OPC_INS6B       =(OPC_OP(0x10) | OPC_FUNC(0x46)),
    OPC_INS7B       =(OPC_OP(0x10) | OPC_FUNC(0x47)),
    OPC_INS0B_I     =(OPC_OP(0x12) | OPC_FUNC(0x40)),
    OPC_INS1B_I     =(OPC_OP(0x12) | OPC_FUNC(0x41)),
    OPC_INS2B_I     =(OPC_OP(0x12) | OPC_FUNC(0x42)),
    OPC_INS3B_I     =(OPC_OP(0x12) | OPC_FUNC(0x43)),
    OPC_INS4B_I     =(OPC_OP(0x12) | OPC_FUNC(0x44)),
    OPC_INS5B_I     =(OPC_OP(0x12) | OPC_FUNC(0x45)),
    OPC_INS6B_I     =(OPC_OP(0x12) | OPC_FUNC(0x46)),
    OPC_INS7B_I     =(OPC_OP(0x12) | OPC_FUNC(0x47)),
          
    OPC_EXTLB       =(OPC_OP(0x10) | OPC_FUNC(0x50)),
    OPC_EXTLH       =(OPC_OP(0x10) | OPC_FUNC(0x51)),
    OPC_EXTLW       =(OPC_OP(0x10) | OPC_FUNC(0x52)),
    OPC_EXTLL       =(OPC_OP(0x10) | OPC_FUNC(0x53)),
    OPC_EXTHB       =(OPC_OP(0x10) | OPC_FUNC(0x54)),
    OPC_EXTHH       =(OPC_OP(0x10) | OPC_FUNC(0x55)),
    OPC_EXTHW       =(OPC_OP(0x10) | OPC_FUNC(0x56)),
    OPC_EXTHL       =(OPC_OP(0x10) | OPC_FUNC(0x57)),
    OPC_EXTLB_I     =(OPC_OP(0x12) | OPC_FUNC(0x50)),
    OPC_EXTLH_I     =(OPC_OP(0x12) | OPC_FUNC(0x51)),
    OPC_EXTLW_I     =(OPC_OP(0x12) | OPC_FUNC(0x52)),
    OPC_EXTLL_I     =(OPC_OP(0x12) | OPC_FUNC(0x53)),
    OPC_EXTHB_I     =(OPC_OP(0x12) | OPC_FUNC(0x54)),
    OPC_EXTHH_I     =(OPC_OP(0x12) | OPC_FUNC(0x55)),
    OPC_EXTHW_I     =(OPC_OP(0x12) | OPC_FUNC(0x56)),
    OPC_EXTHL_I     =(OPC_OP(0x12) | OPC_FUNC(0x57)),
    
    OPC_MASKLB      =(OPC_OP(0x10) | OPC_FUNC(0x60)),
    OPC_MASKLH      =(OPC_OP(0x10) | OPC_FUNC(0x61)),
    OPC_MASKLW      =(OPC_OP(0x10) | OPC_FUNC(0x62)),
    OPC_MASKLL      =(OPC_OP(0x10) | OPC_FUNC(0x63)),
    OPC_MASKHB      =(OPC_OP(0x10) | OPC_FUNC(0x64)),
    OPC_MASKHH      =(OPC_OP(0x10) | OPC_FUNC(0x65)),
    OPC_MASKHW      =(OPC_OP(0x10) | OPC_FUNC(0x66)),
    OPC_MASKHL      =(OPC_OP(0x10) | OPC_FUNC(0x67)),
    OPC_MASKLB_I    =(OPC_OP(0x12) | OPC_FUNC(0x60)),
    OPC_MASKLH_I    =(OPC_OP(0x12) | OPC_FUNC(0x61)),
    OPC_MASKLW_I    =(OPC_OP(0x12) | OPC_FUNC(0x62)),
    OPC_MASKLL_I    =(OPC_OP(0x12) | OPC_FUNC(0x63)),
    OPC_MASKHB_I    =(OPC_OP(0x12) | OPC_FUNC(0x64)),
    OPC_MASKHH_I    =(OPC_OP(0x12) | OPC_FUNC(0x65)),
    OPC_MASKHW_I    =(OPC_OP(0x12) | OPC_FUNC(0x66)),
    OPC_MASKHL_I    =(OPC_OP(0x12) | OPC_FUNC(0x67)),
    
    OPC_CNPGEB      =(OPC_OP(0x10) | OPC_FUNC(0x6C)),
    OPC_CNPGEB_I    =(OPC_OP(0x12) | OPC_FUNC(0x6C)),

    OPC_MEMB        =(OPC_OP(0x06) | OPC_FUNC(0x0)),
    OPC_RTC         =(OPC_OP(0x06) | OPC_FUNC(0x20)),

    /*float insn*/
    OPC_RFPCR = (OPC_OP(0x18) | OPC_FUNC(0x50)),
    OPC_WFPCR = (OPC_OP(0x18) | OPC_FUNC(0x51)),
    OPC_SETFPEC0 = (OPC_OP(0x18) | OPC_FUNC(0x54)),
    OPC_SETFPEC1 = (OPC_OP(0x18) | OPC_FUNC(0x55)),
    OPC_SETFPEC2 = (OPC_OP(0x18) | OPC_FUNC(0x56)),
    OPC_SETFPEC3 = (OPC_OP(0x18) | OPC_FUNC(0x57)),


    OPC_IFMOVS = (OPC_OP(0x18) | OPC_FUNC(0x40)),
    OPC_IFMOVD = (OPC_OP(0x18) | OPC_FUNC(0x41)),
    OPC_FIMOVS = (OPC_OP(0x10) | OPC_FUNC(0x70)),
    OPC_FIMOVD = (OPC_OP(0x10) | OPC_FUNC(0x78)),
    
    /*translate S--D*/
    /*translate S/D--Long*/
    OPC_FCVTSD = (OPC_OP(0x18) | OPC_FUNC(0x20)),
    OPC_FCVTDS = (OPC_OP(0x18) | OPC_FUNC(0x21)),
    OPC_FCVTDL_G = (OPC_OP(0x18) | OPC_FUNC(0x22)),
    OPC_FCVTDL_P = (OPC_OP(0x18) | OPC_FUNC(0x23)),
    OPC_FCVTDL_Z = (OPC_OP(0x18) | OPC_FUNC(0x24)),
    OPC_FCVTDL_N = (OPC_OP(0x18) | OPC_FUNC(0x25)),
    OPC_FCVTDL = (OPC_OP(0x18) | OPC_FUNC(0x27)),
    OPC_FCVTLS = (OPC_OP(0x18) | OPC_FUNC(0x2D)),
    OPC_FCVTLD = (OPC_OP(0x18) | OPC_FUNC(0x2F)),


    OPC_FADDS = (OPC_OP(0x18) | OPC_FUNC(0x00)),
    OPC_FADDD = (OPC_OP(0x18) | OPC_FUNC(0x01)),
    OPC_FSUBS = (OPC_OP(0x18) | OPC_FUNC(0x02)),
    OPC_FSUBD = (OPC_OP(0x18) | OPC_FUNC(0x03)),
    OPC_FMULS = (OPC_OP(0x18) | OPC_FUNC(0x04)),
    OPC_FMULD = (OPC_OP(0x18) | OPC_FUNC(0x05)),
    OPC_FDIVS = (OPC_OP(0x18) | OPC_FUNC(0x06)),
    OPC_FDIVD = (OPC_OP(0x18) | OPC_FUNC(0x07)),
    OPC_FSQRTS = (OPC_OP(0x18) | OPC_FUNC(0x08)),
    OPC_FSQRTD = (OPC_OP(0x18) | OPC_FUNC(0x09)),
}SW_64Insn;


static inline uint32_t tcg_in32(TCGContext *s)
{
    uint32_t v = *(uint32_t *)s->code_ptr;
    return v;
}

/* SW instruction format of syscall
 * insn = opcode[31,26]:Function[25,0],
 */                                     
static void tcg_out_insn_syscall(TCGContext *s, SW_64Insn insn, intptr_t imm26)
{   
    tcg_debug_assert(imm26 == sextract64(imm26, 0 ,26));                                  
    tcg_out32(s, insn | (imm26 & 0x3ffffff));
}


/* SW instruction format of br(alias jump)
* insn = opcode[31,26]:Rd[25,21]:disp[20,0],
*/ 
static void tcg_out_insn_br(TCGContext *s, SW_64Insn insn, TCGReg rd, intptr_t imm64)
{
    tcg_debug_assert( imm64 <= 0xfffff && imm64 >= -0x100000 );
    tcg_out32(s, insn | (rd & 0x1f) << 21 | (imm64 & 0x1fffff));
}


/* SW instruction format of (load and store)
 * insn = opcode[31,26]:rd[25,21]:rn[20,16]:disp[15,0]
 */                                     
static void tcg_out_insn_ldst(TCGContext *s, SW_64Insn insn, TCGReg rd, TCGReg rn, intptr_t imm16)
{                                     
    tcg_debug_assert( imm16 <= 0x7fff && imm16 >= -0x8000 );
    tcg_out32(s, insn | (rd & 0x1f) << 21 | (rn & 0x1f) << 16 | (imm16 & 0xffff) );
}

/* SW instruction format of simple operator for Register
 * insn = opcode[31,26]:rn(ra)[25,21]:rn(rb)[20,16]:Zeors[15,13]:function[12,5]:rd(rc)[4,0]
 */          
                           
static void tcg_out_insn_simpleReg(TCGContext *s, SW_64Insn insn,TCGReg rd, TCGReg rn, TCGReg rm)
{                                     
    tcg_out32(s, insn | (rn & 0x1f) << 21 | (rm & 0x1f) << 16 | (rd & 0x1f));
}

/* SW instruction format of simple operator for imm
 * insn = opcode[31,26]:rn(ra)[25,21]:disp[20,13]:function[12,5]:rd(rc)[4,0]
 */                                     
static void tcg_out_simple(TCGContext *s, SW_64Insn insn_Imm, SW_64Insn insn_Reg, TCGReg rd, TCGReg rn, intptr_t imm64)
{            
    if( imm64 <= 0x7f && imm64 >= -0x80 ){	
        tcg_out32(s, insn_Imm | (rn & 0x1f) << 21 | (imm64 & 0xff) << 13 | (rd & 0x1f));
    }else{
    	tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP3, imm64);
	tcg_out_insn_simpleReg(s, insn_Reg, rd, rn, TCG_REG_TMP3);
    }   
}


static void tcg_out_insn_simpleImm(TCGContext *s, SW_64Insn insn_Imm, TCGReg rd, TCGReg rn, unsigned long imm64)
{
    tcg_debug_assert( imm64 <= 255 );
    tcg_out32(s, insn_Imm | (rn & 0x1f) << 21 | (imm64 & 0xff) << 13  | (rd & 0x1f) );
}


/*
* sw bit operation: and bis etc
*/
static void tcg_out_bit(TCGContext *s, SW_64Insn insn_Imm, SW_64Insn insn_Reg, TCGReg rd, TCGReg rn, unsigned long imm64)
{
    if( imm64 <= 255 ){
        tcg_out32(s, insn_Imm | (rn & 0x1f) << 21 | (imm64 & 0xff) << 13  | (rd & 0x1f) );
    }else{
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP, imm64);
        tcg_out_insn_bitReg(s, insn_Reg, rd, rn, TCG_REG_TMP);
    }
}


/* SW instruction format of complex operator
 * insn = opcode[31,26]:rd[25,21]:rn[20,16],function[15,10]:rm[9,5]:rx[4,0]
 */                                     
static void tcg_out_insn_complexReg(TCGContext *s, SW_64Insn insn, TCGReg cond, TCGReg rd, TCGReg rn, TCGReg rm)
{                                     
    tcg_out32(s, insn | (cond & 0x1f) << 21 | (rn & 0x1f) << 16 | (rm & 0x1f) << 5 | (rd & 0x1f));
}


static void tcg_out_insn_complexImm(TCGContext *s, SW_64Insn insn, TCGReg cond, TCGReg rd, intptr_t imm8, TCGReg rm)
{                                     
    tcg_out32(s, insn | (cond & 0x1f) << 21 | (imm8 & 0xff) << 13 | (rm & 0x1f) << 5 | (rd & 0x1f));
}


/*SW Register to register move using ADDL*/
static void tcg_out_movr(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn)
{
    if (ext == TCG_TYPE_I64) {
        tcg_out_insn_simpleReg(s, OPC_BIS, rd, rn, TCG_REG_ZERO);
    } else {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rn, 0xf);
    }
}


/*sw
 *put imm into rd
 */
static void tcg_out_movi( TCGContext *s, TCGType type, TCGReg rd, tcg_target_long orig)
{
    tcg_target_long l0=0, l1=0, l2=0, l3=0, extra=0;
    tcg_target_long val = orig;
    TCGReg rs = TCG_REG_ZERO;

    if (TCG_TARGET_REG_BITS == 64 && type == TCG_TYPE_I32) {
       val = (int32_t)val;//val64bit
    }

    if (orig == (int16_t)orig) {
       tcg_out_insn_ldst(s, OPC_LDI, rd, TCG_REG_ZERO, (int16_t)orig);
       return;
    }    
   
    if (orig == (uint8_t)orig) {
       tcg_out_insn_simpleImm(s, OPC_BIS_I, rd, TCG_REG_ZERO, (uint8_t)orig);
       return;
    }

    if ( type == TCG_TYPE_I32 ) {
        val = (int32_t)val;
    }

    l0 = (int16_t)val;
    val = (val - l0) >> 16;
    l1 = (int16_t)val;

    if ( orig >> 31 == -1 || orig >> 31 == 0 ) {
        if ( l1 < 0 && orig >= 0) {
            extra = 0x4000;
            l1 = (int16_t)(val - 0x4000);
        }
    } else {
        val = (val - l1) >> 16;
        l2 = (int16_t)val;
        val = (val - l2) >> 16;
        l3 = (int16_t)val;

        if (l3) {
            tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, l3);
            rs = rd;
        }
        if (l2) {
            tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l2);
            rs = rd;
        }
        if ( l3 || l2 )
            tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 32);
    }

    if (l1) {
        tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, l1);
        rs = rd;
    }    
    
    if (extra) {
        tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, extra);
        rs = rd;
    }

#if defined(CONFIG_MOVI_OPT)
    if (l0)
    {
        tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l0);
    }
#else
    tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l0);
#endif

    if ( type == TCG_TYPE_I32 )
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}


/*sw
 *put imm into rd
 */
/*static int bigaddr_jmp( TCGContext *s, TCGType type, TCGReg rd, tcg_target_long orig)
{
    tcg_target_long l0=0, l1=0, l2=0, l3=0, extra=0;
    tcg_target_long val = orig;
    TCGReg rs = TCG_REG_ZERO;
    int num_insn = 0;

    if (TCG_TARGET_REG_BITS == 64 && type == TCG_TYPE_I32) {
       val = (int32_t)val;//val64bit
    }

    if ( type == TCG_TYPE_I32 ) {
        val = (int32_t)val;
    }

    l0 = (int16_t)val;
    val = (val - l0) >> 16;
    l1 = (int16_t)val;

    if ( orig >> 31 == -1 || orig >> 31 == 0 ) {
        if ( l1 < 0 && orig >= 0) {
            extra = 0x4000;
            l1 = (int16_t)(val - 0x4000);
        }
    } else {
        val = (val - l1) >> 16;
        l2 = (int16_t)val;
        val = (val - l2) >> 16;
        l3 = (int16_t)val;

        if (l3) {
            tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, l3);
            rs = rd;
            num_insn++;
        }
        if (l2) {
            tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l2);
            rs = rd;
            num_insn++;
        }
        if ( l3 || l2 )
            tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 32);
            num_insn++;
    }

    if (l1) {
        tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, l1);
        rs = rd;
        num_insn++;
    }    
    
    if (extra) {
        tcg_out_insn_ldst(s, OPC_LDIH, rd, rs, extra);
        rs = rd;
        num_insn++;
    }

    tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l0);
    num_insn++;
    return num_insn;
}*/


static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    if (ret == arg) {
        return true;
    }
    switch (type) {
    case TCG_TYPE_I32:
    case TCG_TYPE_I64:
        if (ret < 32 && arg < 32) {
            tcg_out_movr(s, type, ret, arg);
            break;
        } else if (ret < 32) {
#if defined(TARGET_SW64)
            tcg_out32(s, OPC_FIMOVD | (arg & 0x1f) << 21 | 0x1f << 16 | (ret & 0x1f));
#else
            tcg_debug_assert(0);
#endif
            break;
        } else if (arg < 32) {
#if defined(TARGET_SW64)
            tcg_out32(s, OPC_IFMOVD | (arg & 0x1f) << 21 | 0x1f << 16 | (ret & 0x1f));
#else
            tcg_debug_assert(0);
#endif
            break;
        }
        /* FALLTHRU */
    case TCG_TYPE_V64:
    case TCG_TYPE_V128:
        tcg_debug_assert(0);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

static inline void tcg_out_sxt(TCGContext *s, TCGType ext, MemOp s_bits,
                               TCGReg rd, TCGReg rn)
{
    /* Using ALIASes SXTB, SXTH, SXTW, of SBFM Xd, Xn, #0, #7|15|31 
    int bits = (8 << s_bits) - 1;
    tcg_out_sbfm(s, ext, rd, rn, 0, bits);
    */
    switch(s_bits){
        case MO_8:
	    tcg_out_insn_simpleReg(s, OPC_SEXTB, rd, TCG_REG_ZERO, rn);
	    break;
	case MO_16:
	    tcg_out_insn_simpleReg(s, OPC_SEXTH, rd, TCG_REG_ZERO, rn);
	    break;
	case MO_32:
	    tcg_out_insn_simpleReg(s, OPC_ADDW, rd, rn, TCG_REG_ZERO);
	    break;
	default:
            tcg_debug_assert(0);
	    break;
    }
    if (ext == TCG_TYPE_I32) {
       tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}

/*
* counting heading/tailing zero numbers
* when rn != 0, counting rn heading/tailing zero numbers
* when rn == 0 , mov b to rd
*/
static void tcg_out_ctz64(TCGContext *s, SW_64Insn opc, TCGReg rd, TCGReg rn, TCGArg b, bool const_b)
{
    /* cond1. b is a const, b=32 */
    if (const_b && b == 64) {
        if ( opc == OPC_CTLZ){
            tcg_out_insn_simpleReg(s, OPC_CTLZ, rd, TCG_REG_ZERO, rn);//rd=rn[63:0](heading zero)
        }else //opc==OPC_CTTZ
        {
            tcg_out_insn_simpleReg(s, OPC_CTTZ, rd, TCG_REG_ZERO, rn);//rd=rn[63:0](tailing zero)
        }
    }else{
        if (opc == OPC_CTLZ){
            tcg_out_insn_simpleReg(s, OPC_CTLZ, TCG_REG_TMP2, TCG_REG_ZERO, rn);//tmp2=rn[63:0](heading zero)
        }else //opc==OPC_CTTZ
        {
            tcg_out_insn_simpleReg(s, OPC_CTTZ, TCG_REG_TMP2, TCG_REG_ZERO, rn);//tmp2=rn[63:0](tailing zero)
        }
        if(const_b){
            if(b == -1){
            /* cond2. b is const and b=-1 */
            /* if rn != 0 , rd= counting rn heading/tailing zero numbers, else rd = 0xffffffffffffffff*/
                tcg_out_insn_bitReg(s, OPC_ORNOT, rd, TCG_REG_ZERO, TCG_REG_ZERO);
                //if rn!=0, rd=tmp2(rn[63:0] heading/tailing zero),else rd=-1
                tcg_out_insn_complexReg(s, OPC_SELNE, rn, rd, TCG_REG_TMP2, rd);
	    }else if (b == 0){
                /* cond3. b is const and b=0 */
               /* if rn != 0 , rd=counting rn heading/tailing zero numbers , else rd = TCG_REG_ZERO */
               tcg_out_insn_complexReg(s, OPC_SELNE, rn, rd, TCG_REG_TMP2, TCG_REG_ZERO);
	   } else {
                /* cond4. b is const */
               tcg_out_movi(s, TCG_TYPE_I64, rd, b);
               /* if rn != 0 , rd=counting rn heading/tailing zero numbers , else mov b to rd */
               tcg_out_insn_complexReg(s, OPC_SELNE, rn, rd, TCG_REG_TMP2, rd);
            }
	}
        else{
            /* if b is register */
            /* if rn !=0, rd = counting rn heading/tailing zero numbers ,else rd= b*/
            tcg_out_insn_complexReg(s, OPC_SELNE, rn, rd, TCG_REG_TMP2, b);
       }
    }
}


/*
* counting heading/tailing zero numbers
*/
static void tcg_out_ctz32(TCGContext *s, SW_64Insn opc, TCGReg rd, TCGReg rn, TCGArg b, bool const_b)
{
    tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_TMP, rn, 0xf);//tmp=rn[31:0]

   /* cond1. b is a const, b=32 */
    if (const_b && b == 32) {
        if ( opc == OPC_CTLZ){
            tcg_out_insn_simpleReg(s, OPC_CTLZ, rd, TCG_REG_ZERO, TCG_REG_TMP);//rd=rn[31:0](heading zero)
            tcg_out_insn_simpleImm(s, OPC_SUBW_I, rd, rd, 32);//rd=rd-32
        }else //opc==OPC_CTTZ
        {
            tcg_out_insn_simpleReg(s, OPC_CTTZ, rd, TCG_REG_ZERO, TCG_REG_TMP);//rd=rn[31:0](tailing zero)
            //if TCG_REG_TMP==0, rd=32, else ,rd=rd=rn[31:0](tailing zero)
            tcg_out_insn_complexImm(s, OPC_SELEQ_I, TCG_REG_TMP, rd, 32, rd);
        }
    }
    else{
        if (opc == OPC_CTLZ){
            tcg_out_insn_simpleReg(s, OPC_CTLZ, TCG_REG_TMP2, TCG_REG_ZERO, TCG_REG_TMP);//tmp2=rn[31:0](heading zero)
            tcg_out_insn_simpleImm(s, OPC_SUBW_I, TCG_REG_TMP2, TCG_REG_TMP2, 32);//tmp2=tmp2-32
        }else //opc==OPC_CTTZ
        {
            tcg_out_insn_simpleReg(s, OPC_CTTZ, TCG_REG_TMP2, TCG_REG_ZERO, TCG_REG_TMP);//tmp2=rn[31:0](tailing zero)
            //if TCG_REG_TMP==0, TMP2=32, else ,TMP2=TCG_REG_TMP2=rn[31:0](tailing zero)
            tcg_out_insn_complexImm(s, OPC_SELEQ_I, TCG_REG_TMP, TCG_REG_TMP2, 32, TCG_REG_TMP2);
        }
        if(const_b){
            if(b == -1){
            /* cond2. b is const and b=-1 */
            /* if rn != 0 , rd= counting rn heading/tailing zero numbers, else rd = 0xffffffffffffffff*/
                tcg_out_insn_bitReg(s, OPC_ORNOT, rd, TCG_REG_ZERO, TCG_REG_ZERO);
                //if rn!=0, rd=tmp2(rn[31:0] heading/tailing zero),else rd=-1
                tcg_out_insn_complexReg(s, OPC_SELNE, TCG_REG_TMP, rd, TCG_REG_TMP2, rd);
	    }
	    else if (b == 0){
                /* cond3. b is const and b=0 */
               /* if rn != 0 , rd=counting rn heading/tailing zero numbers , else rd = TCG_REG_ZERO */
               tcg_out_insn_complexReg(s, OPC_SELNE, TCG_REG_TMP, rd, TCG_REG_TMP2, TCG_REG_ZERO);
	   } else {
                /* cond4. b is const */
               tcg_out_movi(s, TCG_TYPE_I32, rd, b);
               /* if rn != 0 , rd=counting rn heading/tailing zero numbers , else mov b to rd */
               tcg_out_insn_complexReg(s, OPC_SELNE, TCG_REG_TMP, rd, TCG_REG_TMP2, rd);
            }
	}
        else{
            /* if b is register */
            /* if rn !=0, rd = counting rn heading/tailing zero numbers ,else rd= b*/
            tcg_out_insn_complexReg(s, OPC_SELNE, TCG_REG_TMP, rd, TCG_REG_TMP2, b);
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
       }
    }
}


/*
* memory protect for order of (ld and st)
*/
static void tcg_out_mb(TCGContext *s)
{
    tcg_out32(s, OPC_MEMB);
}


/*
* rd <- number of "1" in rn
*/
static inline void tcg_out_ctpop(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn)
{
    if (ext == TCG_TYPE_I64) {
        tcg_out_insn_bitReg(s, OPC_CTPOP, rd, TCG_REG_ZERO, rn);
    } else {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_TMP, rn, 0xf);//tmp=rn[31:0]
        tcg_out_insn_bitReg(s, OPC_CTPOP, rd, TCG_REG_ZERO, TCG_REG_TMP);
    }
}


/*
* rn = 0xfedcba9876543210,rd=0xdcfe98ba54761032
*/
static inline void tcg_out_bswap16(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn)
{
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP2, rn, 1); //TCG_REG_TMP2=0x32

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 0); //TMP=0x10
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 8); //TMP=0x1000
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x0000000000001032
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 3); //TMP=0x76
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 16); //TMP=0x760000
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x0000000000761032
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 2); //TMP=0x54
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 24); //TMP=0x54000000
    if (ext == TCG_TYPE_I32) {
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP); //rd=0x0000000054761032
    } else {

        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x0000000054761032

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 5); //TMP=0xba
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 32); //TMP=0xba00000000
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x000000ba54751032

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 4); //TMP=0x98
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 40); //TMP=0x980000000000
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x000098ba75000000

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 7); //TMP=0xfe
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 48); //TMP=0xfe000000000000
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); //TCG_REG_TMP2=0x00fe98ba54761032

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 6); //tmp=0xdc
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 56); //TCG_REG_TMP2=0xdc00000000000000
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP); //rd=0xdcfe98ba54761032
    }
}


/*
* rn = 0xfedcba9876543210,rd=0xfedcba9810325476
*/
static void tcg_out_bswap32(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn)
{
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP2, rn, 3); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 2); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 8); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 1); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 16); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 0); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 24);

    if(ext == TCG_TYPE_I32){
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP); 
    } else {
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 7); 
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 32); 
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 6); 
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 40); 
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 5); 
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 48); 
        tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

        tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 4); 
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 56); 
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP); 
    }
}



/*
* rn = 0xfedcba9876543210,rd=0x1032547698badcfe
*/
static void tcg_out_bswap64(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn)
{
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP2, rn, 7); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 6); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 8); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 5); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 16); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 
    
    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 4); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 24);
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 3); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 32); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 2); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 40); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 1); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 48); 
    tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_TMP); 

    tcg_out_insn_simpleImm(s, OPC_EXTLB_I, TCG_REG_TMP, rn, 0); 
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, 56); 
    tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP); 
}


/*
* extract rn[lsb+len-1, lsb] ->  rd[len-1, 0]
*/
static void tcg_out_extract(TCGContext *s, TCGReg rd, TCGReg rn, int lsb, int len)
{
    tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rn, lsb);
    tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 64-len);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rd, 64-len);
}

#if defined(CONFIG_EXTRACT_OPT)
static void tcg_out_extract_opt(TCGContext *s, TCGReg rd, TCGReg rn, int lsb, int len)
{
    if(lsb % 8 == 0 && len % 8 == 0) {
        if(lsb != 0)
            tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rn, lsb);
        unsigned int flag = (int)(pow(2, len / 8) - 1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, flag);
    }else { 
    	tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rn, lsb);
    	tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 64-len);
    	tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rd, 64-len);
    }
}
#endif
/*sw 20220829
* extract rn[lsb+len-1,lsb] ->  rd[len-1,0]
* sign extension according to rd[len-1]
*/
static void tcg_out_sextract(TCGContext *s, TCGReg rd, TCGReg rn, int lsb, int len)
{
    /* extract rn[lsb+len-1,lsb] ->  rd[len-1,0] */
    tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rn, lsb);
    tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 64-len);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, rd, rd, 64-len);

    /* sign extension */
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rn, 64-len-lsb);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, TCG_REG_TMP2, 63);
    tcg_out_insn_simpleImm(s, OPC_CMPEQ_I, TCG_REG_TMP2, TCG_REG_TMP2, 0);
    tcg_insn_unit * label_ptr = s->code_ptr;
    tcg_out_insn_br(s, OPC_BGT, TCG_REG_ZERO, 0);

    /* when rd[lsb+len-1] = 1 , TCG_REG_TMP2 =0, rd sign extension  */
    //get 111..111..0000
    tcg_out_insn_bitReg(s, OPC_ORNOT, TCG_REG_TMP, TCG_REG_ZERO, TCG_REG_ZERO);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, TCG_REG_TMP, lsb + len);
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, lsb + len);
    tcg_out_insn_bitReg(s, OPC_BIS, rd, rn, TCG_REG_TMP);

    /* when rd[lsb+len-1] = 0 , TCG_REG_TMP2 =1, no need to sign extension 
    reloc_pc21(label_ptr, s->code_ptr) modify bgt to jump to next insn */
    reloc_pc21(label_ptr, s->code_ptr);
}


/*sw 20220826
* bits(datasize) operand1 = rn;
* bits(datasize) operand2 = rm;
* bits(2*datasize) concat = operand1:operand2;
* rd = concat<lsb+datasize-1:lsb>
*/
static inline void tcg_out_extract2(TCGContext *s, TCGType ext, TCGReg rd,
                                TCGReg rn, TCGReg rm, unsigned int lsb) 
{
    unsigned int bits = ext ? 64 : 32;
    tcg_debug_assert( lsb >=0 && lsb <= bits);
    /* get rm[63, lsb]-->TCG_REG_TMP[63-lsb, 0] */
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, rm, lsb); //Logical right

    /* get rn[lsb, 0]-->TCG_REG_TMP2[63-lsb, lsb] */
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rn,  64 -lsb); //Logical Left

    /* get rn[lsb,0]:rm[63,lsb] -->rd[63, 0] */
    tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP2, TCG_REG_TMP);
    if(ext == TCG_TYPE_I32){
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}



/*sw 20210616
* depos: rd = rd[63:msb+1]:rn[msb,lsb]:rd[lsb-1,0]
* len = msb -lsb + 1
*/
static void tcg_out_dep(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, int lsb, int len)
{
    //get 000..111..0000
    tcg_out_insn_bitReg(s, OPC_ORNOT, TCG_REG_TMP, TCG_REG_ZERO, TCG_REG_ZERO);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, TCG_REG_TMP, 64 - len);
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, lsb);
    
    /* TCG_REG_TMP2 = rn[msb,lsb] */
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rn, 64-len);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, TCG_REG_TMP2, 64-len-lsb);

    /* clear rd[msb,lsb] */
    tcg_out_insn_bitReg(s, OPC_BIC, rd, rd, TCG_REG_TMP);
    /* rd = rd[63:msb+1]:rn[msb,lsb]:rd[lsb-1,0] */
    tcg_out_insn_bitReg(s, OPC_BIS, rd, rd, TCG_REG_TMP2);

    if(ext == TCG_TYPE_I32)
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    } 
}

#if defined(CONFIG_DEPOSIT_OPT)
static void tcg_out_dep_opt(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, int lsb, int len)
{
    if(lsb == 0 && len % 8 == 0) { 
        unsigned int flag1 = (1 << (len / 8)) - 1;
        tcg_out_insn_simpleImm(s, OPC_ZAP_I, rd, rd, flag1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_TMP2, rn, flag1);
    }else if(lsb % 8 == 0 && (len==8||len==16||len==32||len==64)){
        unsigned int flag2 = ((1 << (len / 8)) - 1) << (lsb / 8);
        tcg_out_insn_simpleImm(s, OPC_ZAP_I, rd, rd, flag2);
        switch(len){
        case 8:
            tcg_out_insn_simpleImm(s, OPC_INS0B_I, TCG_REG_TMP2, rn, lsb/8);
            break;
        case 16:
            tcg_out_insn_simpleImm(s, OPC_INS1B_I, TCG_REG_TMP2, rn, lsb/8);
            break;
        case 32:
            tcg_out_insn_simpleImm(s, OPC_INS2B_I, TCG_REG_TMP2, rn, lsb/8);
            break;
        case 64:
            tcg_out_insn_simpleImm(s, OPC_INS3B_I, TCG_REG_TMP2, rn, lsb/8);
            break;
        }
    }else {
    //get 000..111..0000
    tcg_out_insn_bitReg(s, OPC_ORNOT, TCG_REG_TMP, TCG_REG_ZERO, TCG_REG_ZERO);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, TCG_REG_TMP, 64 - len);
    if (lsb != 0)
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, TCG_REG_TMP, lsb);
    /* clear rd[msb,lsb] */
    tcg_out_insn_bitReg(s, OPC_BIC, rd, rd, TCG_REG_TMP);

    /* TCG_REG_TMP2 = rn[msb,lsb] */
    tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rn, 64-len);
    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, TCG_REG_TMP2, 64-len-lsb);
    }

    /* rd = rd[63:msb+1]:rn[msb,lsb]:rd[lsb-1,0] */
    tcg_out_insn_bitReg(s, OPC_BIS, rd, rd, TCG_REG_TMP2);

    if(ext == TCG_TYPE_I32)
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    } 
}
#endif
/*sw 20210617
* get val_s64(rn) * val_s64(rm) -> res_128
* res[127:64] -> rd
* warn:maybe rd=rn or rm
*/
static void tcg_out_mulsh64(TCGContext *s,  TCGReg rd, TCGReg rn, TCGReg rm)
{
    tcg_out_insn_simpleReg(s, OPC_UMULH, TCG_REG_TMP, rn, rm);

    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2,  rn, 63);
    tcg_out_insn_complexReg(s, OPC_SELEQ, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_ZERO, rm);
    tcg_out_insn_simpleReg(s, OPC_SUBL, TCG_REG_TMP, TCG_REG_TMP, TCG_REG_TMP2);

    tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, rm, 63);
    tcg_out_insn_complexReg(s, OPC_SELEQ, TCG_REG_TMP2, TCG_REG_TMP2, TCG_REG_ZERO, rn);
    tcg_out_insn_simpleReg(s, OPC_SUBL, rd, TCG_REG_TMP, TCG_REG_TMP2);
}

static void tcg_out_sar(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, TCGArg a2, bool c2)
{
    unsigned int bits = ext ? 64 : 32;
    unsigned int max = bits - 1;
    if(ext == TCG_TYPE_I32){
        tcg_out_insn_simpleReg(s, OPC_ADDW, TCG_REG_TMP, rn, TCG_REG_ZERO);

        if (c2) {
            tcg_out_insn_simpleImm(s, OPC_SRA_I, rd, TCG_REG_TMP, a2&max);
        } else {
            tcg_out_insn_bitReg(s, OPC_SRA, rd, TCG_REG_TMP, a2);
        }
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    
    }else{
        if (c2) {
            tcg_out_insn_simpleImm(s, OPC_SRA_I, rd, rn, a2&max);
        } else {
            tcg_out_insn_bitReg(s, OPC_SRA, rd, rn, a2);
        }
   }
}

#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
static void tcg_out_ld_i128(TCGContext *s, TCGReg rd, TCGReg rn, intptr_t offset)
{
    if (offset != sextract64(offset, 0, 16)) {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP2, offset);
        tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_TMP2, TCG_REG_TMP2, rn); 
        tcg_out_insn_ldst(s, OPC_VLDD, rd, TCG_REG_TMP2, 0);
    } else {
        tcg_out_insn_ldst(s, OPC_VLDD, rd, rn, offset);
    }    
    //zapnot rd
}
static void tcg_out_st_i128(TCGContext *s, TCGReg rd, TCGReg rn, intptr_t offset)
{
    //zapnot rd
    if (offset != sextract64(offset, 0, 16)) {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP2, offset);
        tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_TMP2, TCG_REG_TMP2, rn); 
        tcg_out_insn_ldst(s, OPC_VSTD, rd, TCG_REG_TMP2, 0);
    } else {
        tcg_out_insn_ldst(s, OPC_VSTD, rd, rn, offset);
    }    
    //zapnot
}
static void tcg_out_vec_op(TCGContext *s, TCGOpcode opc,
                           unsigned vecl, unsigned vece,
                           const TCGArg args[TCG_MAX_OP_ARGS],
                           const int const_args[TCG_MAX_OP_ARGS])
{
    /*static const AArch64Insn cmp_vec_insn[16] = {
        [TCG_COND_EQ] = I3616_CMEQ,
        [TCG_COND_GT] = I3616_CMGT,
        [TCG_COND_GE] = I3616_CMGE,
        [TCG_COND_GTU] = I3616_CMHI,
        [TCG_COND_GEU] = I3616_CMHS,
    };
    static const AArch64Insn cmp_scalar_insn[16] = {
    };
    static const AArch64Insn cmp0_vec_insn[16] = {
    };
    static const AArch64Insn cmp0_scalar_insn[16] = {
    };

    TCGType type = vecl + TCG_TYPE_V64;
    unsigned is_q = vecl;
    bool is_scalar = !is_q && vece == MO_64;
    int cmode, imm8;*/

    TCGArg a0, a1, a2, a3;
    a0 = args[0];
    a1 = args[1];
    a2 = args[2];

    switch (opc) {
    case INDEX_op_ld_i128:
        tcg_out_ld_i128(s, a0, a1, a2);
        break;
    case INDEX_op_st_i128:
        tcg_out_st_i128(s, a0, a1, a2);
        break;
    default:
        break;
    }
}
#endif
/*
* memory <=> Reg in (B H W L) bytes
*/
static void tcg_out_ldst(TCGContext *s, SW_64Insn insn, TCGReg rd, TCGReg rn, intptr_t offset, bool sign)
{
    if (offset != sextract64(offset, 0, 16)) {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP2, offset);
        tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_TMP2, TCG_REG_TMP2, rn);
        tcg_out_insn_ldst(s, insn, rd, TCG_REG_TMP2, 0);
    }else{
        tcg_out_insn_ldst(s, insn, rd, rn, offset);
    }

    switch (insn){
        case OPC_LDBU:
             if(sign)
                 tcg_out_insn_simpleReg(s, OPC_SEXTB, rd, TCG_REG_ZERO, rd);//for micro-op:INDEX_op_ld8s_i32/64,set rd[63,8]=1
             break;
        case OPC_LDHU:
             if(sign)
                 tcg_out_insn_simpleReg(s, OPC_SEXTH, rd, TCG_REG_ZERO, rd);//for micro-op:INDEX_op_ld16s_i32/64,set rd[63,16]=1
             break;
        case OPC_LDW:
             if(!sign)
                 tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);//for micro-op:INDEX_op_ld32u_i32/64,set rd[63,32]=0
             break;
        default:
             break; 
	}
}


static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg rd, TCGReg rn, intptr_t ofs)
{
    switch (type) {
    case TCG_TYPE_I32:
        tcg_out_ldst(s, OPC_LDW, rd, rn, ofs, zeroExt);
        break;
    case TCG_TYPE_I64:
        if (rd < 32)
            tcg_out_ldst(s, OPC_LDL, rd, rn, ofs, sigExt);
        else
            tcg_out_ldst(s, OPC_FLDD, rd, rn, ofs, noPara);
        break;
    case TCG_TYPE_V64:
    case TCG_TYPE_V128:
        tcg_debug_assert(0);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_st(TCGContext *s, TCGType type, TCGReg rd,TCGReg rn, intptr_t ofs)
{
    switch (type) {
    case TCG_TYPE_I32:
    	tcg_out_ldst(s, OPC_STW, rd, rn, ofs, noPara);
        break;
    case TCG_TYPE_I64:
        if (rd < 32)
            tcg_out_ldst(s, OPC_STL, rd, rn, ofs, noPara);
        else
            tcg_out_ldst(s, OPC_FSTD, rd, rn, ofs, noPara);
        break;
    case TCG_TYPE_V64:
    case TCG_TYPE_V128:
        tcg_debug_assert(0);
        break;
    default:
        g_assert_not_reached();
    }
}


/* refer to aarch64
*  TCG_REG_TMP stores resulf_of_condition_compare
*/
static void tcg_out_cond_cmp(TCGContext *s, TCGType ext, TCGCond cond, TCGReg ret, TCGArg a, tcg_target_long b, bool const_b)
{
    //ret maybe TCG_REG_TMP
    //for b<0 or b >255
    if( const_b && ( b < 0 || b > 0xff) ){
        tcg_out_movi(s, ext, TCG_REG_TMP2, b);
	b = TCG_REG_TMP2;
	const_b = 0;
    }//end for b<0 || b >0xff

    if(ext == TCG_TYPE_I32){
	tcg_out_insn_simpleReg(s, OPC_ADDW, a, a, TCG_REG_ZERO);
	if(!const_b){
	    tcg_out_insn_simpleReg(s, OPC_ADDW, b, b, TCG_REG_ZERO);
        }else{
            b = (int32_t)b;
        }
    }

    if (const_b) { // 0 <= b <=255
        switch(cond){
            case TCG_COND_EQ:
	    case TCG_COND_NE:
                tcg_out_insn_simpleImm(s, OPC_CMPEQ_I, ret, a, b);
                break;
            case TCG_COND_LT:
            case TCG_COND_GE:
                tcg_out_insn_simpleImm(s, OPC_CMPLT_I, ret, a, b);
                break;
            case TCG_COND_LE:
            case TCG_COND_GT:
                tcg_out_insn_simpleImm(s, OPC_CMPLE_I, ret, a, b);
                break;
            case TCG_COND_LTU:
            case TCG_COND_GEU:
                tcg_out_insn_simpleImm(s, OPC_CMPULT_I, ret, a, b);
                break;
            case TCG_COND_LEU:
	    case TCG_COND_GTU:
                tcg_out_insn_simpleImm(s, OPC_CMPULE_I, ret, a, b);
                break;
            default:
                tcg_debug_assert(0);
                break;
        }
    } else {
	switch(cond){
	    case TCG_COND_EQ:
	    case TCG_COND_NE:
         	tcg_out_insn_simpleReg(s, OPC_CMPEQ, ret, a, b);
		break;
	    case TCG_COND_LT:
	    case TCG_COND_GE:
		tcg_out_insn_simpleReg(s, OPC_CMPLT, ret, a, b);
		break;
	    case TCG_COND_LE:
	    case TCG_COND_GT:
	 	tcg_out_insn_simpleReg(s, OPC_CMPLE, ret, a, b);
	 	break;
	    case TCG_COND_LTU:
	    case TCG_COND_GEU:
	  	tcg_out_insn_simpleReg(s, OPC_CMPULT, ret, a, b);
		break;
	    case TCG_COND_LEU:
	    case TCG_COND_GTU:
	 	tcg_out_insn_simpleReg(s, OPC_CMPULE, ret, a, b);
		break;
            default:
                tcg_debug_assert(0);
                break;
       }
    }

    if(ext == TCG_TYPE_I32){// for a pair of beginning of this function
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a, a, 0xf);
        if(!const_b){
	    tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, b, b, 0xf);
             
        }
    }
   

    switch(cond){
	case TCG_COND_NE:
        case TCG_COND_GE:
        case TCG_COND_GT:
        case TCG_COND_GEU:
        case TCG_COND_GTU:
            tcg_out_insn_simpleImm(s, OPC_XOR_I, ret, ret, 0x1);
	    break;
	case TCG_COND_ALWAYS:
	case TCG_COND_NEVER:
            tcg_debug_assert(0);
	    break;
	default:
	    break;
    }
}



/*sw
*step1 tcg_out_cmp() ,"eq" and "ne" in the same case with the same insn;
store compare result by TCG_REG_TMP, for step2;
step2: jump address with compare result. in last "switch" section, we diff qe/ne by different case with different insn.
*/
static void tcg_out_brcond(TCGContext *s, TCGType ext, TCGCond cond, TCGReg a, tcg_target_long b, bool b_const, TCGLabel *l)
{
    intptr_t offset;
    bool need_cmp;
    TCGReg TMP = TCG_REG_TMP;


    if (b_const && b == 0 && (cond == TCG_COND_EQ || cond == TCG_COND_NE)) {
        need_cmp = false;
        if (ext == TCG_TYPE_I32) {
           tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TMP, a, 0xf);
        } else {
          // tcg_out_insn_bitReg(s, OPC_BIS, TCG_REG_TMP, a, TCG_REG_ZERO);
	    TMP = a;
        }
    } else {
        need_cmp = true;
        tcg_out_cond_cmp(s, ext, cond, TMP, a, b, b_const);
    }

    if (!l->has_value) {
        tcg_out_reloc(s, s->code_ptr, R_SW_64_BRADDR, l, 0);
	offset=0;   //offset = tcg_in32(s) >> 5;
    } else {
        offset = tcg_pcrel_diff(s, l->u.value_ptr) ;
	offset = offset - 4; /* update pc = pc + 4 */
	offset = offset >> 2;
        tcg_debug_assert(offset == sextract64(offset, 0, 21));
    }

    if (need_cmp) {
        tcg_out_insn_br(s, OPC_BGT, TMP, offset); //a cond b,jmp
    } else if (cond == TCG_COND_EQ) {
        tcg_out_insn_br(s, OPC_BEQ, TMP, offset);
    } else {
        tcg_out_insn_br(s, OPC_BNE, TMP, offset);
    }
}

//if cond is successful, ret=1, otherwise ret = 0
static void tcg_out_setcond(TCGContext *s, TCGType ext, TCGCond cond, TCGReg ret,
                            TCGReg a, tcg_target_long b, bool const_b)
{
    switch(cond){
        case TCG_COND_EQ:
        case TCG_COND_LT:
        case TCG_COND_LE:
        case TCG_COND_LTU:
        case TCG_COND_LEU:
	case TCG_COND_NE:
        case TCG_COND_GE:
        case TCG_COND_GT:
        case TCG_COND_GEU:
        case TCG_COND_GTU:
            tcg_out_cond_cmp(s, ext, cond, ret, a, b, const_b);
            break;
	default:
            tcg_abort();
            break;
     }
}

//cond(a1,a2), yes:v1->ret, no:v2->ret
static void tcg_out_movcond(TCGContext *s, TCGType ext, TCGCond cond, TCGReg ret,
                            TCGReg a1, tcg_target_long a2, bool const_b, TCGReg v1, TCGReg v2)
{
    tcg_out_cond_cmp(s, ext, cond, TCG_REG_TMP, a1, a2, const_b);
    tcg_out_insn_complexReg(s, OPC_SELLBS, TCG_REG_TMP, ret, v1, v2);
}

#if defined(CONFIG_MOVCOND_OPT)
//cond(a1,a2), yes:v1->ret, no:v2->ret
static void tcg_out_movcond_opt(TCGContext *s, TCGType ext, TCGCond cond, TCGReg ret,
                            TCGReg a1, tcg_target_long a2, bool const_b, TCGReg v1, TCGReg v2)
{
    if (const_b && a2 == 0) {
        switch(cond){
        case TCG_COND_EQ:
            tcg_out_insn_complexReg(s, OPC_SELEQ, a1, ret, v1, v2);
            break;
        case TCG_COND_NE:
            tcg_out_insn_complexReg(s, OPC_SELNE, a1, ret, v1, v2);
            break;
        case TCG_COND_GE:
            tcg_out_insn_complexReg(s, OPC_SELGE, a1, ret, v1, v2);
            break;
        case TCG_COND_GT:
            tcg_out_insn_complexReg(s, OPC_SELGT, a1, ret, v1, v2);
            break;
        case TCG_COND_LT:
            tcg_out_insn_complexReg(s, OPC_SELLT, a1, ret, v1, v2);
            break;
        case TCG_COND_LE:
            tcg_out_insn_complexReg(s, OPC_SELLE, a1, ret, v1, v2);
            break;
        default:
            tcg_out_cond_cmp(s, ext, cond, TCG_REG_TMP, a1, a2, const_b);
            tcg_out_insn_complexReg(s, OPC_SELLBS, TCG_REG_TMP, ret, v1, v2);
        }
    } else {
        tcg_out_cond_cmp(s, ext, cond, TCG_REG_TMP, a1, a2, const_b);
        tcg_out_insn_complexReg(s, OPC_SELLBS, TCG_REG_TMP, ret, v1, v2);
    }
}
#endif


/*sw*/
static inline bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,TCGReg base, intptr_t ofs)
{
    if (type <= TCG_TYPE_I64 && val == 0) {
	tcg_out_st(s,  type, TCG_REG_ZERO, base, ofs);
        return true;
    }
    return false;
}
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
#define FCVTLD(out, in) tcg_out32(s, OPC_FCVTLD | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f)); 
#define FCVTLS(out, in) tcg_out32(s, OPC_FCVTLS | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f)); 
#define FCVTSD(out, in) tcg_out32(s, OPC_FCVTSD | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f)); 
#define FCVTDS(out, in) tcg_out32(s, OPC_FCVTDS | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f)); 
#define FCVTDL(out, in) tcg_out32(s, OPC_FCVTDL | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f));
#define FCVTDL_Z(out, in) tcg_out32(s, OPC_FCVTDL_Z | 0x1f << 21 | (in & 0x1f) << 16 | (out & 0x1f));
#endif

static void tcg_out_addsubi(TCGContext *s, int ext, TCGReg rd,TCGReg rn, int64_t imm64)
{
    if(ext == TCG_TYPE_I64){			
        if (imm64 >= 0) {
            if(imm64 <= 255){
	        /* we use tcg_out_insn_simpleImm because imm64 is between 0~255 */
                tcg_out_insn_simpleImm(s, OPC_ADDL_I, rd, rn, imm64); 
            }//aimm>0  && aimm == sextract64(aim, 0, 8)
#if defined(CONFIG_ADD2_OPT)
            else if (imm64 <= 0x7fff) {
                tcg_out_insn_ldst(s, OPC_LDI, rd, rn, imm64);
            }
#endif
            else{
                tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP, imm64);
                tcg_out_insn_simpleReg(s, OPC_ADDL, rd, rn, TCG_REG_TMP);
            }//aimm>0  && aimm != sextract64(aim, 0, 8)
        }else{
            if(-imm64 <= 255){
	        /* we use tcg_out_insn_simpleImm because -imm64 is between 0~255 */
                tcg_out_insn_simpleImm(s, OPC_SUBL_I, rd, rn, -imm64);
            }//aimm<0  && aimm == sextract64(aim, 0, 8)
#if defined(CONFIG_ADD2_OPT)
            else if (imm64 >= -0x8000) {
                tcg_out_insn_ldst(s, OPC_LDI, rd, rn, imm64);
            }
#endif
            else{
                tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP, -imm64);
                tcg_out_insn_simpleReg(s, OPC_SUBL, rd, rn, TCG_REG_TMP);
	    }//aimm<0  && aimm != sextract64(aim, 0, 8)
        }
    }else{//TCG_TYPE_I32
        if (imm64 >= 0) {
            if(0 <=imm64 && imm64 <= 255){
                /* we use tcg_out_insn_simpleImm because imm64 is between 0~255 */
                tcg_out_insn_simpleImm(s, OPC_ADDW_I, rd, rn, imm64); 
		tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
             }//aimm>0  && aimm == sextract64(aim, 0, 8)
            else{
                tcg_out_movi(s, TCG_TYPE_I32, TCG_REG_TMP, imm64);
                tcg_out_insn_simpleReg(s, OPC_ADDW, rd, rn, TCG_REG_TMP);
		tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
            }//aimm>0  && aimm != sextract64(aim, 0, 8)
        }else{
            if(0 < -imm64 && -imm64 <= 255){
                /* we use tcg_out_insn_simpleImm because -imm64 is between 0~255 */
                tcg_out_insn_simpleImm(s, OPC_SUBW_I, rd, rn, -imm64);
		tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
            }//aimm<0  && aimm == sextract64(aim, 0, 8)
            else{
                tcg_out_movi(s, TCG_TYPE_I32, TCG_REG_TMP, -imm64);
                tcg_out_insn_simpleReg(s, OPC_SUBW, rd, rn, TCG_REG_TMP);
		tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
            }//aimm<0  && aimm != sextract64(aim, 0, 8)
        }
    }	
}

#if defined(CONFIG_AND_OPT)
static void tcg_out_andori(TCGContext *s, SW_64Insn insn_Imm, SW_64Insn insn_Imm1, TCGReg rd,TCGReg rn, int64_t imm64)
{
    if (imm64 >= -256 && imm64 < 0) {
        tcg_out_insn_simpleImm(s, insn_Imm1, rd, rn, ~imm64);
    } else {
        tcg_out_insn_simpleImm(s, insn_Imm, rd, rn, imm64);
    }
}
#endif
#if defined(__sw_64__)
static void tcg_out_ldi(TCGContext *s, TCGReg rd,TCGReg rn, int64_t imm64)
{
    tcg_out32(s, OPC_LDI | (rd & 0x1f) << 21 | (rn & 0x1f) << 16 | (imm64 & 0xffff) );
}

static void tcg_out_ldih(TCGContext *s, TCGReg rd,TCGReg rn, int64_t imm64)
{
    imm64 = imm64 >> 16;
    tcg_out32(s, OPC_LDIH | (rd & 0x1f) << 21 | (rn & 0x1f) << 16 | (imm64 & 0xffff) );
}
#endif

static void tcg_out_goto(TCGContext *s, const tcg_insn_unit *target)
{
    ptrdiff_t offset = (tcg_pcrel_diff(s, target) - 4) >> 2;
    tcg_debug_assert(offset == sextract64(offset, 0, 21));
    tcg_out_insn_br(s, OPC_BR, TCG_REG_ZERO, offset);
}

static void tcg_out_goto_long(TCGContext *s, const tcg_insn_unit *target)
{
    ptrdiff_t offset = (tcg_pcrel_diff(s, target) - 4) >> 2;
    if ( offset == sextract64(offset, 0 ,21)) {
        tcg_out_insn_br(s, OPC_BR, TCG_REG_ZERO, offset);
    } else {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP, (intptr_t)target);
        tcg_out_insn_jump(s, OPC_JMP, TCG_REG_ZERO, TCG_REG_TMP, noPara);
    }
}


static void tcg_out_call(TCGContext *s, const tcg_insn_unit *target)
{
    ptrdiff_t offset = (tcg_pcrel_diff(s, target) - 4 ) >> 2;
    if (offset != sextract64(offset, 0, 21)) {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_TMP, (intptr_t)target);
        /* code load to cache L1 with share and clean mode*/
#if defined(CONFIG_DATA_PREFETCH)
        tcg_out_ldst(s, OPC_LDWE, TCG_REG_F31, TCG_REG_TMP, 0, 0);
#endif
    }

#if defined(CONFIG_REG_OPT)
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X8,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESP]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X6,  TCG_AREG0, offsetof(CPUX86State, regs[12]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X7,  TCG_AREG0, offsetof(CPUX86State, regs[13]));
    if((s->lookup_tb_ptr_addr != target) && (s->cc_compute_all_addr != target)){
        tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X10,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESI]));
        tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X11,  TCG_AREG0, offsetof(CPUX86State, regs[R_EDI]));
        tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X12,  TCG_AREG0, offsetof(CPUX86State, regs[R_EAX]));
        tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X13,  TCG_AREG0, offsetof(CPUX86State, regs[R_ECX]));
        tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X14,  TCG_AREG0, offsetof(CPUX86State, regs[R_EDX]));
    }
#endif
    if (offset == sextract64(offset, 0, 21)) {
        tcg_out_insn_br(s, OPC_BSR, TCG_REG_RA, offset);
    } else {
        tcg_out_insn_jump(s, OPC_CALL, TCG_REG_RA, TCG_REG_TMP, noPara);
    }
#if defined(CONFIG_REG_OPT)
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X8,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESP]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X6,  TCG_AREG0, offsetof(CPUX86State, regs[12]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X7,  TCG_AREG0, offsetof(CPUX86State, regs[13]));
    if((s->lookup_tb_ptr_addr != target) && (s->cc_compute_all_addr != target)){
        tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X10,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESI]));
        tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X11,  TCG_AREG0, offsetof(CPUX86State, regs[R_EDI]));
        tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X12,  TCG_AREG0, offsetof(CPUX86State, regs[R_EAX]));
        tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X13,  TCG_AREG0, offsetof(CPUX86State, regs[R_ECX]));
        tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X14,  TCG_AREG0, offsetof(CPUX86State, regs[R_EDX]));
    }
#endif
}


static void modify_direct_addr(uintptr_t addr, uintptr_t jmp_rw, uintptr_t jmp_rx)//modify jump addr in sw64, so addr is 48bit
{
    if(addr > 0x1000000000000 || addr < 0x100000000)
       tcg_debug_assert("modify_addr error\n");

    tcg_target_long l0=0, l1=0, l2=0;
    tcg_target_long val = addr;
    TCGReg rs = TCG_REG_ZERO;
    TCGReg rd = TCG_REG_TMP;
    tcg_insn_unit i_nop=OPC_NOP, i1=0, i2=0;
    uint64_t pair = 0;
    uintptr_t jmp = jmp_rw;

    l0 = (int16_t)val;
    val = (val - l0) >> 16;
    l1 = (int16_t)val;

    val = (val - l1) >> 16;
    l2 = (int16_t)val;
    
    
    //tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l2);
    i1 = OPC_LDI | (rd & 0x1f) << 21 | (rs & 0x1f) << 16 | (l2 & 0xffff);
    
    //tcg_out_insn_simpleImm(s, OPC_SLL_I, rd, rd, 32);
    i2 = OPC_SLL_I | (rd & 0x1f) << 21 | (32 & 0xff) << 13 | (rd & 0x1f);
    pair = (uint64_t)i2 << 32 | i1;
    qatomic_set((uint64_t *)jmp, pair);
    pair = 0;
    i1 = 0; 
    i2 = 0;
    jmp = jmp + 8;

    //tcg_out_insn_ldst(s, OPC_LDIH, rd, rd, l1);
    i1 = OPC_LDIH | (rd & 0x1f) << 21 | (rd & 0x1f) << 16 | (l1 & 0xffff);

    //tcg_out_insn_ldst(s, OPC_LDI, rd, rs, l0);
    i2 = OPC_LDI | (rd & 0x1f) << 21 | (rd & 0x1f) << 16 | (l0 & 0xffff);


    pair = (uint64_t)i2 << 32 | i1;
    qatomic_set((uint64_t *)jmp, pair);
    flush_idcache_range(jmp_rx, jmp_rw, 16);
}

/* TCG_TARGET_HAS_direct_jump */
void tb_target_set_jmp_target(uintptr_t tc_ptr, uintptr_t jmp_rx, uintptr_t jmp_rw, uintptr_t addr)
{
    tcg_insn_unit i1, i2;
    uint64_t pair;
    
    ptrdiff_t offset = addr - jmp_rx -1;
    
    if (offset == sextract64(offset, 0, 21)) {
        i1 = OPC_BR | (TCG_REG_ZERO & 0x1f) << 21| ((offset >> 2) & 0x1fffff);
	    i2 = OPC_NOP;
        pair = (uint64_t)i2 << 32 | i1;
        qatomic_set((uint64_t *)jmp_rw, pair);
        flush_idcache_range(jmp_rx, jmp_rw, 8); //not support no sw_64
    } else if(offset == sextract64(offset, 0, 32)){
        modify_direct_addr(addr, jmp_rw, jmp_rx);
    } else {
      tcg_debug_assert("tb_target");
    }
}


static inline void tcg_out_goto_label(TCGContext *s, TCGLabel *l)
{
    if (!l->has_value) {
        tcg_out_reloc(s, s->code_ptr, R_SW_64_BRADDR, l, 0);
        tcg_out_insn_br(s, OPC_BR, TCG_REG_ZERO, 0);
    } else {
        tcg_out_goto(s, l->u.value_ptr);
    }
}

/* 
 *  resut: rd=rn(64,64-m]:rm(64-m,0]
 * 1: rn(m,0]--->TCG_REG_TMP(64,64-m]
 * 2: rm(64,64-m]--->rm(64-m,0]
 * 3: rd=TCG_REG_TMP(64,64-m]:rm(64-m,0]
 */
static inline void tcg_out_extr(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, TCGReg rm, unsigned int m)
{
	int bits = ext ? 64 : 32;
	int max = bits - 1;
	tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, rn, bits - (m & max));
	tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, rm, (m & max));
	tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
}

/* sw 
 * loop right shift
 */
static inline void tcg_out_rotr_Imm(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, unsigned int m)
{
    unsigned int bits = ext ? 64 : 32;
    unsigned int max = bits - 1;
    if(ext == TCG_TYPE_I64)
    {
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, rn, bits - (m & max));
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, rn, (m & max));
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
    }
    else
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rn, 0xf);
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP, rd, bits - (m & max));
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP2, rd, (m & max));
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}

/* sw loop right shift
 */
static inline void tcg_out_rotr_Reg(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, TCGReg rm)
{
    unsigned int bits = ext ? 64 : 32;
    //get TCG_REG_TMP=64-[rm]
    tcg_out_insn_simpleImm(s, OPC_SUBL_I, TCG_REG_TMP, rm, bits);
    tcg_out_insn_bitReg(s, OPC_SUBL, TCG_REG_TMP, TCG_REG_ZERO, TCG_REG_TMP);

    if(ext == TCG_TYPE_I64)
    {
        tcg_out_insn_bitReg(s, OPC_SLL, TCG_REG_TMP2, rn, TCG_REG_TMP);  //get rn right part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_SRL, TCG_REG_TMP, rn, rm);   //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
    }
    else
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rn, 0xf);
        tcg_out_insn_bitReg(s, OPC_SLL, TCG_REG_TMP2, rd, TCG_REG_TMP);  //get rn right part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_SRL, TCG_REG_TMP, rd, rm);   //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}

/* sw 
 * loop left shift
 */
static inline void tcg_out_rotl_Imm(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, unsigned int m)
{
    unsigned int bits = ext ? 64 : 32;
    unsigned int max = bits - 1;

    if(ext == TCG_TYPE_I64)
    {
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, rn, bits -(m & max));
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rn, (m & max));  //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);   //get rn right part to left
    }
    else
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rn, 0xf);
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, rd, bits -(m & max));
        tcg_out_insn_simpleImm(s, OPC_SLL_I, TCG_REG_TMP2, rd, (m & max));  //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);   //get rn right part to left
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}


/* sw loop left shift
 */
static inline void tcg_out_rotl_Reg(TCGContext *s, TCGType ext, TCGReg rd, TCGReg rn, TCGReg rm)
{
    unsigned int bits = ext ? 64 : 32;
    tcg_out_insn_simpleImm(s, OPC_SUBL_I, TCG_REG_TMP, rm, bits); //rm = 64-rm
    tcg_out_insn_bitReg(s, OPC_SUBL, TCG_REG_TMP, TCG_REG_ZERO, TCG_REG_TMP);

    if(ext == TCG_TYPE_I64)
    {
        tcg_out_insn_bitReg(s, OPC_SRL, TCG_REG_TMP2, rn, TCG_REG_TMP);  //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_SLL, TCG_REG_TMP, rn, rm);   //get rn right part to left
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
    }
    else
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rn, 0xf);
        tcg_out_insn_bitReg(s, OPC_SRL, TCG_REG_TMP2, rd, TCG_REG_TMP);  //get rn left part to TCG_REG_TMP
        tcg_out_insn_bitReg(s, OPC_SLL, TCG_REG_TMP, rd, rm);   //get rn right part to left
        tcg_out_insn_bitReg(s, OPC_BIS, rd, TCG_REG_TMP, TCG_REG_TMP2);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, rd, rd, 0xf);
    }
}

#ifdef CONFIG_SOFTMMU
#include "../tcg-ldst.c.inc"

/* helper signature: helper_ret_ld_mmu(CPUState *env, target_ulong addr,
 *                                     TCGMemOpIdx oi, uintptr_t ra)
 */
static void * const qemu_ld_helpers[16] = {
    [MO_UB]   = helper_ret_ldub_mmu,
    [MO_LEUW] = helper_le_lduw_mmu,
    [MO_LEUL] = helper_le_ldul_mmu,
    [MO_LEQ]  = helper_le_ldq_mmu,
    [MO_BEUW] = helper_be_lduw_mmu,
    [MO_BEUL] = helper_be_ldul_mmu,
    [MO_BEQ]  = helper_be_ldq_mmu,
};

/* helper signature: helper_ret_st_mmu(CPUState *env, target_ulong addr,
 *                                     uintxx_t val, TCGMemOpIdx oi,
 *                                     uintptr_t ra)
 */
static void * const qemu_st_helpers[16] = {
    [MO_UB]   = helper_ret_stb_mmu,
    [MO_LEUW] = helper_le_stw_mmu,
    [MO_LEUL] = helper_le_stl_mmu,
    [MO_LEQ]  = helper_le_stq_mmu,
    [MO_BEUW] = helper_be_stw_mmu,
    [MO_BEUL] = helper_be_stl_mmu,
    [MO_BEQ]  = helper_be_stq_mmu,
};


static inline void tcg_out_adr(TCGContext *s, TCGReg rd, const void *target)
{
    ptrdiff_t offset = tcg_pcrel_diff(s, target);
    tcg_debug_assert(offset == sextract64(offset, 0, 21));
    //get current PC to rd
    tcg_out_insn_br(s, OPC_BR, rd, 0);
    tcg_out_insn_simpleImm(s, OPC_SUBL_I, rd, rd, 4);
    if (offset >= 0) {
        tcg_out_simple(s, OPC_ADDL_I, OPC_ADDL, rd, rd, offset);
    } else {
        tcg_out_simple(s, OPC_SUBL_I, OPC_SUBL, rd, rd, -offset);
    }
}

static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *lb)
{
    TCGMemOpIdx oi = lb->oi;
    MemOp opc = get_memop(oi);
    MemOp size = opc & MO_SIZE;

    if (!reloc_pc21(lb->label_ptr[0], tcg_splitwx_to_rx(s->code_ptr))) {
        return false;
    }

    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_X16, TCG_AREG0);
    tcg_out_mov(s, TARGET_LONG_BITS == 64, TCG_REG_X17, lb->addrlo_reg);
    tcg_out_movi(s, TCG_TYPE_I32, TCG_REG_X18, oi);
    tcg_out_adr(s, TCG_REG_X19, lb->raddr);
    tcg_out_call(s, qemu_ld_helpers[opc & (MO_BSWAP | MO_SIZE)]);
    if (opc & MO_SIGN) {
        tcg_out_sxt(s, lb->type, size, lb->datalo_reg, TCG_REG_X0);
    } else {
        tcg_out_mov(s, size == MO_64, lb->datalo_reg, TCG_REG_X0);
    }

    tcg_out_goto(s, lb->raddr);
    return true;
}

static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *lb)
{
    TCGMemOpIdx oi = lb->oi;
    MemOp opc = get_memop(oi);
    MemOp size = opc & MO_SIZE;

    if (!reloc_pc21(lb->label_ptr[0], tcg_splitwx_to_rx(s->code_ptr))) {
        return false;
    }

    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_X16, TCG_AREG0);
    tcg_out_mov(s, TARGET_LONG_BITS == 64, TCG_REG_X17, lb->addrlo_reg);
    tcg_out_mov(s, size == MO_64, TCG_REG_X18, lb->datalo_reg);
    tcg_out_movi(s, TCG_TYPE_I32, TCG_REG_X19, oi);
    tcg_out_adr(s, TCG_REG_X20, lb->raddr);
    tcg_out_call(s, qemu_st_helpers[opc & (MO_BSWAP | MO_SIZE)]);
    tcg_out_goto(s, lb->raddr);
    return true;
}

static void add_qemu_ldst_label(TCGContext *s, bool is_ld, TCGMemOpIdx oi,
                                TCGType ext, TCGReg data_reg, TCGReg addr_reg,
                                tcg_insn_unit *raddr, tcg_insn_unit *label_ptr)
{
    TCGLabelQemuLdst *label = new_ldst_label(s);

    label->is_ld = is_ld;
    label->oi = oi;
    label->type = ext;
    label->datalo_reg = data_reg;
    label->addrlo_reg = addr_reg;
    label->raddr = tcg_splitwx_to_rx(raddr);
    label->label_ptr[0] = label_ptr;
}

/* We expect to use a 7-bit scaled negative offset from ENV.  */
QEMU_BUILD_BUG_ON(TLB_MASK_TABLE_OFS(0) > 0);
QEMU_BUILD_BUG_ON(TLB_MASK_TABLE_OFS(0) < -512);

/* These offsets are built into the LDP below.  */
QEMU_BUILD_BUG_ON(offsetof(CPUTLBDescFast, mask) != 0);
QEMU_BUILD_BUG_ON(offsetof(CPUTLBDescFast, table) != 8);

/* Load and compare a TLB entry, emitting the conditional jump to the
   slow path for the failure case, which will be patched later when finalizing
   the slow path. Generated code returns the host addend in X1,
   clobbers X0,X2,X3,TMP. */
static void tcg_out_tlb_read(TCGContext *s, TCGReg addr_reg, MemOp opc,
                             tcg_insn_unit **label_ptr, int mem_index,
                             bool is_read)
{
    unsigned a_bits = get_alignment_bits(opc);
    unsigned s_bits = opc & MO_SIZE;
    unsigned a_mask = (1u << a_bits) - 1;
    unsigned s_mask = (1u << s_bits) - 1;
    TCGReg x3;
    TCGType mask_type;
    uint64_t compare_mask;

    mask_type = (TARGET_PAGE_BITS + CPU_TLB_DYN_MAX_BITS > 32
                 ? TCG_TYPE_I64 : TCG_TYPE_I32);

    /* Load env_tlb(env)->f[mmu_idx].{mask,table} into {x0,x1}.  */
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X0, TCG_AREG0, TLB_MASK_TABLE_OFS(mem_index));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X1, TCG_AREG0, TLB_MASK_TABLE_OFS(mem_index)+8);

    /* Extract the TLB index from the address into X0.  */
    if(mask_type == TCG_TYPE_I64){
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, addr_reg, TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
        tcg_out_insn_bitReg(s, OPC_AND, TCG_REG_X0, TCG_REG_X0, TCG_REG_TMP);
    }
    else
    {
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_TMP, addr_reg, 0xf);
        tcg_out_insn_simpleImm(s, OPC_SRL_I, TCG_REG_TMP, TCG_REG_TMP, TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
        tcg_out_insn_bitReg(s, OPC_AND, TCG_REG_X0, TCG_REG_X0, TCG_REG_TMP);
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_X0, TCG_REG_X0, 0xf);
    }
    /* Add the tlb_table pointer, creating the CPUTLBEntry address into X1.  */
    tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_X1, TCG_REG_X1, TCG_REG_X0);

    /* Load the tlb comparator into X0, and the fast path addend into X1.  */
    tcg_out_ld(s, TCG_TYPE_TL, TCG_REG_X0, TCG_REG_X1, is_read
               ? offsetof(CPUTLBEntry, addr_read)
               : offsetof(CPUTLBEntry, addr_write));
    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_X1, TCG_REG_X1,
               offsetof(CPUTLBEntry, addend));

    /* For aligned accesses, we check the first byte and include the alignment
       bits within the address.  For unaligned access, we check that we don't
       cross pages using the address of the last byte of the access.  */
    if (a_bits >= s_bits) {
        x3 = addr_reg;
    } else {
        if (s_mask >= a_mask) {
            tcg_out_simple(s, OPC_ADDL_I, OPC_ADDL, TCG_REG_X3, addr_reg, s_mask - a_mask);
        } else {
            tcg_out_simple(s, OPC_SUBL_I, OPC_SUBL, TCG_REG_X3, addr_reg, a_mask - s_mask);
        }
	if(TARGET_LONG_BITS != 64)
        {
	    tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_X3, TCG_REG_X3, 0xf);
        }
        x3 = TCG_REG_X3;
    }
    compare_mask = (uint64_t)TARGET_PAGE_MASK | a_mask;

    /* Store the page mask part of the address into X3.  */
    tcg_out_bit(s, OPC_AND_I, OPC_AND, TCG_REG_X3, x3, compare_mask);
    if(TARGET_LONG_BITS != 64)
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TCG_REG_X3, TCG_REG_X3, 0xf);
    }

    /* Perform the address comparison. */
    tcg_out_cond_cmp(s, TARGET_LONG_BITS == 64, TCG_COND_NE, TCG_REG_TMP, TCG_REG_X0, TCG_REG_X3, 0);

    /* If not equal, we jump to the slow path. */
    *label_ptr = s->code_ptr;
    tcg_out_insn_br(s, OPC_BGT, TCG_REG_TMP, 0);
}

#endif /* CONFIG_SOFTMMU */

#if defined(CONFIG_LDSTOFFSET_OPT)
static void tcg_out_qemu_ld_direct(TCGContext *s, MemOp memop, TCGType ext,
                                   TCGReg data_r, TCGReg addr_r,
                                   TCGType otype, TCGReg off_r, int64_t disp)
#else
static void tcg_out_qemu_ld_direct(TCGContext *s, MemOp memop, TCGType ext,
                                   TCGReg data_r, TCGReg addr_r,
                                   TCGType otype, TCGReg off_r)
#endif
{
    TCGReg TMP = TCG_REG_TMP;
    if(otype == TCG_TYPE_I32)
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TMP, off_r, 0xf);
        tcg_out_insn_simpleReg(s, OPC_ADDL, TMP, addr_r, TCG_REG_TMP);
    }
    else if(off_r == TCG_REG_ZERO)//otype == TCG_TYPE_I64
    {
       //tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_TMP, addr_r, off_r);
        TMP = addr_r;
    }else {
       tcg_out_insn_simpleReg(s, OPC_ADDL, TMP, addr_r, off_r);
    }

    const MemOp bswap = memop & MO_BSWAP;

    switch (memop & MO_SSIZE) {
    case MO_UB:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_LDBU, data_r, TMP, disp, zeroExt);
#else
        tcg_out_ldst(s, OPC_LDBU, data_r, TMP, 0, zeroExt);
#endif
        break;
    case MO_SB:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_LDBU, data_r, TMP, disp, sigExt);
#else
        tcg_out_ldst(s, OPC_LDBU, data_r, TMP, 0, sigExt);
#endif
        if(ext == TCG_TYPE_I32)
        {
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, data_r, data_r, 0xf);
        }
        break;
    case MO_UW:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_LDHU, data_r, TMP, disp, zeroExt);
#else
        tcg_out_ldst(s, OPC_LDHU, data_r, TMP, 0, zeroExt);
#endif
        if (bswap) {
            tcg_out_bswap16(s, ext, data_r, data_r);
        }
        break;
    case MO_SW:
        if(bswap) {
#if defined(CONFIG_LDSTOFFSET_OPT)
            tcg_out_ldst(s, OPC_LDHU, data_r, TMP, disp, zeroExt);
#else
            tcg_out_ldst(s, OPC_LDHU, data_r, TMP, 0, zeroExt);
#endif
            tcg_out_bswap16(s, ext, data_r, data_r);
            tcg_out_insn_simpleReg(s, OPC_SEXTH, data_r, TCG_REG_ZERO, data_r);
        }
        else
        {
#if defined(CONFIG_LDSTOFFSET_OPT)
            tcg_out_ldst(s, OPC_LDHU, data_r, TMP, disp, sigExt);
#else
            tcg_out_ldst(s, OPC_LDHU, data_r, TMP, 0, sigExt);
#endif
        }
	    if(ext == TCG_TYPE_I32)
        {
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, data_r, data_r, 0xf);
        }
        break;
  case MO_UL:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_LDW, data_r, TMP, disp, zeroExt);
#else
        tcg_out_ldst(s, OPC_LDW, data_r, TMP, 0, zeroExt);
#endif
        if (bswap) {
            tcg_out_bswap32(s, ext, data_r, data_r);
        }
        break;
    case MO_SL:
        if (bswap) {
#if defined(CONFIG_LDSTOFFSET_OPT)
            tcg_out_ldst(s, OPC_LDW, data_r, TMP, disp, zeroExt);
#else
            tcg_out_ldst(s, OPC_LDW, data_r, TMP, 0, zeroExt);
#endif
            tcg_out_bswap32(s, ext, data_r, data_r);
	        tcg_out_insn_simpleReg(s, OPC_ADDW, data_r, data_r, TCG_REG_ZERO);
        }
        else
        {
#if defined(CONFIG_LDSTOFFSET_OPT)
            tcg_out_ldst(s, OPC_LDW, data_r, TMP, disp, sigExt);
#else
            tcg_out_ldst(s, OPC_LDW, data_r, TMP, 0, sigExt);
#endif
        }
        break;
    case MO_Q:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_LDL, data_r, TMP, disp, zeroExt);
#else
        tcg_out_ldst(s, OPC_LDL, data_r, TMP, 0, zeroExt);
#endif
        if (bswap) {
            tcg_out_bswap64(s, ext, data_r, data_r);
        }
        break;
    default:
        tcg_abort();
    }
}

#if defined(CONFIG_LDSTOFFSET_OPT)
static void tcg_out_qemu_ld(TCGContext *s, TCGReg data_reg, TCGReg addr_reg, TCGMemOpIdx oi, TCGType ext, int64_t disp)
#else
static void tcg_out_qemu_ld(TCGContext *s, TCGReg data_reg, TCGReg addr_reg, TCGMemOpIdx oi, TCGType ext)
#endif
{
    MemOp memop = get_memop(oi);
    const TCGType otype = TARGET_LONG_BITS == 64 ? TCG_TYPE_I64: TCG_TYPE_I32;
#ifdef CONFIG_SOFTMMU
    unsigned mem_index = get_mmuidx(oi);
    tcg_insn_unit *label_ptr;

    tcg_out_tlb_read(s, addr_reg, memop, &label_ptr, mem_index, 1);
    tcg_out_qemu_ld_direct(s, memop, ext, data_reg,
                           TCG_REG_X1, otype, addr_reg);
    add_qemu_ldst_label(s, true, oi, ext, data_reg, addr_reg,
                        s->code_ptr, label_ptr);

#else /* !CONFIG_SOFTMMU */
    if (USE_GUEST_BASE) {
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_qemu_ld_direct(s, memop, ext, data_reg, TCG_REG_GUEST_BASE, otype, addr_reg, disp);
#else
        tcg_out_qemu_ld_direct(s, memop, ext, data_reg, TCG_REG_GUEST_BASE, otype, addr_reg);
#endif
    } else {
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_qemu_ld_direct(s, memop, ext, data_reg, addr_reg, TCG_TYPE_I64, TCG_REG_ZERO, disp);
#else
        tcg_out_qemu_ld_direct(s, memop, ext, data_reg, addr_reg, TCG_TYPE_I64, TCG_REG_ZERO);
#endif
    }
#endif /* CONFIG_SOFTMMU */

}


#if defined(CONFIG_LDSTOFFSET_OPT)
static void tcg_out_qemu_st_direct(TCGContext *s, MemOp memop,
                                   TCGReg data_r, TCGReg addr_r,
                                   TCGType otype, TCGReg off_r, int64_t disp)
#else
static void tcg_out_qemu_st_direct(TCGContext *s, MemOp memop,
                                   TCGReg data_r, TCGReg addr_r,
                                   TCGType otype, TCGReg off_r)
#endif
{
    TCGReg TMP = TCG_REG_TMP;
    if(otype == TCG_TYPE_I32)
    {
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, TMP, off_r, 0xf);
        tcg_out_insn_simpleReg(s, OPC_ADDL, TMP, addr_r, TCG_REG_TMP);
    }
    else if (off_r == TCG_REG_ZERO) //otype==TCG_TYPE_I64
    {
       // tcg_out_insn_simpleReg(s, OPC_ADDL, TCG_REG_TMP, addr_r, off_r);
       TMP = addr_r;
    }else{
       tcg_out_insn_simpleReg(s, OPC_ADDL, TMP, addr_r, off_r);
    }

    const MemOp bswap = memop & MO_BSWAP;

    switch (memop & MO_SIZE) {
    case MO_8:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_STB, data_r, TMP, disp, 0);
#else
        tcg_out_ldst(s, OPC_STB, data_r, TMP, 0, 0);
#endif
        break;
    case MO_16:
        if (bswap && data_r != TCG_REG_ZERO) {
            tcg_out_bswap16(s, TCG_TYPE_I32, TCG_REG_TMP3, data_r);
            data_r = TCG_REG_TMP3;
        }
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_STH, data_r, TMP, disp, 0);
#else
        tcg_out_ldst(s, OPC_STH, data_r, TMP, 0, 0);
#endif
        break;
    case MO_32:
        if (bswap && data_r != TCG_REG_ZERO) {
            tcg_out_bswap32(s, TCG_TYPE_I32, TCG_REG_TMP3, data_r);
            data_r = TCG_REG_TMP3;
        }
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_STW, data_r, TMP, disp, 0);
#else
        tcg_out_ldst(s, OPC_STW, data_r, TMP, 0, 0);
#endif
        break;
    case MO_64:
        if (bswap && data_r != TCG_REG_ZERO) {
            tcg_out_bswap64(s, TCG_TYPE_I64, TCG_REG_TMP3, data_r);
            data_r = TCG_REG_TMP3;
        }
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_ldst(s, OPC_STL, data_r, TMP, disp, 0);
#else
        tcg_out_ldst(s, OPC_STL, data_r, TMP, 0, 0);
#endif
        break;
    default:
        tcg_abort();
    }
}


#if defined(CONFIG_LDSTOFFSET_OPT)
static void tcg_out_qemu_st(TCGContext *s, TCGReg data_reg, TCGReg addr_reg,
                            TCGMemOpIdx oi, int64_t disp)
#else
static void tcg_out_qemu_st(TCGContext *s, TCGReg data_reg, TCGReg addr_reg,
                            TCGMemOpIdx oi)
#endif
{
    MemOp memop = get_memop(oi);
    const TCGType otype = TARGET_LONG_BITS == 64 ? TCG_TYPE_I64: TCG_TYPE_I32;
#ifdef CONFIG_SOFTMMU
    unsigned mem_index = get_mmuidx(oi);
    tcg_insn_unit *label_ptr;

    tcg_out_tlb_read(s, addr_reg, memop, &label_ptr, mem_index, 0);
    tcg_out_qemu_st_direct(s, memop, data_reg, TCG_REG_X1, otype, addr_reg);
    add_qemu_ldst_label(s, false, oi, (memop & MO_SIZE)== MO_64, data_reg, addr_reg, s->code_ptr, label_ptr);
#else /* !CONFIG_SOFTMMU */
    if (USE_GUEST_BASE) {
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_qemu_st_direct(s, memop, data_reg, TCG_REG_GUEST_BASE, otype, addr_reg, disp);
#else
        tcg_out_qemu_st_direct(s, memop, data_reg, TCG_REG_GUEST_BASE, otype, addr_reg);
#endif
    } else {
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_out_qemu_st_direct(s, memop, data_reg, addr_reg, TCG_TYPE_I64, TCG_REG_ZERO, disp);
#else
        tcg_out_qemu_st_direct(s, memop, data_reg, addr_reg, TCG_TYPE_I64, TCG_REG_ZERO);
#endif
    }
#endif /* CONFIG_SOFTMMU */
}


static const tcg_insn_unit *tb_ret_addr;


static void tcg_out_op(TCGContext *s, TCGOpcode opc, const TCGArg args[TCG_MAX_OP_ARGS],const int const_args[TCG_MAX_OP_ARGS])
{
    /* 99% of the time, we can signal the use of extension registers
       by looking to see if the opcode handles 64-bit data.  */
    TCGType ext = (tcg_op_defs[opc].flags & TCG_OPF_64BIT) != 0; 
    /* Hoist the loads of the most common arguments.  */
    TCGArg a0 = args[0];
    TCGArg a1 = args[1];
    TCGArg a2 = args[2];
    int c2 = const_args[2];

    /* Some operands are defined with "rZ" constraint, a register or
       the zero register.  These need not actually test args[I] == 0.  */
    #define REG0(I)  (const_args[I] ? TCG_REG_ZERO : (TCGReg)args[I])

    switch (opc) {
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
    case INDEX_op_cmpeq_i64:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_CMPEQ_I, OPC_CMPEQ, a0, a1, a2); 
        } else {
            tcg_out_insn_bitReg(s, OPC_CMPEQ, a0, a1, a2); 
        }
        break;
#endif
#if defined(CONFIG_IROPT) && defined(__sw_64__)
    case INDEX_op_s8addl_i64:
       tcg_out_insn_simpleReg(s, OPC_S8ADDL, a0, a1, a2);
       break;
    case INDEX_op_s4addl_i64:
       tcg_out_insn_simpleReg(s, OPC_S4ADDL, a0, a1, a2);
       break;
#endif
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
    case INDEX_op_fimovd:
       tcg_out32(s, OPC_FIMOVD | (a1 & 0x1f) << 21 | 0x1f << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_fimovs:
       tcg_out32(s, OPC_FIMOVS | (a1 & 0x1f) << 21 | 0x1f << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_ifmovd:
       tcg_out32(s, OPC_IFMOVD | (a1 & 0x1f) << 21 | 0x1f << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_ifmovs:
       tcg_out32(s, OPC_IFMOVS | (a1 & 0x1f) << 21 | 0x1f << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_fcvtld:
       FCVTLD(a0, a1);
       break;
    case INDEX_op_fcvtdl:
       FCVTDL(a0, a1);
       break;
    case INDEX_op_fcvtdl_z:
       FCVTDL_Z(a0, a1);
       break;
    case INDEX_op_fcvtls:
       FCVTLS(a0, a1);
       break;
    case INDEX_op_fcvtsd:
       FCVTSD(a0, a1);
       break;
    case INDEX_op_fcvtds:
       FCVTDS(a0, a1);
       break;
    case INDEX_op_fadds:
       tcg_out32(s, OPC_FADDS | (a2 & 0x1f) << 21 | (a1 & 0x1f) << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_faddd:
       tcg_out32(s, OPC_FADDD | (a2 & 0x1f) << 21 | (a1 & 0x1f) << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_fsubd:
       tcg_out32(s, OPC_FSUBD | (a2 & 0x1f) << 21 | (a1 & 0x1f) << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_fmuls:
       tcg_out32(s, OPC_FMULS | (a2 & 0x1f) << 21 | (a1 & 0x1f) << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_fmuld:
       tcg_out32(s, OPC_FMULD | (a2 & 0x1f) << 21 | (a1 & 0x1f) << 16 | (a0 & 0x1f));
       break;
    case INDEX_op_zapnot:
       if (c2) {
	       tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a1, a2);
       } else {
           tcg_out_insn_simpleReg(s, OPC_ZAPNOT, a0, a1, a2);
       }
       break;
#endif
    case INDEX_op_ldl_u:
        tcg_out_ldst(s, OPC_LDL_U, a0, a1, a2, 0);
        break;
    case INDEX_op_flds:
        tcg_out_ldst(s, OPC_FLDS, a0, a1, a2, 0);
        break;
    case INDEX_op_fldd:
        tcg_out_ldst(s, OPC_FLDD, a0, a1, a2, 0);
        break;
    case INDEX_op_stl_u:
        tcg_out_ldst(s, OPC_STL_U, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_fsts:
        tcg_out_ldst(s, OPC_FSTS, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_fstd:
        tcg_out_ldst(s, OPC_FSTD, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_ldi:
        if (c2) {
            tcg_out_ldi(s, a0, a1, a2);
        }else {
            tcg_out_insn_simpleReg(s, OPC_ADDL, a0, a1, a2);
        }
        break;
    case INDEX_op_ldih:
        if (c2){
            tcg_out_ldih(s, a0, a1, a2);
        }else {
            tcg_out_insn_simpleReg(s, OPC_ADDL, a0, a1, a2);
        }
        break;

    case INDEX_op_exit_tb: /* sw */
        /* Reuse the zeroing that exists for goto_ptr.  */
        if (a0 == 0) {
            tcg_out_goto_long(s, tcg_code_gen_epilogue);
        } else {
            tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_X0, a0);
            tcg_out_goto_long(s, tb_ret_addr);
        }
        break;

    case INDEX_op_goto_tb: /* sw */
        if (s->tb_jmp_insn_offset != NULL) {
            /* TCG_TARGET_HAS_direct_jump */
            /* Ensure that ADRP+ADD are 8-byte aligned so that an atomic
               write can be used to patch the target address. */
            if ((uintptr_t)s->code_ptr & 7) {
                tcg_out32(s, OPC_NOP);
            }
            s->tb_jmp_insn_offset[a0] = tcg_current_code_size(s);
            tcg_out32(s, OPC_NOP);
            tcg_out32(s, OPC_NOP);
            tcg_out32(s, OPC_NOP);
            tcg_out32(s, OPC_NOP);//total 2 nop for tb_target
        } else {
            /* !TCG_TARGET_HAS_direct_jump */
            tcg_debug_assert(s->tb_jmp_target_addr != NULL);
	    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TMP, TCG_REG_ZERO, (uintptr_t)(s->tb_jmp_target_addr + a0));
        }
        tcg_out_insn_jump(s, OPC_JMP, TCG_REG_ZERO, TCG_REG_TMP, noPara);
        set_jmp_reset_offset(s, a0);
        break;

    case INDEX_op_goto_ptr:
        tcg_out_insn_jump(s, OPC_JMP, TCG_REG_ZERO, a0, noPara);
        break;

    case INDEX_op_br:
        tcg_out_goto_label(s, arg_label(a0));
        break;

    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
        tcg_out_ldst(s, OPC_LDBU, a0, a1, a2, 0);
        break;
    case INDEX_op_ld8s_i32:
        tcg_out_ldst(s, OPC_LDBU, a0, a1, a2, 1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_ld8s_i64:
        tcg_out_ldst(s, OPC_LDBU, a0, a1, a2, 1);
        break;
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
        tcg_out_ldst(s, OPC_LDHU, a0, a1, a2, 0);
        break;
    case INDEX_op_ld16s_i32:
        tcg_out_ldst(s, OPC_LDHU, a0, a1, a2, 1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_ld16s_i64:
        tcg_out_ldst(s, OPC_LDHU, a0, a1, a2, 1);
        break;
    case INDEX_op_ld_i32:
        tcg_out_ldst(s, OPC_LDW, a0, a1, a2, 0);
	break;
    case INDEX_op_ld32u_i64:
        tcg_out_ldst(s, OPC_LDW, a0, a1, a2, 0);
        break;
    case INDEX_op_ld32s_i64:
        tcg_out_ldst(s, OPC_LDW, a0, a1, a2, 1);
        break;
    case INDEX_op_ld_i64:
        tcg_out_ldst(s, OPC_LDL, a0, a1, a2, 1);
        break;
    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
        tcg_out_ldst(s, OPC_STB, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
        tcg_out_ldst(s, OPC_STH, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_st_i32:
    case INDEX_op_st32_i64:
        tcg_out_ldst(s, OPC_STW, REG0(0), a1, a2, 0);
        break;
    case INDEX_op_st_i64:
        tcg_out_ldst(s, OPC_STL, REG0(0), a1, a2, 0);
        break;

    case INDEX_op_add_i32:
        a2 = (int32_t)a2;
        if (c2) {
            tcg_out_addsubi(s, ext, a0, a1, a2);
        } else {
            tcg_out_insn_simpleReg(s, OPC_ADDW, a0, a1, a2);
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        }
        break;
    case INDEX_op_add_i64:
        if (c2) {
            tcg_out_addsubi(s, ext, a0, a1, a2);
        } else {
            tcg_out_insn_simpleReg(s, OPC_ADDL, a0, a1, a2);
        }
        break;

    case INDEX_op_sub_i32:
        a2 = (int32_t)a2;
        if (c2) {
            tcg_out_addsubi(s, ext, a0, a1, -a2);
        } else {
            tcg_out_insn_simpleReg(s, OPC_SUBW, a0, a1, a2);
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        }
        break;
    case INDEX_op_sub_i64:
        if (c2) {
            tcg_out_addsubi(s, ext, a0, a1, -a2);
        } else {
            tcg_out_insn_simpleReg(s, OPC_SUBL, a0, a1, a2);
        }
        break;

    case INDEX_op_neg_i32:
        tcg_out_insn_bitReg(s, OPC_SUBW, a0, TCG_REG_ZERO, a1);
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_neg_i64:
        tcg_out_insn_bitReg(s, OPC_SUBL, a0, TCG_REG_ZERO, a1);
        break;

    case INDEX_op_and_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_AND_I, OPC_AND, a0, a1, a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_AND, a0, a1, a2);
        }
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_and_i64:
        if (c2) {
#if defined(CONFIG_AND_OPT)
            tcg_out_andori(s, OPC_AND_I, OPC_BIC_I, a0, a1, a2);
#else
            tcg_out_bit(s, OPC_AND_I, OPC_AND, a0, a1, a2);
#endif
        } else {
            tcg_out_insn_bitReg(s, OPC_AND, a0, a1, a2);
        }
        break;

    case INDEX_op_andc_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_AND_I, OPC_AND, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_BIC, a0, a1, a2);
        }
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_andc_i64:
        if (c2) {
            tcg_out_bit(s, OPC_AND_I, OPC_AND, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_BIC, a0, a1, a2);
        }
        break;

    case INDEX_op_or_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_BIS_I, OPC_BIS, a0, a1, a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_BIS, a0, a1, a2);
        }
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_or_i64:
        if (c2) {
#if defined(CONFIG_AND_OPT)
            tcg_out_andori(s, OPC_BIS_I, OPC_ORNOT_I, a0, a1, a2);
#else
            tcg_out_bit(s, OPC_BIS_I, OPC_BIS, a0, a1, a2);
#endif
        } else {
            tcg_out_insn_bitReg(s, OPC_BIS, a0, a1, a2);
        }
        break;

    case INDEX_op_orc_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_BIS_I, OPC_BIS, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_ORNOT, a0, a1, a2);
        }
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_orc_i64:
        if (c2) {
            tcg_out_bit(s, OPC_BIS_I, OPC_BIS, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_ORNOT, a0, a1, a2);
        }
        break;

    case INDEX_op_xor_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_XOR_I, OPC_XOR, a0, a1, a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_XOR, a0, a1, a2);
        }
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_xor_i64:
        if (c2) {
            tcg_out_bit(s, OPC_XOR_I, OPC_XOR, a0, a1, a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_XOR, a0, a1, a2);
        }
        break;

    case INDEX_op_eqv_i32:
        if (c2) {
            a2 = (int32_t)a2;
            tcg_out_bit(s, OPC_XOR_I, OPC_XOR, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_EQV, a0, a1, a2); 
        }
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_eqv_i64:
        if (c2) {
            tcg_out_bit(s, OPC_XOR_I, OPC_XOR, a0, a1, ~a2);
        } else {
            tcg_out_insn_bitReg(s, OPC_EQV, a0, a1, a2); 
        }
        break;

    case INDEX_op_not_i32:
    	tcg_out_insn_bitReg(s, OPC_ORNOT, a0, TCG_REG_ZERO, a1);
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_not_i64:
    	tcg_out_insn_bitReg(s, OPC_ORNOT, a0, TCG_REG_ZERO, a1);
        break;

    case INDEX_op_mul_i32:
        tcg_out_insn_simpleReg(s, OPC_MULL, a0, a1, a2);
	tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_mul_i64:
        tcg_out_insn_simpleReg(s, OPC_MULL, a0, a1, a2);
        break;

    case INDEX_op_div_i32: 
    case INDEX_op_div_i64: 
        tcg_debug_assert(0);
        break;
    case INDEX_op_divu_i32:
    case INDEX_op_divu_i64:
        tcg_debug_assert(0);
        break;

    case INDEX_op_rem_i32:
    case INDEX_op_rem_i64:
        tcg_debug_assert(0);
        break;
    case INDEX_op_remu_i32:
    case INDEX_op_remu_i64:
        tcg_debug_assert(0);
        break;

    case INDEX_op_shl_i32: /* sw logical left*/
        if (c2) {
            unsigned int bits = ext ? 64 : 32;
            unsigned int max = bits - 1;
            tcg_out_insn_simpleImm(s, OPC_SLL_I, a0, a1, a2&max);
	    tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        } else {
            tcg_out_insn_bitReg(s, OPC_SLL, a0, a1, a2);
	    tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        }
        break;
    case INDEX_op_shl_i64:
        if (c2) {
            unsigned int bits = ext ? 64 : 32;
            unsigned int max = bits - 1;
            tcg_out_insn_simpleImm(s, OPC_SLL_I, a0, a1, a2&max);
        } else {
            tcg_out_insn_bitReg(s, OPC_SLL, a0, a1, a2);
        }
        break;

    case INDEX_op_shr_i32: /* sw logical right */
        a2 = (int32_t)a2;
        if (c2) {
            int bits = ext ? 64 : 32;
            int max = bits - 1;
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a1, a1, 0xf);
            tcg_out_insn_simpleImm(s, OPC_SRL_I, a0, a1, a2&max);
        } else {
            tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a1, a1, 0xf);
            tcg_out_insn_bitReg(s, OPC_SRL, a0, a1, a2);
        }
        break;
    case INDEX_op_shr_i64:
        if (c2) {
            int bits = ext ? 64 : 32;
            int max = bits - 1;
            tcg_out_insn_simpleImm(s, OPC_SRL_I, a0, a1, a2&max);
        } else {
            tcg_out_insn_bitReg(s, OPC_SRL, a0, a1, a2);
        }
        break;

    case INDEX_op_sar_i32:
        a2 = (int32_t)a2;
        tcg_out_sar(s, ext, a0, a1, a2, c2);
        break;
    case INDEX_op_sar_i64: /* sw arithmetic right*/
        tcg_out_sar(s, ext, a0, a1, a2, c2);
        break;

    case INDEX_op_rotr_i32: /* loop shift */
    case INDEX_op_rotr_i64:
        if (c2) {/* loop right shift a2*/
            tcg_out_rotr_Imm(s, ext, a0, a1, a2);
        } else {
            tcg_out_rotr_Reg(s, ext, a0, a1, a2);
        }
        break;

    case INDEX_op_rotl_i32: /* loop shift */
    case INDEX_op_rotl_i64: /* sw */
        if (c2) {/* loop left shift a2*/
            tcg_out_rotl_Imm(s, ext, a0, a1, a2);   
        } else {
            tcg_out_rotl_Reg(s, ext, a0, a1, a2);
        }
        break;

    case INDEX_op_clz_i32:
        tcg_out_ctz32(s, OPC_CTLZ, a0, a1, a2, c2);
        break;
    case INDEX_op_clz_i64: /* counting leading zero numbers */
        tcg_out_ctz64(s, OPC_CTLZ, a0, a1, a2, c2);
        break;
    case INDEX_op_ctz_i32:
        tcg_out_ctz32(s, OPC_CTTZ, a0, a1, a2, c2);
        break;
    case INDEX_op_ctz_i64: /* counting tailing zero numbers */
        tcg_out_ctz64(s, OPC_CTTZ, a0, a1, a2, c2);
        break;
    case INDEX_op_ctpop_i32:
    case INDEX_op_ctpop_i64:
        tcg_out_ctpop(s, ext, a0, a1);
        break;

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        tcg_out_brcond(s, ext, a2, a0, a1, const_args[1], arg_label(args[3]));
        break;

    case INDEX_op_setcond_i32:
        a2 = (int32_t)a2;
    case INDEX_op_setcond_i64:    	
        tcg_out_setcond(s, ext, args[3], a0, a1, a2, c2);
        break;

    case INDEX_op_movcond_i32:
        a2 = (int32_t)a2;
    case INDEX_op_movcond_i64: 
#if defined(CONFIG_MOVCOND_OPT)
        tcg_out_movcond_opt(s, ext, args[5], a0, a1, a2, c2, REG0(3), REG0(4));
#else
        tcg_out_movcond(s, ext, args[5], a0, a1, a2, c2, REG0(3), REG0(4));
#endif
        break;

    case INDEX_op_qemu_ld_i32:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_debug_assert((int16_t)args[3] <= 0x7fff && (int16_t)args[3] >= -0x8000);
        tcg_out_qemu_ld(s, a0, a1, a2, ext, (int16_t)args[3]);
#else
        tcg_out_qemu_ld(s, a0, a1, a2, ext);
#endif
        break;
    case INDEX_op_qemu_ld_i64:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_debug_assert((int16_t)args[3] <= 0x7fff && (int16_t)args[3] >= -0x8000);
        tcg_out_qemu_ld(s, a0, a1, a2, ext, (int16_t)args[3]);
#else
        tcg_out_qemu_ld(s, a0, a1, a2, ext);
#endif
        break;
    case INDEX_op_qemu_st_i32:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_debug_assert((int16_t)args[3] <= 0x7fff && (int16_t)args[3] >= -0x8000);
        tcg_out_qemu_st(s, REG0(0), a1, a2, (int16_t)args[3]);
#else
        tcg_out_qemu_st(s, REG0(0), a1, a2);
#endif
        break;
    case INDEX_op_qemu_st_i64:
#if defined(CONFIG_LDSTOFFSET_OPT)
        tcg_debug_assert((int16_t)args[3] <= 0x7fff && (int16_t)args[3] >= -0x8000);
        tcg_out_qemu_st(s, REG0(0), a1, a2, (int16_t)args[3]);
#else
        tcg_out_qemu_st(s, REG0(0), a1, a2);
#endif
        break;

    case INDEX_op_bswap64_i64:
        tcg_out_bswap64(s, ext, a0, a1);
        break;
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap32_i64:
        tcg_out_bswap32(s, ext, a0, a1);
        break;
    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
        tcg_out_bswap16(s, ext, a0, a1);
        break;

    case INDEX_op_ext8s_i32:
	tcg_out_insn_simpleReg(s, OPC_SEXTB, a0, TCG_REG_ZERO, a1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_ext8s_i64:
	tcg_out_insn_simpleReg(s, OPC_SEXTB, a0, TCG_REG_ZERO, a1);
        break;
    case INDEX_op_ext16s_i32:
        tcg_out_insn_simpleReg(s, OPC_SEXTH, a0, TCG_REG_ZERO, a1);
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a0, 0xf);
        break;
    case INDEX_op_ext16s_i64:
        tcg_out_insn_simpleReg(s, OPC_SEXTH, a0, TCG_REG_ZERO, a1);
        break;
    case INDEX_op_ext_i32_i64:
    case INDEX_op_ext32s_i64:
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
    case INDEX_op_extrl_i64_i32:
        tcg_out_insn_simpleReg(s, OPC_ADDW, a0, TCG_REG_ZERO, a1);
        break;
    case INDEX_op_extrh_i64_i32:
        tcg_out_insn_simpleImm(s, OPC_SRA_I, a0, a1, 32);
        break;
#else
        tcg_out_insn_simpleReg(s, OPC_ADDW, a0, TCG_REG_ZERO, a1);
        break;
#endif
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
	tcg_out_insn_simpleImm(s, OPC_EXTLB_I, a0, a1, 0x0);
        break;
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
	tcg_out_insn_simpleImm(s, OPC_EXTLH_I, a0, a1, 0x0);
        break;
    case INDEX_op_extu_i32_i64:
    case INDEX_op_ext32u_i64:
        tcg_out_insn_simpleImm(s, OPC_ZAPNOT_I, a0, a1, 0xf);
        break;

    case INDEX_op_deposit_i32:
    case INDEX_op_deposit_i64:
#if defined(CONFIG_DEPOSIT_OPT)
        tcg_out_dep_opt(s, ext, a0, REG0(2), args[3], args[4]);
#else
       tcg_out_dep(s, ext, a0, REG0(2), args[3], args[4]);
#endif
        break;

    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64: 
#if defined(CONFIG_EXTRACT_OPT)
        tcg_out_extract_opt(s, a0, a1, a2, args[3]);//refer mips
#else
        tcg_out_extract(s, a0, a1, a2, args[3]);//refer mips
#endif
        break;

    case INDEX_op_sextract_i32:
    case INDEX_op_sextract_i64:
        tcg_out_sextract(s, a0, a1, a2, args[3]);
        break;

    case INDEX_op_extract2_i32:
    case INDEX_op_extract2_i64:
        tcg_out_extract2(s, ext, a0, REG0(2), REG0(1), args[3]);
        break;

    case INDEX_op_add2_i32:
    case INDEX_op_add2_i64:
        tcg_debug_assert(0);
        break;
    case INDEX_op_sub2_i32:
    case INDEX_op_sub2_i64:
        tcg_debug_assert(0);
        break;

    case INDEX_op_muluh_i64:
        tcg_out_insn_simpleReg(s, OPC_UMULH, a0, a1, a2);
        break;
    case INDEX_op_mulsh_i64:
        tcg_out_mulsh64(s, a0, a1, a2);
        break;

    case INDEX_op_mb:
        tcg_out_mb(s);
        break;

    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_mov_i64:
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    default:
        g_assert_not_reached();
    }

#undef REG0
}


static TCGConstraintSetIndex tcg_target_op_def(TCGOpcode op)
{
    switch (op) {
#if defined(CONFIG_IROPT) && defined(__sw_64__)
    case INDEX_op_s8addl_i64:
        return C_O1_I2(r, r, r); 
    case INDEX_op_s4addl_i64:
        return C_O1_I2(r, r, r); 
#endif
#if defined(CONFIG_FUNC_OPT) && defined(__sw_64__)
    case INDEX_op_cmpeq_i64:
        return C_O1_I2(r, r, rU); 
    case INDEX_op_ld_i128:
        return C_O1_I1(w, r);
    case INDEX_op_st_i128:
        return C_O0_I2(wZ, r);
    case INDEX_op_fimovs:
    case INDEX_op_fimovd:
        return C_O1_I1(r, w);
    case INDEX_op_ifmovs:
    case INDEX_op_ifmovd:
        return C_O1_I1(w, r);
    case INDEX_op_fcvtds:
    case INDEX_op_fcvtsd:
    case INDEX_op_fcvtld:
    case INDEX_op_fcvtdl:
    case INDEX_op_fcvtdl_z:
    case INDEX_op_fcvtls:
        return C_O1_I1(w, w);
    case INDEX_op_extrl_i64_i32:
    case INDEX_op_extrh_i64_i32:
        return C_O1_I1(r, r);
    case INDEX_op_fadds:
    case INDEX_op_faddd:
    case INDEX_op_fsubd:
    case INDEX_op_fmuls:
    case INDEX_op_fmuld:
        return C_O1_I2(w, w, w); 
    case INDEX_op_zapnot:
        return C_O1_I2(r, r, rU);
#endif
    case INDEX_op_ldl_u:
        return C_O1_I1(r, r);
    case INDEX_op_flds:
        return C_O1_I1(w, r);
    case INDEX_op_fldd:
        return C_O1_I1(w, r);
    case INDEX_op_stl_u:
        return C_O0_I2(rZ, r);
    case INDEX_op_fsts:
        return C_O0_I2(wZ, r);
    case INDEX_op_fstd:
        return C_O0_I2(wZ, r);
    case INDEX_op_ldi:
        return C_O1_I2(r, r, rT);
    case INDEX_op_ldih:
        return C_O1_I2(r, r, rT);
    case INDEX_op_goto_ptr:
        return C_O0_I1(r);

    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld_i32:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld_i64:
    case INDEX_op_neg_i32:
    case INDEX_op_neg_i64:
    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
    case INDEX_op_ctpop_i32:
    case INDEX_op_ctpop_i64:
    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap16_i64:
    case INDEX_op_bswap32_i64:
    case INDEX_op_bswap64_i64:
    case INDEX_op_ext8s_i32:
    case INDEX_op_ext16s_i32:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext8u_i64:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64:
    case INDEX_op_sextract_i32:
    case INDEX_op_sextract_i64:
        return C_O1_I1(r, r);

    case INDEX_op_st8_i32:
    case INDEX_op_st16_i32:
    case INDEX_op_st_i32:
    case INDEX_op_st8_i64:
    case INDEX_op_st16_i64:
    case INDEX_op_st32_i64:
    case INDEX_op_st_i64:
        return C_O0_I2(rZ, r);

    case INDEX_op_add_i32:
    case INDEX_op_sub_i32:
        return C_O1_I2(r, r, rU);
    case INDEX_op_add_i64:
    case INDEX_op_sub_i64:
#if defined(CONFIG_ADD1_OPT)
        return C_O1_I2(r, r, rD);
#elif defined(CONFIG_ADD2_OPT)
        return C_O1_I2(r, r, rT);
#else
        return C_O1_I2(r, r, rU);
#endif

    case INDEX_op_setcond_i32:
    case INDEX_op_setcond_i64:
        return C_O1_I2(r, r, rU);

    case INDEX_op_mul_i32:
    case INDEX_op_mul_i64:
    case INDEX_op_div_i32:
    case INDEX_op_div_i64:
    case INDEX_op_divu_i32:
    case INDEX_op_divu_i64:
    case INDEX_op_rem_i32:
    case INDEX_op_rem_i64:
    case INDEX_op_remu_i32:
    case INDEX_op_remu_i64:
    case INDEX_op_muluh_i64:
    case INDEX_op_mulsh_i64:
        return C_O1_I2(r, r, r);

    case INDEX_op_and_i64:
    case INDEX_op_or_i64:
#if defined(CONFIG_AND_OPT)
        return C_O1_I2(r, r, rC);
#endif
    case INDEX_op_and_i32:
    case INDEX_op_or_i32:
    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
    case INDEX_op_orc_i32:
    case INDEX_op_orc_i64:
    case INDEX_op_eqv_i32:
    case INDEX_op_eqv_i64:
        return C_O1_I2(r, r, rU);

    case INDEX_op_shl_i32:
    case INDEX_op_shr_i32:
    case INDEX_op_sar_i32:
    case INDEX_op_rotl_i32:
    case INDEX_op_rotr_i32:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i64:
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i64:
        return C_O1_I2(r, r, ri);

    case INDEX_op_clz_i32:
    case INDEX_op_clz_i64:
        return C_O1_I2(r, r, r); 

    case INDEX_op_ctz_i32:
    case INDEX_op_ctz_i64:
        return C_O1_I2(r, r, r);

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        return C_O0_I2(r, rU);

    case INDEX_op_movcond_i32:
    case INDEX_op_movcond_i64:
        return C_O1_I4(r, r, rU, rZ, rZ);

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        return C_O1_I1(r, l);

    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
        return C_O0_I2(lZ, l);

    case INDEX_op_deposit_i32:
    case INDEX_op_deposit_i64:
        return C_O1_I2(r, 0, rZ);

    case INDEX_op_extract2_i32:
    case INDEX_op_extract2_i64:
        return C_O1_I2(r, rZ, rZ);

    case INDEX_op_add2_i32:
    case INDEX_op_add2_i64:
    case INDEX_op_sub2_i32:
    case INDEX_op_sub2_i64:
        return C_O2_I4(r, r, rZ, rZ, rA, rMZ);

    case INDEX_op_add_vec:
    case INDEX_op_sub_vec:
    case INDEX_op_mul_vec:
    case INDEX_op_xor_vec:
    case INDEX_op_ssadd_vec:
    case INDEX_op_sssub_vec:
    case INDEX_op_usadd_vec:
    case INDEX_op_ussub_vec:
    case INDEX_op_smax_vec:
    case INDEX_op_smin_vec:
    case INDEX_op_umax_vec:
    case INDEX_op_umin_vec:
    case INDEX_op_shlv_vec:
    case INDEX_op_shrv_vec:
    case INDEX_op_sarv_vec:
    //case INDEX_op_aa64_sshl_vec:
        return C_O1_I2(w, w, w);
    case INDEX_op_not_vec:
    case INDEX_op_neg_vec:
    case INDEX_op_abs_vec:
    case INDEX_op_shli_vec:
    case INDEX_op_shri_vec:
    case INDEX_op_sari_vec:
        return C_O1_I1(w, w);
    case INDEX_op_ld_vec:
    case INDEX_op_dupm_vec:
        return C_O1_I1(w, r);
    case INDEX_op_st_vec:
        return C_O0_I2(w, r);
    case INDEX_op_dup_vec:
        return C_O1_I1(w, wr);
    case INDEX_op_or_vec:
    case INDEX_op_andc_vec:
        return C_O1_I2(w, w, wO);
    case INDEX_op_and_vec:
    case INDEX_op_orc_vec:
        return C_O1_I2(w, w, wN);
    case INDEX_op_cmp_vec:
        return C_O1_I2(w, w, wZ);
    case INDEX_op_bitsel_vec:
        return C_O1_I3(w, w, w, w);
    //case INDEX_op_aa64_sli_vec:
    //    return C_O1_I2(w, 0, w);


    default:
        g_assert_not_reached();
    }
}


static void tcg_target_init(TCGContext *s)
{
    tcg_target_available_regs[TCG_TYPE_I32] = 0xffffffffu;
    tcg_target_available_regs[TCG_TYPE_I64] = 0xffffffffu;
    tcg_target_available_regs[TCG_TYPE_V64] = 0xffffffff00000000ull;
    tcg_target_available_regs[TCG_TYPE_V128] = 0xffffffff00000000ull;
    tcg_target_call_clobber_regs = -1ull;
    
    //sw_64 callee saved x9-x15
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X9);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X10);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X11);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X12);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X13);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X14);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_X15);
    
    //sw_64 callee saved f2~f9
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F2);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F3);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F4);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F5);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F6);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F7);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F8);
    tcg_regset_reset_reg(tcg_target_call_clobber_regs, TCG_REG_F9);

    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_SP);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_FP);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP); //TCG_REG_X27
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP2); //TCG_REG_X25	
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP3); //TCG_REG_X24	
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_RA); //TCG_REG_X26
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_X29); /*sw_64 platform register */
    tcg_regset_set_reg(s->reserved_regs, TCG_FLOAT_TMP); /*sw_64 platform register */
    tcg_regset_set_reg(s->reserved_regs, TCG_FLOAT_TMP2); /*sw_64 platform register */
}


#define PUSH_SIZE  ((15-9+1+1) * 8)

#define STACK_SIZE TCG_STATIC_CALL_ARGS_SIZE

#define FRAME_SIZE \
    ((PUSH_SIZE \
      + STACK_SIZE \
      + CPU_TEMP_BUF_NLONGS * sizeof(long) \
      + TCG_TARGET_STACK_ALIGN - 1) \
     & ~(TCG_TARGET_STACK_ALIGN - 1))


/* We're expecting a 2 byte uleb128 encoded value.  */
QEMU_BUILD_BUG_ON(FRAME_SIZE >= (1 << 14));

/* We're expecting to use a single ADDI insn.  */
QEMU_BUILD_BUG_ON(FRAME_SIZE - PUSH_SIZE > 0xfff);

static void tcg_target_qemu_prologue(TCGContext *s) 
{
    TCGReg r;
    int ofs;
    
#if defined(CONFIG_DATA_PREFETCH)
    /* code load to cache L1 with share and clean mode*/
    tcg_out_ldst(s, OPC_LDWE, TCG_REG_F31, TCG_REG_X17, 0, 0);
#endif

    /* allocate space for all saved registers */
    /* subl $sp,PUSH_SIZE,$sp */
    tcg_out_simple(s, OPC_SUBL_I, OPC_SUBL, TCG_REG_SP, TCG_REG_SP, PUSH_SIZE);
    
    /* Push (FP, LR)  */
    /* stl $fp,0($sp) */
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_FP, TCG_REG_SP, 0);
    /* stl $26,8($sp) */
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_RA, TCG_REG_SP, 8);


    /* Set up frame pointer for canonical unwinding.  */
    /* TCG_REG_FP=TCG_REG_SP */
    tcg_out_movr(s, TCG_TYPE_I64, TCG_REG_FP, TCG_REG_SP);

    /* Store callee-preserved regs x9..x14.  */
    for (r = TCG_REG_X9; r <= TCG_REG_X14; r += 1){
        ofs = (r - TCG_REG_X9 + 2) * 8;
        tcg_out_insn_ldst(s, OPC_STL, r, TCG_REG_SP, ofs);
    }

    /* Make stack space for TCG locals.  */
    /* subl $sp,FRAME_SIZE-PUSH_SIZE,$sp */
    tcg_out_simple(s, OPC_SUBL_I, OPC_SUBL, TCG_REG_SP, TCG_REG_SP, FRAME_SIZE - PUSH_SIZE);

    /* Inform TCG about how to find TCG locals with register, offset, size.  */
    tcg_set_frame(s, TCG_REG_SP, TCG_STATIC_CALL_ARGS_SIZE,
                  CPU_TEMP_BUF_NLONGS * sizeof(long));

#if !defined(CONFIG_SOFTMMU)
    if (USE_GUEST_BASE) {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_GUEST_BASE, guest_base);
        tcg_regset_set_reg(s->reserved_regs, TCG_REG_GUEST_BASE);
    }
#endif
    
    /* TCG_AREG0=tcg_target_call_iarg_regs[0], on sw, we mov $16 to $9 */
    tcg_out_mov(s, TCG_TYPE_I64, TCG_AREG0, tcg_target_call_iarg_regs[0]);
#if defined(CONFIG_REG_OPT)
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X10, TCG_AREG0, offsetof(CPUX86State, regs[R_ESI]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X11, TCG_AREG0, offsetof(CPUX86State, regs[R_EDI]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X12, TCG_AREG0, offsetof(CPUX86State, regs[R_EAX]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X13, TCG_AREG0, offsetof(CPUX86State, regs[R_ECX]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X14, TCG_AREG0, offsetof(CPUX86State, regs[R_EDX]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X8,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESP]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X6,  TCG_AREG0, offsetof(CPUX86State, regs[12]));
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_X7,  TCG_AREG0, offsetof(CPUX86State, regs[13]));
#endif
    tcg_out_insn_jump(s, OPC_JMP, TCG_REG_ZERO, tcg_target_call_iarg_regs[1], noPara);

    /*
     * Return path for goto_ptr. Set return value to 0, a-la exit_tb,
     * and fall through to the rest of the epilogue.
     */
    tcg_code_gen_epilogue = tcg_splitwx_to_rx(s->code_ptr);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_X0, 0);

    /* TB epilogue */
    tb_ret_addr = tcg_splitwx_to_rx(s->code_ptr);

#if defined(CONFIG_DATA_PREFETCH)
    /* code load to cache L1 with share and clean mode, return address store in (FRAME_SIZE - PUSH_SIZE + 8)sp */
    tcg_out_ldst(s, OPC_LDWE, TCG_REG_F31, TCG_REG_SP, FRAME_SIZE - PUSH_SIZE + 8, 0);
#endif

#if defined(CONFIG_REG_OPT)
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X10, TCG_AREG0, offsetof(CPUX86State, regs[R_ESI]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X11, TCG_AREG0, offsetof(CPUX86State, regs[R_EDI]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X12, TCG_AREG0, offsetof(CPUX86State, regs[R_EAX]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X13, TCG_AREG0, offsetof(CPUX86State, regs[R_ECX]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X14, TCG_AREG0, offsetof(CPUX86State, regs[R_EDX]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X8,  TCG_AREG0, offsetof(CPUX86State, regs[R_ESP]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X6,  TCG_AREG0, offsetof(CPUX86State, regs[12]));
    tcg_out_insn_ldst(s, OPC_STL, TCG_REG_X7,  TCG_AREG0, offsetof(CPUX86State, regs[13]));
#endif

    /* Remove TCG locals stack space.  */
    /* addl $sp,FRAME_SIZE-PUSH_SIZE,$sp */
    tcg_out_simple(s, OPC_ADDL_I, OPC_ADDL, TCG_REG_SP, TCG_REG_SP, FRAME_SIZE - PUSH_SIZE);

    /* Restore registers x9..x14.  */
    for (r = TCG_REG_X9; r <= TCG_REG_X14; r += 1) {
        int ofs = (r - TCG_REG_X9 + 2) * 8;
        tcg_out_insn_ldst(s, OPC_LDL, r, TCG_REG_SP, ofs);
    }
    
    /* Pop (FP, LR) */
    /* ldl $fp,0($sp) */
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_FP, TCG_REG_SP, 0);
    /* ldl $26,8($sp) */
    tcg_out_insn_ldst(s, OPC_LDL, TCG_REG_RA, TCG_REG_SP, 8);
    
    /* restore SP to previous frame. */
    /* addl $sp,PUSH_SIZE,$sp */
    tcg_out_simple(s, OPC_ADDL_I, OPC_ADDL, TCG_REG_SP, TCG_REG_SP, PUSH_SIZE);
    
    tcg_out_insn_jump(s, OPC_RET, TCG_REG_ZERO, TCG_REG_RA, noPara);
}


static void tcg_out_nop_fill(tcg_insn_unit *p, int count)
{
    int i;
    for (i = 0; i < count; ++i) {
        p[i] = OPC_NOP;
    }
}

typedef struct {
    DebugFrameHeader h;
    uint8_t fde_def_cfa[4];
    uint8_t fde_reg_ofs[8 * 2];
} DebugFrame;

#define ELF_HOST_MACHINE EM_SW_64
/* GDB doesn't appear to require proper setting of ELF_HOST_FLAGS,
   which is good because they're really quite complicated for MIPS.  */

static const DebugFrame debug_frame = {
    .h.cie.len = sizeof(DebugFrameCIE) - 4, /* length after .len member */
    .h.cie.id = -1,
    .h.cie.version = 1,
    .h.cie.code_align = 1,
    .h.cie.data_align = -(TCG_TARGET_REG_BITS / 8) & 0x7f, /* sleb128 */
    .h.cie.return_column = TCG_REG_RA,

    /* Total FDE size does not include the "len" member.  */
    .h.fde.len = sizeof(DebugFrame) - offsetof(DebugFrame, h.fde.cie_offset),

    .fde_def_cfa = {
        12, TCG_REG_SP,                 /* DW_CFA_def_cfa sp, ... */
        (FRAME_SIZE & 0x7f) | 0x80,     /* ... uleb128 FRAME_SIZE */
        (FRAME_SIZE >> 7)
    },
    .fde_reg_ofs = {
        0x80 + 14, 1,                   /* DW_CFA_offset,  */
        0x80 + 13, 2,                   /* DW_CFA_offset,  */
        0x80 + 12, 3,                   /* DW_CFA_offset,  */
        0x80 + 11, 4,                   /* DW_CFA_offset,  */
        0x80 + 10, 5,                   /* DW_CFA_offset,  */
        0x80 +  9, 6,                   /* DW_CFA_offset,  */
        0x80 + 26, 7,                   /* DW_CFA_offset, ra, -24 */
        0x80 + 15, 8,                   /* DW_CFA_offset, fp,  -8 */
    }
};

void tcg_register_jit(const void *buf, size_t buf_size)
{
    tcg_register_jit_int(buf, buf_size, &debug_frame, sizeof(debug_frame));
}
