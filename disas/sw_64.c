/* sw_64-dis.c -- Disassemble Sw_64 AXP instructions
   Copyright 1996, 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
   Contributed by Richard Henderson <rth@tamu.edu>,
   patterned after the PPC opcode handling written by Ian Lance Taylor.

This file is part of GDB, GAS, and the GNU binutils.

GDB, GAS, and the GNU binutils are free software; you can redistribute
them and/or modify them under the terms of the GNU General Public
License as published by the Free Software Foundation; either version
2, or (at your option) any later version.

GDB, GAS, and the GNU binutils are distributed in the hope that they
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file; see the file COPYING.  If not, see
<http://www.gnu.org/licenses/>. */

#include "qemu/osdep.h"
#include "disas/dis-asm.h"

/* MAX is redefined below, so remove any previous definition. */
#undef MAX

/* The opcode table is an array of struct sw_64_opcode.  */

struct sw_64_opcode
{
  /* The opcode name.  */
  const char *name;

  /* The opcode itself.  Those bits which will be filled in with
     operands are zeroes.  */
  unsigned opcode;

  /* The opcode mask.  This is used by the disassembler.  This is a
     mask containing ones indicating those bits which must match the
     opcode field, and zeroes indicating those bits which need not
     match (and are presumably filled in by operands).  */
  unsigned mask;

  /* One bit flags for the opcode.  These are primarily used to
     indicate specific processors and environments support the
     instructions.  The defined values are listed below. */
  unsigned flags;

  /* An array of operand codes.  Each code is an index into the
     operand table.  They appear in the order which the operands must
     appear in assembly code, and are terminated by a zero.  */
  unsigned char operands[5];
};

/* The table itself is sorted by major opcode number, and is otherwise
   in the order in which the disassembler should consider
   instructions.  */
extern const struct sw_64_opcode sw_64_opcodes[];
extern const unsigned sw_64_num_opcodes;

/* Values defined for the flags field of a struct sw_64_opcode.  */

/* CPU Availability */
#define AXP_OPCODE_BASE  0x0001  /* Base architecture -- all cpus.  */
#define AXP_OPCODE_EV4   0x0002  /* EV4 specific PALcode insns.  */
#define AXP_OPCODE_EV5   0x0004  /* EV5 specific PALcode insns.  */
#define AXP_OPCODE_BWX   0x0100  /* Byte/word extension (amask bit 0).  */
#define AXP_OPCODE_CIX   0x0200  /* "Count" extension (amask bit 1).  */
#define AXP_OPCODE_MAX   0x0400  /* Multimedia extension (amask bit 8).  */
#define AXP_OPCODE_SW6   0x0800  /* EV6 specific PALcode insns.  */

#define AXP_OPCODE_NOPAL (~(AXP_OPCODE_EV4|AXP_OPCODE_EV5|AXP_OPCODE_SW6))

/* A macro to extract the major opcode from an instruction.  */
#define AXP_OP(i)	(((i) >> 26) & 0x3F)
#define AXP_LITOP(i)    (((i) >> 26) & 0x3D)

/* The total number of major opcodes. */
#define AXP_NOPS	0x40


/* The operands table is an array of struct sw_64_operand.  */

struct sw_64_operand
{
  /* The number of bits in the operand.  */
  unsigned int bits : 5;

  /* How far the operand is left shifted in the instruction.  */
  unsigned int shift : 5;

  /* The default relocation type for this operand.  */
  signed int default_reloc : 16;

  /* One bit syntax flags.  */
  unsigned int flags : 16;

  /* Insertion function.  This is used by the assembler.  To insert an
     operand value into an instruction, check this field.

     If it is NULL, execute
         i |= (op & ((1 << o->bits) - 1)) << o->shift;
     (i is the instruction which we are filling in, o is a pointer to
     this structure, and op is the opcode value; this assumes twos
     complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction and the operand value.  It will return the new value
     of the instruction.  If the ERRMSG argument is not NULL, then if
     the operand value is illegal, *ERRMSG will be set to a warning
     string (the operand will be inserted in any case).  If the
     operand value is legal, *ERRMSG will be unchanged (most operands
     can accept any value).  */
  unsigned (*insert) (unsigned instruction, int op,
                      const char **errmsg);

  /* Extraction function.  This is used by the disassembler.  To
     extract this operand type from an instruction, check this field.

     If it is NULL, compute
         op = ((i) >> o->shift) & ((1 << o->bits) - 1);
	 if ((o->flags & AXP_OPERAND_SIGNED) != 0
	     && (op & (1 << (o->bits - 1))) != 0)
	   op -= 1 << o->bits;
     (i is the instruction, o is a pointer to this structure, and op
     is the result; this assumes twos complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction value.  It will return the value of the operand.  If
     the INVALID argument is not NULL, *INVALID will be set to
     non-zero if this operand type can not actually be extracted from
     this operand (i.e., the instruction does not match).  If the
     operand is valid, *INVALID will not be changed.  */
  int (*extract) (unsigned instruction, int *invalid);
};

/* Elements in the table are retrieved by indexing with values from
   the operands field of the sw_64_opcodes table.  */

extern const struct sw_64_operand sw_64_operands[];
extern const unsigned sw_64_num_operands;

/* Values defined for the flags field of a struct sw_64_operand.  */

/* Mask for selecting the type for typecheck purposes */
#define AXP_OPERAND_TYPECHECK_MASK					\
  (AXP_OPERAND_PARENS | AXP_OPERAND_COMMA | AXP_OPERAND_IR |		\
   AXP_OPERAND_FPR | AXP_OPERAND_RELATIVE | AXP_OPERAND_SIGNED | 	\
   AXP_OPERAND_UNSIGNED)

/* This operand does not actually exist in the assembler input.  This
   is used to support extended mnemonics, for which two operands fields
   are identical.  The assembler should call the insert function with
   any op value.  The disassembler should call the extract function,
   ignore the return value, and check the value placed in the invalid
   argument.  */
#define AXP_OPERAND_FAKE	01

/* The operand should be wrapped in parentheses rather than separated
   from the previous by a comma.  This is used for the load and store
   instructions which want their operands to look like "Ra,disp(Rb)".  */
#define AXP_OPERAND_PARENS	02

/* Used in combination with PARENS, this suppresses the suppression of
   the comma.  This is used for "jmp Ra,(Rb),hint".  */
#define AXP_OPERAND_COMMA	04

/* This operand names an integer register.  */
#define AXP_OPERAND_IR		010

/* This operand names a floating point register.  */
#define AXP_OPERAND_FPR		020

/* This operand is a relative branch displacement.  The disassembler
   prints these symbolically if possible.  */
#define AXP_OPERAND_RELATIVE	040

/* This operand takes signed values.  */
#define AXP_OPERAND_SIGNED	0100

/* This operand takes unsigned values.  This exists primarily so that
   a flags value of 0 can be treated as end-of-arguments.  */
#define AXP_OPERAND_UNSIGNED	0200

/* Suppress overflow detection on this field.  This is used for hints. */
#define AXP_OPERAND_NOOVERFLOW	0400

/* Mask for optional argument default value.  */
#define AXP_OPERAND_OPTIONAL_MASK 07000

/* This operand defaults to zero.  This is used for jump hints.  */
#define AXP_OPERAND_DEFAULT_ZERO 01000

/* This operand should default to the first (real) operand and is used
   in conjunction with AXP_OPERAND_OPTIONAL.  This allows
   "and $0,3,$0" to be written as "and $0,3", etc.  I don't like
   it, but it's what DEC does.  */
#define AXP_OPERAND_DEFAULT_FIRST 02000

/* Similarly, this operand should default to the second (real) operand.
   This allows "negl $0" instead of "negl $0,$0".  */
#define AXP_OPERAND_DEFAULT_SECOND 04000

/* Similarly, this operand should default to the third (real) operand.
   This allows "selne $0,$1,$2,$2" to be written as "selne $0,$1,$2"   */
#define AXP_OPERAND_DEFAULT_THIRD 0xa00


/* Register common names */

#define AXP_REG_V0	0
#define AXP_REG_T0	1
#define AXP_REG_T1	2
#define AXP_REG_T2	3
#define AXP_REG_T3	4
#define AXP_REG_T4	5
#define AXP_REG_T5	6
#define AXP_REG_T6	7
#define AXP_REG_T7	8
#define AXP_REG_S0	9
#define AXP_REG_S1	10
#define AXP_REG_S2	11
#define AXP_REG_S3	12
#define AXP_REG_S4	13
#define AXP_REG_S5	14
#define AXP_REG_FP	15
#define AXP_REG_A0	16
#define AXP_REG_A1	17
#define AXP_REG_A2	18
#define AXP_REG_A3	19
#define AXP_REG_A4	20
#define AXP_REG_A5	21
#define AXP_REG_T8	22
#define AXP_REG_T9	23
#define AXP_REG_T10	24
#define AXP_REG_T11	25
#define AXP_REG_RA	26
#define AXP_REG_PV	27
#define AXP_REG_T12	27
#define AXP_REG_AT	28
#define AXP_REG_GP	29
#define AXP_REG_SP	30
#define AXP_REG_ZERO	31

enum bfd_reloc_code_real {
    BFD_RELOC_23_PCREL_S2,
    BFD_RELOC_SW_64_HINT
};

/* This file holds the Sw_64 AXP opcode table.  The opcode table includes
   almost all of the extended instruction mnemonics.  This permits the
   disassembler to use them, and simplifies the assembler logic, at the
   cost of increasing the table size.  The table is strictly constant
   data, so the compiler should be able to put it in the text segment.

   This file also holds the operand table.  All knowledge about inserting
   and extracting operands from instructions is kept in this file.

   The information for the base instruction set was compiled from the
   _Sw_64 Architecture Handbook_, Digital Order Number EC-QD2KB-TE,
   version 2.

   The information for the post-ev5 architecture extensions BWX, CIX and
   MAX came from version 3 of this same document, which is also available
   on-line at http://ftp.digital.com/pub/Digital/info/semiconductor
   /literature/sw_64hb2.pdf

   The information for the EV4 PALcode instructions was compiled from
   _DECchip 21064 and DECchip 21064A Sw_64 AXP Microprocessors Hardware
   Reference Manual_, Digital Order Number EC-Q9ZUA-TE, preliminary
   revision dated June 1994.

   The information for the EV5 PALcode instructions was compiled from
   _Sw_64 21164 Microprocessor Hardware Reference Manual_, Digital
   Order Number EC-QAEQB-TE, preliminary revision dated April 1995.  */

/* Local insertion and extraction functions */

static unsigned insert_rba (unsigned, int, const char **);
static unsigned insert_rca (unsigned, int, const char **);
static unsigned insert_rdc (unsigned, int, const char **);
static unsigned insert_za (unsigned, int, const char **);
static unsigned insert_zb (unsigned, int, const char **);
static unsigned insert_zc (unsigned, int, const char **);
static unsigned insert_zc2 (unsigned, int, const char **);
static unsigned insert_bdisp (unsigned, int, const char **);
static unsigned insert_jhint (unsigned, int, const char **);
static unsigned insert_ev6hwjhint (unsigned, int, const char **);

static int extract_rba (unsigned, int *);
static int extract_rca (unsigned, int *);
static int extract_rdc (unsigned, int *);
static int extract_za (unsigned, int *);
static int extract_zb (unsigned, int *);
static int extract_zc (unsigned, int *);
static int extract_zc2 (unsigned, int *);
static int extract_bdisp (unsigned, int *);
static int extract_jhint (unsigned, int *);
static int extract_ev6hwjhint (unsigned, int *);


/* The operands table  */

const struct sw_64_operand sw_64_operands[] =
{
  /* The fields are bits, shift, insert, extract, flags */
  /* The zero index is used to indicate end-of-list */
#define UNUSED		0
  { 0, 0, 0, 0, 0, 0 },

  /* The plain integer register fields */
#define RA		(UNUSED + 1)
  { 5, 21, 0, AXP_OPERAND_IR, 0, 0 },
#define RB		(RA + 1)
  { 5, 16, 0, AXP_OPERAND_IR, 0, 0 },
#define RC		(RB + 1)
  { 5, 0, 0, AXP_OPERAND_IR, 0, 0 },

  /* The plain fp register fields */
#define FA		(RC + 1)
  { 5, 21, 0, AXP_OPERAND_FPR, 0, 0 },
#define FB		(FA + 1)
  { 5, 16, 0, AXP_OPERAND_FPR, 0, 0 },
#define FC		(FB + 1)
  { 5, 0, 0, AXP_OPERAND_FPR, 0, 0 },

  /* The integer registers when they are ZERO */
#define ZA		(FC + 1)
  { 5, 21, 0, AXP_OPERAND_FAKE, insert_za, extract_za },
#define ZB		(ZA + 1)
  { 5, 16, 0, AXP_OPERAND_FAKE, insert_zb, extract_zb },
#define ZC		(ZB + 1)
  { 5, 0, 0, AXP_OPERAND_FAKE, insert_zc, extract_zc },

  /* The RB field when it needs parentheses */
#define PRB		(ZC + 1)
  { 5, 16, 0, AXP_OPERAND_IR|AXP_OPERAND_PARENS, 0, 0 },

  /* The RB field when it needs parentheses _and_ a preceding comma */
#define CPRB		(PRB + 1)
  { 5, 16, 0,
    AXP_OPERAND_IR|AXP_OPERAND_PARENS|AXP_OPERAND_COMMA, 0, 0 },

  /* The RB field when it must be the same as the RA field */
#define RBA		(CPRB + 1)
  { 5, 16, 0, AXP_OPERAND_FAKE, insert_rba, extract_rba },

  /* The RC field when it must be the same as the RB field */
#define RCA		(RBA + 1)
  { 5, 0, 0, AXP_OPERAND_FAKE, insert_rca, extract_rca },

#define RDC            (RCA + 1)
  { 5, 0, 0, AXP_OPERAND_FAKE, insert_rdc, extract_rdc },

  /* The RC field when it can *default* to RA */
#define DRC1		(RDC + 1)
  { 5, 0, 0,
    AXP_OPERAND_IR|AXP_OPERAND_DEFAULT_FIRST, 0, 0 },

  /* The RC field when it can *default* to RB */
#define DRC2		(DRC1 + 1)
  { 5, 0, 0,
    AXP_OPERAND_IR|AXP_OPERAND_DEFAULT_SECOND, 0, 0 },

  /* The RD field when it can *default* to RC.  */
#define DRC3            (DRC2 + 1)
  { 5, 0, 0,
    AXP_OPERAND_IR|AXP_OPERAND_DEFAULT_THIRD, 0, 0 },

  /* The FC field when it can *default* to RA */
#define DFC1		(DRC3 + 1)
  { 5, 0, 0,
    AXP_OPERAND_FPR|AXP_OPERAND_DEFAULT_FIRST, 0, 0 },

  /* The FC field when it can *default* to RB */
#define DFC2		(DFC1 + 1)
  { 5, 0, 0,
    AXP_OPERAND_FPR|AXP_OPERAND_DEFAULT_SECOND, 0, 0 },

  /* The FD field when it can *default* to FC.  */
#define DFC3            (DFC2 + 1)
  { 5, 0, 0,
    AXP_OPERAND_FPR|AXP_OPERAND_DEFAULT_THIRD, 0, 0 },

  /* The unsigned 8-bit literal of Operate format insns */
#define LIT		(DFC3 + 1)
  { 8, 13, -LIT, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The signed 16-bit displacement of Memory format insns.  From here
     we can't tell what relocation should be used, so don't use a default. */
#define MDISP		(LIT + 1)
  { 16, 0, -MDISP, AXP_OPERAND_SIGNED, 0, 0 },

  /* The signed "23-bit" aligned displacement of Branch format insns */
#define BDISP		(MDISP + 1)
  { 21, 0, BFD_RELOC_23_PCREL_S2,
    AXP_OPERAND_RELATIVE, insert_bdisp, extract_bdisp },

  /* The 25-bit PALcode function */
#define PALFN		(BDISP + 1)
  { 25, 0, -PALFN, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The optional signed "16-bit" aligned displacement of the JMP/JSR hint */
#define JMPHINT		(PALFN + 1)
  { 16, 0, BFD_RELOC_SW_64_HINT,
    AXP_OPERAND_RELATIVE|AXP_OPERAND_DEFAULT_ZERO|AXP_OPERAND_NOOVERFLOW,
    insert_jhint, extract_jhint },

  /* The optional hint to RET/JSR_COROUTINE */
#define RETHINT		(JMPHINT + 1)
  { 16, 0, -RETHINT,
    AXP_OPERAND_UNSIGNED|AXP_OPERAND_DEFAULT_ZERO, 0, 0 },

  /* The 12-bit displacement for the ev[46] hw_{ld,st} (pal1b/pal1f) insns */
#define EV4HWDISP	(RETHINT + 1)
#define SW6HWDISP	(EV4HWDISP)
  { 12, 0, -EV4HWDISP, AXP_OPERAND_SIGNED, 0, 0 },

  /* The 5-bit index for the ev4 hw_m[ft]pr (pal19/pal1d) insns */
#define EV4HWINDEX	(EV4HWDISP + 1)
  { 5, 0, -EV4HWINDEX, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The 8-bit index for the oddly unqualified hw_m[tf]pr insns
     that occur in DEC PALcode.  */
#define EV4EXTHWINDEX	(EV4HWINDEX + 1)
  { 8, 0, -EV4EXTHWINDEX, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The 10-bit displacement for the ev5 hw_{ld,st} (pal1b/pal1f) insns */
#define EV5HWDISP	(EV4EXTHWINDEX + 1)
  { 10, 0, -EV5HWDISP, AXP_OPERAND_SIGNED, 0, 0 },

  /* The 16-bit index for the ev5 hw_m[ft]pr (pal19/pal1d) insns */
#define EV5HWINDEX	(EV5HWDISP + 1)
  { 16, 0, -EV5HWINDEX, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The 16-bit combined index/scoreboard mask for the ev6
     hw_m[ft]pr (pal19/pal1d) insns */
#define EV6HWINDEX	(EV5HWINDEX + 1)
  { 16, 0, -EV6HWINDEX, AXP_OPERAND_UNSIGNED, 0, 0 },

  /* The 13-bit branch hint for the ev6 hw_jmp/jsr (pal1e) insn */
#define EV6HWJMPHINT	(EV6HWINDEX+ 1)
  { 8, 0, -EV6HWJMPHINT,
    AXP_OPERAND_RELATIVE|AXP_OPERAND_DEFAULT_ZERO|AXP_OPERAND_NOOVERFLOW,
    insert_ev6hwjhint, extract_ev6hwjhint },
/* for the third operand of ternary operands integer insn. */
#define R3              (EV6HWJMPHINT + 1)  
  { 5, 5, 0, AXP_OPERAND_IR, 0, 0 },
  /* The plain fp register fields */
#define F3              (R3 + 1)
  { 5, 5, 0, AXP_OPERAND_FPR, 0, 0 },
/* sw simd settle instruction lit */
#define FMALIT             (F3 + 1)
  { 5,  5, -FMALIT, AXP_OPERAND_UNSIGNED, 0, 0 },//V1.1
/*for pal to check disp which must be plus sign and less than 0x8000*/
#define LMDISP          (FMALIT + 1)
  { 15, 0, -LMDISP, AXP_OPERAND_UNSIGNED, 0, 0 },
#define RPIINDEX          (LMDISP + 1)
  { 8, 0, -RPIINDEX, AXP_OPERAND_UNSIGNED, 0, 0 },
#define ATMDISP          (RPIINDEX + 1)
  { 12, 0, -ATMDISP, AXP_OPERAND_SIGNED, 0, 0 },

#define DISP13          (ATMDISP + 1)
  { 13, 13, -DISP13, AXP_OPERAND_SIGNED, 0, 0},
#define DPFTH          (DISP13  + 1)
  { 5, 21, -DPFTH, AXP_OPERAND_UNSIGNED, 0, 0},
/* Used by vshfqb.  */
#define ZC2              (DPFTH + 1)
  { 5, 5, 0, AXP_OPERAND_FAKE, insert_zc2, extract_zc2 }
};

const unsigned sw_64_num_operands = sizeof(sw_64_operands)/sizeof(*sw_64_operands);

/* The RB field when it is the same as the RA field in the same insn.
   This operand is marked fake.  The insertion function just copies
   the RA field into the RB field, and the extraction function just
   checks that the fields are the same. */

/*ARGSUSED*/
static unsigned
insert_rba(unsigned insn, int value ATTRIBUTE_UNUSED, const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | (((insn >> 21) & 0x1f) << 16);
}

static int
extract_rba(unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL
      && ((insn >> 21) & 0x1f) != ((insn >> 16) & 0x1f))
    *invalid = 1;
  return 0;
}


/* The same for the RC field */

/*ARGSUSED*/
static unsigned
insert_rca(unsigned insn, int value ATTRIBUTE_UNUSED, const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | ((insn >> 21) & 0x1f);
}

static int
extract_rca(unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL
      && ((insn >> 21) & 0x1f) != (insn & 0x1f))
    *invalid = 1;
  return 0;
}

static unsigned
insert_rdc (unsigned insn,
            int value ATTRIBUTE_UNUSED,
            const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | ((insn >> 5) & 0x1f);
}

static int
extract_rdc (unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL
      && ((insn >> 5) & 0x1f) != (insn & 0x1f))
    *invalid = 1;
  return 0;
}

/* Fake arguments in which the registers must be set to ZERO */

/*ARGSUSED*/
static unsigned
insert_za(unsigned insn, int value ATTRIBUTE_UNUSED, const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | (31 << 21);
}

static int
extract_za(unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL && ((insn >> 21) & 0x1f) != 31)
    *invalid = 1;
  return 0;
}

/*ARGSUSED*/
static unsigned
insert_zb(unsigned insn, int value ATTRIBUTE_UNUSED, const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | (31 << 16);
}

static int
extract_zb(unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL && ((insn >> 16) & 0x1f) != 31)
    *invalid = 1;
  return 0;
}

/*ARGSUSED*/
static unsigned
insert_zc(unsigned insn, int value ATTRIBUTE_UNUSED, const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | 31;
}

static int
extract_zc(unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL && (insn & 0x1f) != 31)
    *invalid = 1;
  return 0;
}

static unsigned
insert_zc2 (unsigned insn,
           int value ATTRIBUTE_UNUSED,
           const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | 31 << 5;
}

static int
extract_zc2 (unsigned insn, int *invalid)
{
  if (invalid != (int *) NULL && ((insn >> 5) & 0x1f) != 31)
    *invalid = 1;
  return 0;
}

/* The displacement field of a Branch format insn.  */

static unsigned
insert_bdisp(unsigned insn, int value, const char **errmsg)
{
  if (errmsg != (const char **)NULL && (value & 3))
    *errmsg = "branch operand unaligned";
  return insn | ((value / 4) & 0x1FFFFF);
}

/*ARGSUSED*/
static int
extract_bdisp(unsigned insn, int *invalid ATTRIBUTE_UNUSED)
{
  return 4 * (((insn & 0x1FFFFF) ^ 0x100000) - 0x100000);
}

static unsigned
insert_bdisp26 (unsigned insn, int value, const char **errmsg)
{
  if (errmsg != (const char **)NULL && (value & 3))
    *errmsg = "branch operand unaligned";
  return insn | ((value / 4) & 0x3FFFFFF);
}

static int
extract_bdisp26 (unsigned insn, int *invalid ATTRIBUTE_UNUSED)
{
  return 4 * (((insn & 0x3FFFFFF) ^ 0x2000000) - 0x2000000);
}


/* The hint field of a JMP/JSR insn.  */
/* sw use 16 bits hint disp. */
static unsigned
insert_jhint (unsigned insn, int value, const char **errmsg)
{
  if (errmsg != (const char **)NULL && (value & 3))
    *errmsg ="jump hint unaligned";
  return insn | ((value / 4) & 0xFFFF);
}

static int
extract_jhint (unsigned insn, int *invalid ATTRIBUTE_UNUSED)
{
  return 4 * (((insn & 0xFFFF) ^ 0x8000) - 0x8000);
}

/* The hint field of an EV6 HW_JMP/JSR insn.  */

static unsigned
insert_ev6hwjhint(unsigned insn, int value, const char **errmsg)
{
  if (errmsg != (const char **)NULL && (value & 3))
    *errmsg = "jump hint unaligned";
  return insn | ((value / 4) & 0x1FFF);
}

/*ARGSUSED*/
static int
extract_ev6hwjhint(unsigned insn, int *invalid ATTRIBUTE_UNUSED)
{
  return 4 * (((insn & 0x1FFF) ^ 0x1000) - 0x1000);
}


/* Macros used to form opcodes */

/* The main opcode */
#define OP(x)		(((x) & 0x3F) << 26)
#define OP_MASK		0xFC000000

/* Branch format instructions */
#define BRA_(oo)	OP(oo)
#define BRA_MASK	OP_MASK
#define BRA(oo)		BRA_(oo), BRA_MASK

/* Floating point format instructions.  */
#define FP_(oo,fff)     (OP(oo) | (((fff) & 0xFF) << 5))
#define FP_MASK         (OP_MASK | 0x1FE0)
#define FP(oo,fff)      FP_(oo,fff), FP_MASK

#define FMA_(oo,fff)    (OP(oo) | (((fff) & 0x3F) << 10 ))
#define FMA_MASK        (OP_MASK | 0xFC00)
#define FMA(oo,fff)     FMA_(oo,fff), FMA_MASK

/* Memory format instructions */
#define MEM_(oo)	OP(oo)
#define MEM_MASK	OP_MASK
#define MEM(oo)		MEM_(oo), MEM_MASK

/* Memory/Func Code format instructions */
#define MFC_(oo,ffff)	(OP(oo) | ((ffff) & 0xFFFF))
#define MFC_MASK	(OP_MASK | 0xFFFF)
#define MFC(oo,ffff)	MFC_(oo,ffff), MFC_MASK

/* Memory/Branch format instructions */
#define MBR_(oo,h)	(OP(oo) | (((h) & 3) << 14))
#define MBR_MASK	(OP_MASK | 0xC000)
#define MBR(oo,h)	MBR_(oo,h), MBR_MASK

// Now sw Operate format instructions is different with SW1.
#define OPR_(oo,ff)     (OP(oo) | (((ff) & 0xFF) << 5))
#define OPRL_(oo,ff)    (OPR_((oo),(ff)) )
#define OPR_MASK        (OP_MASK | 0x1FE0)
#define OPR(oo,ff)      OPR_(oo,ff), OPR_MASK
#define OPRL(oo,ff)     OPRL_(oo,ff), OPR_MASK

// sw ternary operands Operate format instructions
#define TOPR_(oo,ff)     (OP(oo) | (((ff) & 0x07) << 10))
#define TOPRL_(oo,ff)    (TOPR_((oo),(ff))) 
#define TOPR_MASK        (OP_MASK | 0x1C00)
#define TOPR(oo,ff)      TOPR_(oo,ff), TOPR_MASK
#define TOPRL(oo,ff)     TOPRL_(oo,ff), TOPR_MASK

// sw atom instructions
#define ATMEM_(oo,h)  (OP(oo) | (((h) & 0xF) << 12))
#define ATMEM_MASK    (OP_MASK | 0xF000)
#define ATMEM(oo,h)   ATMEM_(oo,h), ATMEM_MASK

// sw privilege instructions
#define PRIRET_(oo,h)  (OP(oo) | (((h) & 0x1) << 20))
#define PRIRET_MASK    (OP_MASK | 0x100000)
#define PRIRET(oo,h)   PRIRET_(oo,h), PRIRET_MASK

// sw rpi_rcsr,rpi_wcsr
#define CSR_(oo,ff)     (OP(oo) | (((ff) & 0xFF) << 8))
#define CSR_MASK        (OP_MASK | 0xFF00)
#define CSR(oo,ff)      CSR_(oo,ff), CSR_MASK
/* Generic PALcode format instructions */
#define PCD_(oo,ff)     (OP(oo) | (ff << 25))
#define PCD_MASK        OP_MASK
#define PCD(oo,ff)      PCD_(oo,ff), PCD_MASK

/* Specific PALcode instructions */
#define SPCD_(oo,ffff)	(OP(oo) | ((ffff) & 0x3FFFFFF))
#define SPCD_MASK	0xFFFFFFFF
#define SPCD(oo,ffff)	SPCD_(oo,ffff), SPCD_MASK

/* Hardware memory (hw_{ld,st}) instructions */
#define EV4HWMEM_(oo,f)	(OP(oo) | (((f) & 0xF) << 12))
#define EV4HWMEM_MASK	(OP_MASK | 0xF000)
#define EV4HWMEM(oo,f)	EV4HWMEM_(oo,f), EV4HWMEM_MASK

#define EV5HWMEM_(oo,f)	(OP(oo) | (((f) & 0x3F) << 10))
#define EV5HWMEM_MASK	(OP_MASK | 0xF800)
#define EV5HWMEM(oo,f)	EV5HWMEM_(oo,f), EV5HWMEM_MASK

#define SW6HWMEM_(oo,f)	(OP(oo) | (((f) & 0xF) << 12))
#define SW6HWMEM_MASK	(OP_MASK | 0xF000)
#define SW6HWMEM(oo,f)	SW6HWMEM_(oo,f), SW6HWMEM_MASK

#define SW6HWMBR_(oo,h)	(OP(oo) | (((h) & 7) << 13))
#define SW6HWMBR_MASK	(OP_MASK | 0xE000)
#define SW6HWMBR(oo,h)	SW6HWMBR_(oo,h), SW6HWMBR_MASK

#define LOGX_(oo,ff)     (OP(oo) | (((ff) & 0x3F) << 10))
#define LOGX_MASK        (0xF0000000)
#define LOGX(oo,ff)      LOGX_(oo,ff), LOGX_MASK

#define PSE_LOGX_(oo,ff)  (OP(oo) | (((ff) & 0x3F) << 10) | (((ff) >> 0x6) << 26 ) | 0x3E0 )
#define PSE_LOGX(oo,ff)   PSE_LOGX_(oo,ff), LOGX_MASK

/* Abbreviations for instruction subsets.  */
#define BASE			AXP_OPCODE_BASE
#define SW6			AXP_OPCODE_BASE
#define BWX			AXP_OPCODE_BWX
#define CIX			AXP_OPCODE_CIX
#define MAX			AXP_OPCODE_MAX

/* Common combinations of arguments */
#define ARG_NONE		{ 0 }
#define ARG_BRA			{ RA, BDISP }
#define ARG_FBRA		{ FA, BDISP }
#define ARG_FP			{ FA, FB, DFC1 }
#define ARG_FPZ1		{ ZA, FB, DFC1 }
#define ARG_MEM			{ RA, MDISP, PRB }
#define ARG_FMEM		{ FA, MDISP, PRB }
#define ARG_OPR			{ RA, RB, DRC1 }
#define ARG_OPRCAS              { RA, RB, RC }
#define ARG_OPRL		{ RA, LIT, DRC1 }
#define ARG_OPRZ1		{ ZA, RB, DRC1 }
#define ARG_OPRLZ1		{ ZA, LIT, RC }
#define ARG_PCD			{ PALFN }
#define ARG_EV4HWMEM		{ RA, EV4HWDISP, PRB }
#define ARG_EV4HWMPR		{ RA, RBA, EV4HWINDEX }
#define ARG_EV5HWMEM		{ RA, EV5HWDISP, PRB }
#define ARG_SW6HWMEM		{ RA, SW6HWDISP, PRB }
#define ARG_FPL                 { FA,LIT, DFC1 }  /*ADD NEW SIMD FUNCTION*/
#define ARG_FMA               { FA,FB,F3, DFC1 } /* ADD NEW FUNCITONS */
#define ARG_PREFETCH            { ZA, MDISP, PRB }
#define ARG_FCMOV               { FA,FB,F3, DFC3 } /* ADD NEW FCMOV */
#define ARG_TOPR                 { RA, RB,R3, DRC3 }
#define ARG_TOPRL                { RA, LIT, R3,DRC3 }
//for cmov** instruction
#define ARG_TOPC                 { RA, RB, R3, RDC } 
#define ARG_TOPCL                { RA, LIT, R3, RDC }
#define ARG_TOPFC                 { FA, FB, F3, RDC } 
#define ARG_TOPFCL                { FA, LIT, F3, RDC }
#define ARG_FMAL               { FA,FB,FMALIT, DFC1 } // sw settle instruction ,Modified by WCH20081104 V1.1
#define ARG_ATMEM                { RA, ATMDISP, PRB } //atom insitruction
#define ARG_VUAMEM                { FA, ATMDISP, PRB } //WCH20090805 New V1.1 add
#define ARG_OPRLZ3              { RA, LIT, ZC }     /*ADD NEW FUNCTION*/
#define ARG_DISP13              {DISP13, RC}


/* The opcode table.

   The format of the opcode table is:

   NAME OPCODE MASK { OPERANDS }

   NAME		is the name of the instruction.

   OPCODE	is the instruction opcode.

   MASK		is the opcode mask; this is used to tell the disassembler
		which bits in the actual opcode must match OPCODE.

   OPERANDS	is the list of operands.

   The preceding macros merge the text of the OPCODE and MASK fields.

   The disassembler reads the table in order and prints the first
   instruction which matches, so this table is sorted to put more
   specific instructions before more general instructions.

   Otherwise, it is sorted by major opcode and minor function code.

   There are three classes of not-really-instructions in this table:

   ALIAS	is another name for another instruction.  Some of
		these come from the Architecture Handbook, some
		come from the original gas opcode tables.  In all
		cases, the functionality of the opcode is unchanged.

   PSEUDO	a stylized code form endorsed by Chapter A.4 of the
		Architecture Handbook.

   EXTRA	a stylized code form found in the original gas tables.

   And two annotations:

   EV56 BUT	opcodes that are officially introduced as of the ev56,
		but with defined results on previous implementations.

   EV56 UNA	opcodes that were introduced as of the ev56 with
		presumably undefined results on previous implementations
		that were not assigned to a particular extension.
*/

const struct sw_64_opcode sw_64_opcodes[] = {
  { "sys_call/b",       PCD(0x00,0x00), SW6, ARG_PCD },
  { "sys_call",         PCD(0x00,0x01), SW6, ARG_PCD },
  { "draina",           SPCD(0x00,0x0002), SW6, ARG_NONE },
  { "bpt",              SPCD(0x00,0x0080), SW6, ARG_NONE },
  { "bugchk",           SPCD(0x00,0x0081), SW6, ARG_NONE },
  { "callsys",          SPCD(0x00,0x0083), SW6, ARG_NONE },
  { "chmk",             SPCD(0x00,0x0083), SW6, ARG_NONE },
  { "imb",              SPCD(0x00,0x0086), SW6, ARG_NONE },
  { "rduniq",           SPCD(0x00,0x009e), SW6, ARG_NONE },
  { "wruniq",           SPCD(0x00,0x009f), SW6, ARG_NONE },
  { "gentrap",          SPCD(0x00,0x00aa), SW6, ARG_NONE },
  { "call",             MEM(0x01), SW6, { RA, CPRB, JMPHINT } },
  { "ret",              MEM(0x02), SW6, { RA, CPRB, RETHINT } },
  { "ret",              MEM_(0x02)| (31 << 21) | (26 << 16) | 1,0xFFFFFFFF, SW6, { 0 } }, /*pseudo*/
  { "jmp",              MEM(0x03), SW6, { RA, CPRB, JMPHINT } },
  { "br",               BRA(0x04), SW6, { ZA, BDISP } },       /* pseudo */
  { "br",               BRA(0x04), SW6, ARG_BRA },
  { "bsr",              BRA(0x05), SW6, ARG_BRA },
  { "memb",             MFC(0x06,0x0000), SW6, ARG_NONE },
  { "imemb",            MFC(0x06,0x0001), SW6, ARG_NONE },
  { "rtc",              MFC(0x06,0x0020), SW6, { RA, ZB } },
  { "rtc",              MFC(0x06,0x0020), SW6, { RA, RB } },
  { "rcid",             MFC(0x06,0x0040), SW6, { RA , ZB} },
  { "halt",             MFC(0x06,0x0080), SW6, { ZA, ZB } },
  { "rd_f",             MFC(0x06,0x1000), SW6, { RA, ZB } },
  { "wr_f",             MFC(0x06,0x1020), SW6, { RA, ZB } },
  { "rtid",             MFC(0x06,0x1040), SW6, { RA } },
  { "pri_rcsr",         CSR(0x06,0xFE), SW6, { RA, RPIINDEX ,ZB } },
  { "pri_wcsr",         CSR(0x06,0xFF), SW6, { RA, RPIINDEX ,ZB } },
  { "pri_ret",          PRIRET(0x07,0x0),   SW6,  { RA } },
  { "pri_ret/b",        PRIRET(0x07,0x1),   SW6,  { RA } },
  { "lldw",             ATMEM(0x08,0x0), SW6, ARG_ATMEM },
  { "lldl",             ATMEM(0x08,0x1), SW6, ARG_ATMEM },
  { "ldw_inc",          ATMEM(0x08,0x2), SW6, ARG_ATMEM },
  { "ldl_inc",          ATMEM(0x08,0x3), SW6, ARG_ATMEM },
  { "ldw_dec",          ATMEM(0x08,0x4), SW6, ARG_ATMEM },
  { "ldl_dec",          ATMEM(0x08,0x5), SW6, ARG_ATMEM },
  { "ldw_set",          ATMEM(0x08,0x6), SW6, ARG_ATMEM },
  { "ldl_set",          ATMEM(0x08,0x7), SW6, ARG_ATMEM },
  { "lstw",             ATMEM(0x08,0x8), SW6, ARG_ATMEM },
  { "lstl",             ATMEM(0x08,0x9), SW6, ARG_ATMEM },
  { "ldw_nc",           ATMEM(0x08,0xA), SW6, ARG_ATMEM },
  { "ldl_nc",           ATMEM(0x08,0xB), SW6, ARG_ATMEM },
  { "ldd_nc",           ATMEM(0x08,0xC), SW6, ARG_VUAMEM },
  { "stw_nc",           ATMEM(0x08,0xD), SW6, ARG_ATMEM },
  { "stl_nc",           ATMEM(0x08,0xE), SW6, ARG_ATMEM },
  { "std_nc",           ATMEM(0x08,0xF), SW6, ARG_VUAMEM },
  { "fillcs",           MEM(0x09), SW6, ARG_PREFETCH },
  { "ldwe",             MEM(0x09), SW6, ARG_FMEM },   //sw6 v0.2a
  { "e_fillcs",         MEM(0x0A), SW6, ARG_PREFETCH },
  { "ldse",             MEM(0x0A), SW6, ARG_FMEM },
  { "lds4e",            MEM(0x0A), SW6, ARG_FMEM },/* pseudo SW6 SIMD WCH20081028*/
  { "fillcs_e",         MEM(0x0B), SW6, ARG_PREFETCH },
  { "ldde",             MEM(0x0B), SW6, ARG_FMEM },
  { "ldd4e",            MEM(0x0B), SW6, ARG_FMEM },/* pseudo SW6 SIMD WCH20081028*/
  { "e_fillde",         MEM(0x0C), SW6, ARG_PREFETCH },
  { "vlds",             MEM(0x0C), SW6, ARG_FMEM },
  { "v4lds",            MEM(0x0C), SW6, ARG_FMEM },
  { "vldd",             MEM(0x0D), SW6, ARG_FMEM },
  { "v4ldd",            MEM(0x0D), SW6, ARG_FMEM },
  { "vsts",             MEM(0x0E), SW6, ARG_FMEM },
  { "v4sts",            MEM(0x0E), SW6, ARG_FMEM },
  { "vstd",             MEM(0x0F), SW6, ARG_FMEM },
  { "v4std",            MEM(0x0F), SW6, ARG_FMEM },
  { "addw",             OPR(0x10,0x00), SW6, ARG_OPR },
  { "sextl",            OPR(0x10,0x00), SW6, ARG_OPRZ1 },       /* pseudo */
  { "subw",             OPR(0x10,0x01), SW6, ARG_OPR },
  { "negw",             OPR(0x10,0x01),  SW6, ARG_OPRZ1 },      /* pseudo swgcc */
  { "s4addw",           OPR(0x10,0x02), SW6, ARG_OPR },
  { "s4subw",           OPR(0x10,0x03), SW6, ARG_OPR },
  { "s8addw",           OPR(0x10,0x04), SW6, ARG_OPR },
  { "addl",             OPR(0x10,0x08), SW6, ARG_OPR },
  { "subl",             OPR(0x10,0x09), SW6, ARG_OPR },
  { "negl",             OPR(0x10,0x09),  SW6, ARG_OPRZ1 },      /* pseudo swgcc */
  { "s8subw",           OPR(0x10,0x05), SW6, ARG_OPR },
  { "slll",              OPR(0x10,0x48), SW6, ARG_OPR },
  { "neglv",            OPR(0x10,0x09),  SW6, ARG_OPRZ1 },      /* pseudo swgcc */
  { "s4addl",           OPR(0x10,0x0A), SW6, ARG_OPR },
  { "s4subl",           OPR(0x10,0x0B), SW6, ARG_OPR },
  { "s8addl",           OPR(0x10,0x0C), SW6, ARG_OPR },
  { "s8subl",           OPR(0x10,0x0D), SW6, ARG_OPR },
  { "mulw",             OPR(0x10,0x10), SW6, ARG_OPR },
  { "divw",             OPR(0x10,0x11), SW6, ARG_OPR },
  { "udivw",            OPR(0x10,0x12), SW6, ARG_OPR },
  { "remw",             OPR(0x10,0x13), SW6, ARG_OPR },
  { "uremw",            OPR(0x10,0x14), SW6, ARG_OPR },
  { "mull",             OPR(0x10,0x18), SW6, ARG_OPR },
  { "umulh",            OPR(0x10,0x19), SW6, ARG_OPR },
  { "divl",             OPR(0x10,0x1A), SW6, ARG_OPR },
  { "udivl",            OPR(0x10,0x1B), SW6, ARG_OPR },
  { "reml",             OPR(0x10,0x1C), SW6, ARG_OPR },
  { "ureml",            OPR(0x10,0x1D), SW6, ARG_OPR },
  { "addpi",            OPRL(0x10,0x1E), SW6, {ZA, LIT, RC} },
  { "addpis",           OPRL(0x10,0x1F), SW6, {ZA, LIT, RC} },
  { "cmpeq",            OPR(0x10,0x28), SW6, ARG_OPR },
  { "cmplt",            OPR(0x10,0x29), SW6, ARG_OPR },
  { "cmple",            OPR(0x10,0x2A), SW6, ARG_OPR },
  { "cmpult",           OPR(0x10,0x2B), SW6, ARG_OPR },
  { "cmpule",           OPR(0x10,0x2C), SW6, ARG_OPR },
  { "sbt",              OPR(0x10,0x2D), SW6, ARG_OPR },
  { "cbt",              OPR(0x10,0x2E), SW6, ARG_OPR },
  { "and",              OPR(0x10,0x38), SW6, ARG_OPR },
  { "bic",              OPR(0x10,0x39), SW6, ARG_OPR },
  { "andnot",           OPR(0x10,0x39), SW6, ARG_OPR },/* pseudo */
  { "nop",              OPR(0x10,0x3A), SW6, { ZA, ZB, ZC } }, /* now unop has a new expression */
  { "excb",             OPR(0x10,0x3A), SW6, { ZA, ZB, ZC } }, /* pseudo */
  { "clr",              OPR(0x10,0x3A),SW6, { ZA, ZB, RC } }, /* pseudo swgcc */
  { "mov",              OPR(0x10,0x3A), SW6, { ZA, RB, RC } },  /* pseudo */
  { "or",               OPR(0x10,0x3A), SW6, ARG_OPR },
  { "bis",              OPR(0x10,0x3A), SW6, ARG_OPR },
  { "not",              OPR(0x10,0x3B), SW6, ARG_OPRZ1 },       /* pseudo swgcc */
  { "ornot",            OPR(0x10,0x3B), SW6, ARG_OPR },
  { "xor",              OPR(0x10,0x3C), SW6, ARG_OPR },
  { "amask",            OPR_(0x10,0x3A)|31<<16,OPR_MASK, SW6, { ZA, RB, RC } },  /* pseudo */
  { "eqv",              OPR(0x10,0x3D), SW6, ARG_OPR },
  { "xornot",           OPR(0x10,0x3D), SW6, ARG_OPR }, /* pseudo swgcc */
  { "inslb",            OPR(0x10,0x40), SW6, ARG_OPR },
  { "ins0b",            OPR(0x10,0x40), SW6, ARG_OPR },
  { "inslh",            OPR(0x10,0x41), SW6, ARG_OPR },
  { "ins1b",            OPR(0x10,0x41), SW6, ARG_OPR },
  { "inslw",            OPR(0x10,0x42), SW6, ARG_OPR },
  { "ins2b",            OPR(0x10,0x42), SW6, ARG_OPR },
  { "insll",            OPR(0x10,0x43), SW6, ARG_OPR },
  { "ins3b",            OPR(0x10,0x43), SW6, ARG_OPR },
  { "inshb",            OPR(0x10,0x44), SW6, ARG_OPR },
  { "ins4b",            OPR(0x10,0x44), SW6, ARG_OPR },
  { "inshh",            OPR(0x10,0x45), SW6, ARG_OPR },
  { "ins5b",            OPR(0x10,0x45), SW6, ARG_OPR },
  { "inshw",            OPR(0x10,0x46), SW6, ARG_OPR },
  { "ins6b",            OPR(0x10,0x46), SW6, ARG_OPR },
  { "inshl",            OPR(0x10,0x47), SW6, ARG_OPR },
  { "ins7b",            OPR(0x10,0x47), SW6, ARG_OPR },
  { "srll",             OPR(0x10,0x49), SW6, ARG_OPR },
  { "sral",             OPR(0x10,0x4A), SW6, ARG_OPR },
  { "roll",             OPR(0x10,0x4B), SW6, ARG_OPR },
  { "sllw",             OPR(0x10,0x4C), SW6, ARG_OPR }, //sw6 v0.2a
  { "srlw",             OPR(0x10,0x4D), SW6, ARG_OPR }, //sw6 v0.2a
  { "sraw",             OPR(0x10,0x4E), SW6, ARG_OPR }, //sw6 v0.2a
  { "rolw",             OPR(0x10,0x4F), SW6, ARG_OPR }, //sw6 v0.2a
  { "extlb",            OPR(0x10,0x50), SW6, ARG_OPR },
  { "ext0b",            OPR(0x10,0x50), SW6, ARG_OPR },
  { "extlh",            OPR(0x10,0x51), SW6, ARG_OPR },
  { "ext1b",            OPR(0x10,0x51), SW6, ARG_OPR },
  { "extlw",            OPR(0x10,0x52), SW6, ARG_OPR },
  { "ext2b",            OPR(0x10,0x52), SW6, ARG_OPR },
  { "extll",            OPR(0x10,0x53), SW6, ARG_OPR },
  { "ext3b",            OPR(0x10,0x53), SW6, ARG_OPR },
  { "exthb",            OPR(0x10,0x54), SW6, ARG_OPR },
  { "ext4b",            OPR(0x10,0x54), SW6, ARG_OPR },
  { "exthh",            OPR(0x10,0x55), SW6, ARG_OPR },
  { "ext5b",            OPR(0x10,0x55), SW6, ARG_OPR },
  { "exthw",            OPR(0x10,0x56), SW6, ARG_OPR },
  { "ext6b",            OPR(0x10,0x56), SW6, ARG_OPR },
  { "exthl",            OPR(0x10,0x57), SW6, ARG_OPR },
  { "ext7b",            OPR(0x10,0x57), SW6, ARG_OPR },
  { "ctpop",            OPR(0x10,0x58), SW6, ARG_OPRZ1 },
  { "ctlz",             OPR(0x10,0x59), SW6, ARG_OPRZ1 },
  { "cttz",             OPR(0x10,0x5A), SW6, ARG_OPRZ1 },
  { "revbh",            OPR(0x10,0x5B), SW6, ARG_OPRZ1 },
  { "revbw",            OPR(0x10,0x5C), SW6, ARG_OPRZ1 },
  { "revbl",            OPR(0x10,0x5D), SW6, ARG_OPRZ1 },
  { "casw",             OPR(0x10,0x5E), SW6, ARG_OPR },
  { "casl",             OPR(0x10,0x5F), SW6, ARG_OPR },
  { "masklb",           OPR(0x10,0x60), SW6, ARG_OPR },
  { "mask0b",           OPR(0x10,0x60), SW6, ARG_OPR },
  { "masklh",           OPR(0x10,0x61), SW6, ARG_OPR },
  { "mask1b",           OPR(0x10,0x61), SW6, ARG_OPR },
  { "masklw",           OPR(0x10,0x62), SW6, ARG_OPR },
  { "mask2b",           OPR(0x10,0x62), SW6, ARG_OPR },
  { "maskll",           OPR(0x10,0x63), SW6, ARG_OPR },
  { "mask3b",           OPR(0x10,0x63), SW6, ARG_OPR },
  { "maskhb",           OPR(0x10,0x64), SW6, ARG_OPR },
  { "mask4b",           OPR(0x10,0x64), SW6, ARG_OPR },
  { "maskhh",           OPR(0x10,0x65), SW6, ARG_OPR },
  { "mask5b",           OPR(0x10,0x65), SW6, ARG_OPR },
  { "maskhw",           OPR(0x10,0x66), SW6, ARG_OPR },
  { "mask6b",           OPR(0x10,0x66), SW6, ARG_OPR },
  { "maskhl",           OPR(0x10,0x67), SW6, ARG_OPR },
  { "mask7b",           OPR(0x10,0x67), SW6, ARG_OPR },
  { "zap",              OPR(0x10,0x68), SW6, ARG_OPR },
  { "zapnot",           OPR(0x10,0x69), SW6, ARG_OPR },
  { "sextb",            OPR(0x10,0x6A), SW6, ARG_OPRZ1},
  { "sexth",            OPR(0x10,0x6B), SW6, ARG_OPRZ1 },
  { "cmpgeb",           OPR(0x10,0x6C), SW6, ARG_OPR },
  { "fimovs",           OPR(0x10,0x70), SW6, { FA, ZB, RC } },
  { "fimovd",           OPR(0x10,0x78), SW6, { FA, ZB, RC } },
  { "ftoid",            OPR(0x10,0x78), SW6, { FA, ZB, RC } },
  { "cmovdl",           OPR(0x10,0x72), SW6, { ZA, FB, RC } },
  { "cmovdl_g",         OPR(0x10,0x74), SW6, { ZA, FB, RC } },
  { "cmovdl_p",         OPR(0x10,0x7a), SW6, { ZA, FB, RC } },
  { "cmovdl_z",         OPR(0x10,0x7c), SW6, { ZA, FB, RC } },
  { "cmovdl_n",         OPR(0x10,0x80), SW6, { ZA, FB, RC } },
  { "cmovdlu",          OPR(0x10,0x81), SW6, { ZA, FB, RC } },
  { "cmovdlu_g",        OPR(0x10,0x82), SW6, { ZA, FB, RC } },
  { "cmovdlu_p",        OPR(0x10,0x83), SW6, { ZA, FB, RC } },
  { "cmovdlu_z",        OPR(0x10,0x84), SW6, { ZA, FB, RC } },
  { "cmovdlu_n",        OPR(0x10,0x85), SW6, { ZA, FB, RC } },  
  { "cmovdwu",          OPR(0x10,0x86), SW6, { ZA, FB, RC } },
  { "cmovdwu_g",        OPR(0x10,0x87), SW6, { ZA, FB, RC } },
  { "cmovdwu_p",        OPR(0x10,0x88), SW6, { ZA, FB, RC } },
  { "cmovdwu_z",        OPR(0x10,0x89), SW6, { ZA, FB, RC } },
  { "cmovdwu_n",        OPR(0x10,0x8a), SW6, { ZA, FB, RC } },  
  { "cmovdw",           OPR(0x10,0x8b), SW6, { ZA, FB, RC } },
  { "cmovdw_g",         OPR(0x10,0x8c), SW6, { ZA, FB, RC } },
  { "cmovdw_p",         OPR(0x10,0x8d), SW6, { ZA, FB, RC } },
  { "cmovdw_z",         OPR(0x10,0x8e), SW6, { ZA, FB, RC } },
  { "cmovdw_n",         OPR(0x10,0x8f), SW6, { ZA, FB, RC } },

  { "addw",             OPRL(0x12,0x00), SW6, ARG_OPRL },
  { "sextl",            OPRL(0x12,0x00), SW6, ARG_OPRLZ1 },     /* pseudo */
  { "subw",             OPRL(0x12,0x01), SW6, ARG_OPRL },
  { "negw",             OPRL(0x12,0x01), SW6, ARG_OPRLZ1 },    /* pseudo  swgcc */
  { "s4addw",           OPRL(0x12,0x02), SW6, ARG_OPRL },
  { "s4subw",           OPRL(0x12,0x03), SW6, ARG_OPRL },
  { "s8addw",           OPRL(0x12,0x04), SW6, ARG_OPRL },
  { "s8subw",           OPRL(0x12,0x05), SW6, ARG_OPRL },
  { "addl",             OPRL(0x12,0x08), SW6, ARG_OPRL },
  { "subl",             OPRL(0x12,0x09), SW6, ARG_OPRL },
  { "negl",             OPRL(0x12,0x09), SW6, ARG_OPRLZ1 },    /* pseudo swgcc */
  { "neglv",            OPRL(0x12,0x09), SW6, ARG_OPRLZ1 },    /* pseudo swgcc */
  { "s4addl",           OPRL(0x12,0x0A), SW6, ARG_OPRL },
  { "s4subl",           OPRL(0x12,0x0B), SW6, ARG_OPRL },
  { "s8addl",           OPRL(0x12,0x0C), SW6, ARG_OPRL },
  { "s8subl",           OPRL(0x12,0x0D), SW6, ARG_OPRL },
  { "mulw",             OPRL(0x12,0x10), SW6, ARG_OPRL },
  { "mull",             OPRL(0x12,0x18), SW6, ARG_OPRL },
  { "umulh",            OPRL(0x12,0x19), SW6, ARG_OPRL },
  { "cmpeq",            OPRL(0x12,0x28), SW6, ARG_OPRL },
  { "cmplt",            OPRL(0x12,0x29), SW6, ARG_OPRL },
  { "cmple",            OPRL(0x12,0x2A), SW6, ARG_OPRL },
  { "sbt",              OPRL(0x12,0x2D), SW6, ARG_OPRL },
  { "cbt",              OPRL(0x12,0x2E), SW6, ARG_OPRL },
  { "bis",              OPRL(0x12,0x3A),SW6, ARG_OPRL },
  { "cmpult",           OPRL(0x12,0x2B), SW6, ARG_OPRL },
  { "cmpule",           OPRL(0x12,0x2C), SW6, ARG_OPRL },
  { "and",              OPRL(0x12,0x38), SW6, ARG_OPRL },
  { "bic",              OPRL(0x12,0x39), SW6, ARG_OPRL },
  { "andnot",           OPRL(0x12,0x39), SW6, ARG_OPRL },/* pseudo */
  { "mov",              OPRL(0x12,0x3A), SW6, { ZA, LIT, RC } },  /* pseudo */
  { "implver",          OPRL_(0x12,0x3A)|2<<13,0xFFFFFFE0,SW6, {ZA,RC } }, /* pseudo swgcc */
  { "amask",            OPRL(0x12,0x3A), SW6, { ZA, LIT, RC } },  /* pseudo */
  { "or",               OPRL(0x12,0x3A),SW6, ARG_OPRL },
  { "not",              OPRL(0x12,0x3B),SW6, ARG_OPRLZ1 },      /* pseudo swgcc */
  { "ornot",            OPRL(0x12,0x3B),SW6, ARG_OPRL },
  { "xor",              OPRL(0x12,0x3C),SW6, ARG_OPRL },
  { "eqv",              OPRL(0x12,0x3D),SW6, ARG_OPRL },
  { "xornot",           OPRL(0x12,0x3D),SW6, ARG_OPRL },/* pseudo swgcc */
  { "inslb",            OPRL(0x12,0x40),SW6, ARG_OPRL },
  { "ins0b",            OPRL(0x12,0x40),SW6, ARG_OPRL },
  { "inslh",            OPRL(0x12,0x41),SW6, ARG_OPRL },
  { "ins1b",            OPRL(0x12,0x41),SW6, ARG_OPRL },
  { "inslw",            OPRL(0x12,0x42),SW6, ARG_OPRL },
  { "ins2b",            OPRL(0x12,0x42),SW6, ARG_OPRL },
  { "insll",            OPRL(0x12,0x43),SW6, ARG_OPRL },
  { "ins3b",            OPRL(0x12,0x43),SW6, ARG_OPRL },
  { "inshb",            OPRL(0x12,0x44),SW6, ARG_OPRL },
  { "ins4b",            OPRL(0x12,0x44),SW6, ARG_OPRL },
  { "inshh",            OPRL(0x12,0x45),SW6, ARG_OPRL },
  { "ins5b",            OPRL(0x12,0x45),SW6, ARG_OPRL },
  { "inshw",            OPRL(0x12,0x46),SW6, ARG_OPRL },
  { "ins6b",            OPRL(0x12,0x46),SW6, ARG_OPRL },
  { "inshl",            OPRL(0x12,0x47),SW6, ARG_OPRL },
  { "ins7b",            OPRL(0x12,0x47),SW6, ARG_OPRL },
  { "slll",             OPRL(0x12,0x48),SW6, ARG_OPRL },
  { "srll",             OPRL(0x12,0x49),SW6, ARG_OPRL },
  { "sral",             OPRL(0x12,0x4A),SW6, ARG_OPRL },
  { "roll",             OPRL(0x12,0x4B),SW6, ARG_OPRL },
  { "sllw",             OPRL(0x12,0x4C),SW6, ARG_OPRL },//sw6 v0.2a
  { "srlw",             OPRL(0x12,0x4D),SW6, ARG_OPRL },//sw6 v0.2a
  { "sraw",             OPRL(0x12,0x4E),SW6, ARG_OPRL },//sw6 v0.2a
  { "rolw",             OPRL(0x12,0x4F),SW6, ARG_OPRL },//sw6 v0.2a
  { "extlb",            OPRL(0x12,0x50),SW6, ARG_OPRL },
  { "ext0b",            OPRL(0x12,0x50),SW6, ARG_OPRL },
  { "extlh",            OPRL(0x12,0x51),SW6, ARG_OPRL },
  { "ext1b",            OPRL(0x12,0x51),SW6, ARG_OPRL },
  { "extlw",            OPRL(0x12,0x52),SW6, ARG_OPRL },
  { "ext2b",            OPRL(0x12,0x52),SW6, ARG_OPRL },
  { "extll",            OPRL(0x12,0x53),SW6, ARG_OPRL },
  { "ext3b",            OPRL(0x12,0x53),SW6, ARG_OPRL },
  { "exthb",            OPRL(0x12,0x54),SW6, ARG_OPRL },
  { "ext4b",            OPRL(0x12,0x54),SW6, ARG_OPRL },
  { "ext5b",            OPRL(0x12,0x55),SW6, ARG_OPRL },
  { "exthw",            OPRL(0x12,0x56),SW6, ARG_OPRL },
  { "ext6b",            OPRL(0x12,0x56),SW6, ARG_OPRL },
  { "exthl",            OPRL(0x12,0x57),SW6, ARG_OPRL },
  { "ext7b",            OPRL(0x12,0x57),SW6, ARG_OPRL },
  { "masklb",           OPRL(0x12,0x60),SW6, ARG_OPRL },
  { "mask0b",           OPRL(0x12,0x60),SW6, ARG_OPRL },
  { "masklh",           OPRL(0x12,0x61),SW6, ARG_OPRL },
  { "mask1b",           OPRL(0x12,0x61),SW6, ARG_OPRL },
  { "masklw",           OPRL(0x12,0x62),SW6, ARG_OPRL },
  { "mask2b",           OPRL(0x12,0x62),SW6, ARG_OPRL },
  { "maskll",           OPRL(0x12,0x63),SW6, ARG_OPRL },
  { "mask3b",           OPRL(0x12,0x63),SW6, ARG_OPRL },
  { "maskhb",           OPRL(0x12,0x64),SW6, ARG_OPRL },
  { "mask4b",           OPRL(0x12,0x64),SW6, ARG_OPRL },
  { "maskhh",           OPRL(0x12,0x65),SW6, ARG_OPRL },
  { "mask5b",           OPRL(0x12,0x65),SW6, ARG_OPRL },
  { "maskhw",           OPRL(0x12,0x66),SW6, ARG_OPRL },
  { "mask6b",           OPRL(0x12,0x66),SW6, ARG_OPRL },
  { "maskhl",           OPRL(0x12,0x67),SW6, ARG_OPRL },
  { "mask7b",           OPRL(0x12,0x67),SW6, ARG_OPRL },
  { "zap",              OPRL(0x12,0x68),SW6, ARG_OPRL },
  { "zapnot",           OPRL(0x12,0x69),SW6, ARG_OPRL },
  { "sextb",            OPRL(0x12,0x6A),SW6, ARG_OPRLZ1 },
  { "sexth",            OPRL(0x12,0x6B),SW6, ARG_OPRLZ1 },
  { "cmpgeb",           OPRL(0x12,0x6C),SW6, ARG_OPRL },
  { "seleq",            TOPR(0x11,0x0), SW6, ARG_TOPR },
  { "selge",            TOPR(0x11,0x1), SW6, ARG_TOPR },
  { "selgt",            TOPR(0x11,0x2), SW6, ARG_TOPR },
  { "selle",            TOPR(0x11,0x3), SW6, ARG_TOPR },
  { "sellt",            TOPR(0x11,0x4), SW6, ARG_TOPR },
  { "selne",            TOPR(0x11,0x5), SW6, ARG_TOPR },
  { "seleq",            TOPRL(0x13,0x0),SW6, ARG_TOPRL },
  { "selge",            TOPRL(0x13,0x1),SW6, ARG_TOPRL },
  { "selgt",            TOPRL(0x13,0x2),SW6, ARG_TOPRL },
  { "selle",            TOPRL(0x13,0x3),SW6, ARG_TOPRL },
  { "sellt",            TOPRL(0x13,0x4),SW6, ARG_TOPRL },
  { "selne",            TOPRL(0x13,0x5),SW6, ARG_TOPRL },
  { "sellbc",           TOPR(0x11,0x6), SW6, ARG_TOPR },
  { "sellbc",           TOPRL(0x13,0x6),SW6, ARG_TOPRL },
  { "sellbs",           TOPR(0x11,0x7), SW6, ARG_TOPR },
  { "sellbs",           TOPRL(0x13,0x7),SW6, ARG_TOPRL },
  { "vlog",             LOGX(0x14,0x00), SW6, ARG_FMA },

  { "vbicw",            PSE_LOGX(0x14,0x30), SW6, { FA , FB , DFC1 } },
  { "vxorw",            PSE_LOGX(0x14,0x3c), SW6, { FA , FB , DFC1 } },
  { "vandw",            PSE_LOGX(0x14,0xc0), SW6, { FA , FB , DFC1 } },
  { "veqvw",            PSE_LOGX(0x14,0xc3), SW6, { FA , FB , DFC1 } },
  { "vornotw",          PSE_LOGX(0x14,0xf3), SW6, { FA , FB , DFC1 } },
  { "vbisw",            PSE_LOGX(0x14,0xfc), SW6, { FA , FB , DFC1 } },

  { "fadds",            FP(0x18,0x00), SW6, ARG_FP },
  { "faddd",            FP(0x18,0x01), SW6, ARG_FP },
  { "fsubs",            FP(0x18,0x02), SW6, ARG_FP },
  { "fsubd",            FP(0x18,0x03), SW6, ARG_FP },
  { "fmuls",            FP(0x18,0x04), SW6, ARG_FP },
  { "fmuld",            FP(0x18,0x05), SW6, ARG_FP },
  { "fdivs",            FP(0x18,0x06), SW6, ARG_FP },
  { "fdivd",            FP(0x18,0x07), SW6, ARG_FP },
  { "fsqrts",           FP(0x18,0x08), SW6, ARG_FPZ1 },
  { "fsqrtd",           FP(0x18,0x09), SW6, ARG_FPZ1 },
  { "fcmpeq",           FP(0x18,0x10), SW6, ARG_FP },
  { "fcmple",           FP(0x18,0x11), SW6, ARG_FP },
  { "fcmplt",           FP(0x18,0x12), SW6, ARG_FP },
  { "fcmpun",           FP(0x18,0x13), SW6, ARG_FP },

  { "fcvtsd",           FP(0x18,0x20), SW6, ARG_FPZ1 }, //WCH20120521
  { "fcvtds",           FP(0x18,0x21), SW6, ARG_FPZ1 }, //WCH20120521
  { "fcvtdl_g",         FP(0x18,0x22), SW6, ARG_FPZ1 },
  { "fcvtdl_p",         FP(0x18,0x23), SW6, ARG_FPZ1 },
  { "fcvtdl_z",         FP(0x18,0x24), SW6, ARG_FPZ1 },
  { "fcvtdl_n",         FP(0x18,0x25), SW6, ARG_FPZ1 },
  { "fcvtdl",           FP(0x18,0x27), SW6, ARG_FPZ1 },
  { "fcvtwl",           FP(0x18,0x28), SW6, ARG_FPZ1 },
  { "fcvtlw",           FP(0x18,0x29), SW6, ARG_FPZ1 },
  { "fcvtls",           FP(0x18,0x2d), SW6, ARG_FPZ1 },
  { "fcvtld",           FP(0x18,0x2f), SW6, ARG_FPZ1 },

  { "fnop",             FP(0x18,0x030), SW6, { ZA, ZB, ZC } },  /* pseudo swgcc */
  { "fclr",             FP(0x18,0x030), SW6, { ZA, ZB, FC } },  /* pseudo swgcc */
  { "fabs",             FP(0x18,0x030), SW6, ARG_FPZ1 },        /* pseudo swgcc */
  { "fcpys",            FP(0x18,0x30), SW6, ARG_FP },
  { "fmov",             FP(0x18,0x30), SW6,  { FA, RBA, FC } }, /* pseudo */
  { "fcpyse",           FP(0x18,0x31), SW6, ARG_FP },
  { "fneg",             FP(0x18,0x32), SW6, { FA, RBA, FC } },/* pseudo */
  { "fcpysn",           FP(0x18,0x32), SW6, ARG_FP },

  { "ifmovs",           FP(0x18,0x40), SW6, { RA, ZB, FC } },
  { "ifmovd",           FP(0x18,0x41), SW6, { RA, ZB, FC } },
  { "itofd",            FP(0x18,0x41), SW6, { RA, ZB, FC } },
  { "cmovls",           FP(0x18,0x48), SW6, { ZA, RB, FC } },
  { "cmovws",           FP(0x18,0x49), SW6, { ZA, RB, FC } },
  { "cmovld",           FP(0x18,0x4a), SW6, { ZA, RB, FC } },
  { "cmovwd",           FP(0x18,0x4b), SW6, { ZA, RB, FC } },
  { "cmovuls",          FP(0x18,0x4c), SW6, { ZA, RB, FC } },
  { "cmovuws",          FP(0x18,0x4d), SW6, { ZA, RB, FC } },
  { "cmovuld",          FP(0x18,0x4e), SW6, { ZA, RB, FC } },
  { "cmovuwd",          FP(0x18,0x4f), SW6, { ZA, RB, FC } },
  { "rfpcr",            FP(0x18,0x50), SW6, { FA, RBA, RCA } },
  { "wfpcr",            FP(0x18,0x51), SW6, { FA, RBA, RCA } },
  { "setfpec0",         FP(0x18,0x54), SW6, ARG_NONE },
  { "setfpec1",         FP(0x18,0x55), SW6, ARG_NONE },
  { "setfpec2",         FP(0x18,0x56), SW6, ARG_NONE },
  { "setfpec3",         FP(0x18,0x57), SW6, ARG_NONE }, 
  { "frecs",            FP(0x18,0x58), SW6, { FA, ZB, FC } },
  { "frecd",            FP(0x18,0x59), SW6, { FA, ZB, FC } },
  { "fris",             FP(0x18,0x5a), SW6, { ZA, FB, FC } },
  { "fris_g",           FP(0x18,0x5b), SW6, { ZA, FB, FC } },
  { "fris_p",           FP(0x18,0x5c), SW6, { ZA, FB, FC } },
  { "fris_z",           FP(0x18,0x5d), SW6, { ZA, FB, FC } },
  { "fris_n",           FP(0x18,0x5f), SW6, { ZA, FB, FC } },
  { "frid",             FP(0x18,0x60), SW6, { ZA, FB, FC } },
  { "frid_g",           FP(0x18,0x61), SW6, { ZA, FB, FC } },
  { "frid_p",           FP(0x18,0x62), SW6, { ZA, FB, FC } },
  { "frid_z",           FP(0x18,0x63), SW6, { ZA, FB, FC } },
  { "frid_n",           FP(0x18,0x64), SW6, { ZA, FB, FC } },
 
  { "fmas",             FMA(0x19,0x00), SW6, ARG_FMA },
  { "fmad",             FMA(0x19,0x01), SW6, ARG_FMA },
  { "fmss",             FMA(0x19,0x02), SW6, ARG_FMA },
  { "fmsd",             FMA(0x19,0x03), SW6, ARG_FMA },
  { "fnmas",            FMA(0x19,0x04), SW6, ARG_FMA },
  { "fnmad",            FMA(0x19,0x05), SW6, ARG_FMA },
  { "fnmss",            FMA(0x19,0x06), SW6, ARG_FMA },
  { "fnmsd",            FMA(0x19,0x07), SW6, ARG_FMA },

//fcmov*(SW6) to fcmov*(EV6)  for fcmov* no need in sw64, and fsel*->fcmov* has difference in operands number,so it should not repalce directly. The default FD should be the same FC but not FA
  { "fseleq",           FMA(0x19,0x10), SW6, ARG_FCMOV },
  { "fselne",           FMA(0x19,0x11), SW6, ARG_FCMOV },
  { "fsellt",           FMA(0x19,0x12), SW6, ARG_FCMOV },
  { "fselle",           FMA(0x19,0x13), SW6, ARG_FCMOV },
  { "fselgt",           FMA(0x19,0x14), SW6, ARG_FCMOV },
  { "fselge",           FMA(0x19,0x15), SW6, ARG_FCMOV },

  { "vaddw",            FP(0x1A,0x00), SW6, ARG_FP },
  { "vaddw",            FP(0x1A,0x20), SW6, ARG_FPL },
  { "vsubw",            FP(0x1A,0x01), SW6, ARG_FP },
  { "vsubw",            FP(0x1A,0x21), SW6, ARG_FPL },
  { "vcmpgew",          FP(0x1A,0x02), SW6, ARG_FP },
  { "vcmpgew",          FP(0x1A,0x22), SW6, ARG_FPL },
  { "vcmpeqw",          FP(0x1A,0x03), SW6, ARG_FP },
  { "vcmpeqw",          FP(0x1A,0x23), SW6, ARG_FPL },
  { "vcmplew",          FP(0x1A,0x04), SW6, ARG_FP },
  { "vcmplew",          FP(0x1A,0x24), SW6, ARG_FPL },
  { "vcmpltw",          FP(0x1A,0x05), SW6, ARG_FP },
  { "vcmpltw",          FP(0x1A,0x25), SW6, ARG_FPL },
  { "vcmpulew",         FP(0x1A,0x06), SW6, ARG_FP },
  { "vcmpulew",         FP(0x1A,0x26), SW6, ARG_FPL },
{ "vcmpultw",         FP(0x1A,0x07), SW6, ARG_FP },
  { "vcmpultw",         FP(0x1A,0x27), SW6, ARG_FPL },

  { "vsllw",            FP(0x1A,0x08), SW6, ARG_FP },
  { "vsllw",            FP(0x1A,0x28), SW6, ARG_FPL },
  { "vsrlw",            FP(0x1A,0x09), SW6, ARG_FP },
  { "vsrlw",            FP(0x1A,0x29), SW6, ARG_FPL },
  { "vsraw",            FP(0x1A,0x0A), SW6, ARG_FP },
  { "vsraw",            FP(0x1A,0x2A), SW6, ARG_FPL },
  { "vrolw",            FP(0x1A,0x0B), SW6, ARG_FP },
  { "vrolw",            FP(0x1A,0x2B), SW6, ARG_FPL },
  { "sllow",            FP(0x1A,0x0C), SW6, ARG_FP },
  { "sllow",            FP(0x1A,0x2C), SW6, ARG_FPL },
  { "srlow",            FP(0x1A,0x0D), SW6, ARG_FP },
  { "srlow",            FP(0x1A,0x2D), SW6, ARG_FPL },
  { "vaddl",            FP(0x1A,0x0E), SW6, ARG_FP },
  { "vaddl",            FP(0x1A,0x2E), SW6, ARG_FPL },
  { "vsubl",            FP(0x1A,0x0F), SW6, ARG_FP },
  { "vsubl",            FP(0x1A,0x2F), SW6, ARG_FPL },
  { "ctpopow",          FP(0x1A,0x18), SW6, { FA, ZB, DFC1 } },
  { "ctlzow",           FP(0x1A,0x19), SW6, { FA, ZB, DFC1 } },
  { "vucaddw",          FP(0x1A,0x40), SW6, ARG_FP },
  { "vucaddw",          FP(0x1A,0x60), SW6, ARG_FPL },
  { "vucsubw",          FP(0x1A,0x41), SW6, ARG_FP },
  { "vucsubw",          FP(0x1A,0x61), SW6, ARG_FPL },
  { "vucaddh",          FP(0x1A,0x42), SW6, ARG_FP },
  { "vucaddh",          FP(0x1A,0x62), SW6, ARG_FPL },
  { "vucsubh",          FP(0x1A,0x43), SW6, ARG_FP },
{ "vucsubh",          FP(0x1A,0x63), SW6, ARG_FPL },
  { "vucaddb",          FP(0x1A,0x44), SW6, ARG_FP },
  { "vucaddb",          FP(0x1A,0x64), SW6, ARG_FPL },
  { "vucsubb",          FP(0x1A,0x45), SW6, ARG_FP },
  { "vucsubb",          FP(0x1A,0x65), SW6, ARG_FPL },
  { "vadds",            FP(0x1A,0x80), SW6, ARG_FP },
  { "v4adds",           FP(0x1A,0x80), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vaddd",            FP(0x1A,0x81), SW6, ARG_FP },
  { "v4addd",           FP(0x1A,0x81), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vsubs",            FP(0x1A,0x82), SW6, ARG_FP },
  { "v4subs",           FP(0x1A,0x82), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vsubd",            FP(0x1A,0x83), SW6, ARG_FP },
  { "v4subd",           FP(0x1A,0x83), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vmuls",            FP(0x1A,0x84), SW6, ARG_FP },
  { "v4muls",           FP(0x1A,0x84), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vmuld",            FP(0x1A,0x85), SW6, ARG_FP },
  { "v4muld",           FP(0x1A,0x85), SW6, ARG_FP },/* pseudo SW6 SIMD WCH20081028*/
  { "vdivs",            FP(0x1A,0x86), SW6, ARG_FP },
  { "vdivd",            FP(0x1A,0x87), SW6, ARG_FP },
  { "vsqrts",           FP(0x1A,0x88), SW6, ARG_FPZ1 },
  { "vsqrtd",           FP(0x1A,0x89), SW6, ARG_FPZ1 },
  { "vfcmpeq",          FP(0x1A,0x8C), SW6, ARG_FP },
  { "vfcmple",          FP(0x1A,0x8D), SW6, ARG_FP },
  { "vfcmplt",          FP(0x1A,0x8E), SW6, ARG_FP },
  { "vfcmpun",          FP(0x1A,0x8F), SW6, ARG_FP },
  { "vcpys",            FP(0x1A,0x90), SW6, ARG_FP },
  { "vfmov",            FP(0x1A,0x90), SW6, { FA, RBA, FC } }, //V1.1 WCH20081105
 { "vcpyse",           FP(0x1A,0x91), SW6, ARG_FP }, //WCH20081117 SW6 1.0
  { "vcpysn",           FP(0x1A,0x92), SW6, ARG_FP }, //WCH20081117 SW6 1.0
  { "vmas",             FMA(0x1B,0x00), SW6, ARG_FMA },
  { "vmad",             FMA(0x1B,0x01), SW6, ARG_FMA },
  { "vmss",             FMA(0x1B,0x02), SW6, ARG_FMA },
  { "vmsd",             FMA(0x1B,0x03), SW6, ARG_FMA },
  { "vnmas",            FMA(0x1B,0x04), SW6, ARG_FMA },
  { "vnmad",            FMA(0x1B,0x05), SW6, ARG_FMA },
  { "vnmss",            FMA(0x1B,0x06), SW6, ARG_FMA },
  { "vnmsd",            FMA(0x1B,0x07), SW6, ARG_FMA },
  { "vfseleq",          FMA(0x1B,0x10), SW6, ARG_FMA },
  { "vfsellt",          FMA(0x1B,0x12), SW6, ARG_FMA },
  { "vfselle",          FMA(0x1B,0x13), SW6, ARG_FMA },
  { "vseleqw",          FMA(0x1B,0x18), SW6, ARG_FMA },
  { "vseleqw",          FMA(0x1B,0x38), SW6, ARG_FMAL },
  { "vsellbcw",         FMA(0x1B,0x19), SW6, ARG_FMA },
  { "vsellbcw",         FMA(0x1B,0x39), SW6, ARG_FMAL },
  { "vselltw",          FMA(0x1B,0x1A), SW6, ARG_FMA },
  { "vselltw",          FMA(0x1B,0x3A), SW6, ARG_FMAL },
  { "vsellew",          FMA(0x1B,0x1B), SW6, ARG_FMA },
  { "vsellew",          FMA(0x1B,0x3B), SW6, ARG_FMAL },
  { "vinsw",            FMA(0x1B,0x20), SW6, ARG_FMAL },
  { "vinsf",            FMA(0x1B,0x21), SW6, ARG_FMAL },
  { "vextw",            FMA(0x1B,0x22), SW6, { FA, FMALIT, DFC1 }},// Modified by WCH20081104 V1.1
  { "vextf",            FMA(0x1B,0x23), SW6, { FA, FMALIT, DFC1 }},// Modified by WCH20081104 V1.1
  { "vcpyw",            FMA(0x1B,0x24), SW6, { FA, DFC1 }},// Modified by WCH20081104 V1.1
 { "vcpyf",            FMA(0x1B,0x25), SW6, { FA, DFC1 }},// Modified by WCH20081104 V1.1 
  { "vconw",            FMA(0x1B,0x26), SW6, ARG_FMA },
  { "vshfw",            FMA(0x1B,0x27), SW6, ARG_FMA },
  { "vcons",            FMA(0x1B,0x28), SW6, ARG_FMA },
  { "vcond",            FMA(0x1B,0x29), SW6, ARG_FMA },
  { "vldw_u",           ATMEM(0x1C,0x0), SW6, ARG_VUAMEM },
  { "vstw_u",           ATMEM(0x1C,0x1), SW6, ARG_VUAMEM },
  { "vlds_u",           ATMEM(0x1C,0x2), SW6, ARG_VUAMEM },
  { "vsts_u",           ATMEM(0x1C,0x3), SW6, ARG_VUAMEM },
  { "vldd_u",           ATMEM(0x1C,0x4), SW6, ARG_VUAMEM },
  { "vstd_u",           ATMEM(0x1C,0x5), SW6, ARG_VUAMEM },
  { "vstw_ul",          ATMEM(0x1C,0x8), SW6, ARG_VUAMEM },
  { "vstw_uh",          ATMEM(0x1C,0x9), SW6, ARG_VUAMEM },
  { "vsts_ul",          ATMEM(0x1C,0xA), SW6, ARG_VUAMEM },
  { "vsts_uh",          ATMEM(0x1C,0xB), SW6, ARG_VUAMEM },
  { "vstd_ul",          ATMEM(0x1C,0xC), SW6, ARG_VUAMEM },
  { "vstd_uh",          ATMEM(0x1C,0xD), SW6, ARG_VUAMEM },
  { "vldd_nc",          ATMEM(0x1C,0xE), SW6, ARG_VUAMEM },
  { "vstd_nc",          ATMEM(0x1C,0xF), SW6, ARG_VUAMEM },

  { "lbr",              BRA(0x1D), SW6, ARG_BRA },

  { "ldbu_a",           ATMEM(0x1E,0x0), SW6, ARG_ATMEM },
  { "ldhu_a",           ATMEM(0x1E,0x1), SW6, ARG_ATMEM },
  { "ldw_a",            ATMEM(0x1E,0x2), SW6, ARG_ATMEM },
  { "ldl_a",            ATMEM(0x1E,0x3), SW6, ARG_ATMEM },
  { "flds_a",           ATMEM(0x1E,0x4), SW6, ARG_VUAMEM },
  { "fldd_a",           ATMEM(0x1E,0x5), SW6, ARG_VUAMEM },
  { "stb_a",            ATMEM(0x1E,0x6), SW6, ARG_ATMEM },
  { "sth_a",            ATMEM(0x1E,0x7), SW6, ARG_ATMEM },
  { "stw_a",            ATMEM(0x1E,0x8), SW6, ARG_ATMEM },
  { "stl_a",            ATMEM(0x1E,0x9), SW6, ARG_ATMEM },
  { "fsts_a",           ATMEM(0x1E,0xA), SW6, ARG_VUAMEM },
  { "fstd_a",           ATMEM(0x1E,0xB), SW6, ARG_VUAMEM },
  { "flushd",           MEM(0x20), SW6, ARG_PREFETCH }, //Modified by WCH20081205 SW61121 v1.0
  { "ldbu",             MEM(0x20), SW6, ARG_MEM },
  { "evictdg",          MEM(0x21), SW6, ARG_PREFETCH }, /* v0.2c */
  { "ldhu",             MEM(0x21), SW6, ARG_MEM },
  { "s_fillcs",         MEM(0x22), SW6, ARG_PREFETCH },
  { "ldw",              MEM(0x22), SW6, ARG_MEM },
  { "wh64",             MFC(0x22,0xF800), SW6, { ZA, PRB } },   /* sw6f una */
  { "s_fillde",         MEM(0x23), SW6, ARG_PREFETCH },
  { "ldl",              MEM(0x23), SW6, ARG_MEM },
  { "evictdl",          MEM(0x24), SW6, ARG_PREFETCH }, /* v0.2c */
  { "ldl_u",            MEM(0x24), SW6, ARG_MEM },
  { "pri_ldw/p",        SW6HWMEM(0x25,0x0), SW6, ARG_SW6HWMEM },
  { "pri_ldw_inc/p",    SW6HWMEM(0x25,0x2), SW6, ARG_SW6HWMEM },
  { "pri_ldw_dec/p",    SW6HWMEM(0x25,0x4), SW6, ARG_SW6HWMEM },
  { "pri_ldw_set/p",    SW6HWMEM(0x25,0x6), SW6, ARG_SW6HWMEM },
  { "pri_ldw/v",        SW6HWMEM(0x25,0x8), SW6, ARG_SW6HWMEM },
  { "pri_ldw/vpte",     SW6HWMEM(0x25,0xA), SW6, ARG_SW6HWMEM }, //WCH20081124 SW6-1121 v1.0
  { "pri_ldl/p",        SW6HWMEM(0x25,0x1), SW6, ARG_SW6HWMEM },
  { "pri_ldl_inc/p",    SW6HWMEM(0x25,0x3), SW6, ARG_SW6HWMEM },
  { "pri_ldl_dec/p",    SW6HWMEM(0x25,0x5), SW6, ARG_SW6HWMEM },
  { "pri_ldl_set/p",    SW6HWMEM(0x25,0x7), SW6, ARG_SW6HWMEM },
  { "pri_ldl/v",        SW6HWMEM(0x25,0x9), SW6, ARG_SW6HWMEM },
  { "pri_ldl/vpte",     SW6HWMEM(0x25,0xB), SW6, ARG_SW6HWMEM }, //WCH20081124 SW6-1121 v1.0
  { "fillde",           MEM(0x26), SW6, ARG_PREFETCH },
  { "flds",             MEM(0x26), SW6, ARG_FMEM },
  { "fillde_e",         MEM(0x27), SW6, ARG_PREFETCH },
  { "fldd",             MEM(0x27), SW6, ARG_FMEM },

  { "stb",              MEM(0x28), SW6, ARG_MEM },
  { "sth",              MEM(0x29), SW6, ARG_MEM },
  { "stw",              MEM(0x2A), SW6, ARG_MEM },
  { "stl",              MEM(0x2B), SW6, ARG_MEM },
  { "stl_u",            MEM(0x2C), SW6, ARG_MEM },
  { "pri_stw/p",        SW6HWMEM(0x2D,0x0), SW6, ARG_SW6HWMEM },
  { "pri_stw/v",        SW6HWMEM(0x2D,0x8), SW6, ARG_SW6HWMEM },
  { "pri_stl/p",        SW6HWMEM(0x2D,0x1), SW6, ARG_SW6HWMEM },
  { "pri_stl/v",        SW6HWMEM(0x2D,0x9), SW6, ARG_SW6HWMEM },
  { "fsts",             MEM(0x2E), SW6, ARG_FMEM },
  { "fstd",             MEM(0x2F), SW6, ARG_FMEM },
  { "beq",              BRA(0x30), SW6, ARG_BRA },
  { "bne",              BRA(0x31), SW6, ARG_BRA },
  { "blt",              BRA(0x32), SW6, ARG_BRA },
  { "ble",              BRA(0x33), SW6, ARG_BRA },
  { "bgt",              BRA(0x34), SW6, ARG_BRA },
  { "bge",              BRA(0x35), SW6, ARG_BRA },
  { "blbc",             BRA(0x36), SW6, ARG_BRA },
  { "blbs",             BRA(0x37), SW6, ARG_BRA },

  { "fbeq",             BRA(0x38), SW6, ARG_FBRA },
  { "fbne",             BRA(0x39), SW6, ARG_FBRA },
  { "fblt",             BRA(0x3A), SW6, ARG_FBRA },
  { "fble",             BRA(0x3B), SW6, ARG_FBRA },
  { "fbgt",             BRA(0x3C), SW6, ARG_FBRA },
  { "fbge",             BRA(0x3D), SW6, ARG_FBRA },
  { "ldi",              MEM(0x3E), SW6, { RA, MDISP, ZB } },   /* pseudo */
  { "ldi",              MEM(0x3E), SW6, ARG_MEM },
  { "ldih",             MEM(0x3F), SW6, { RA, MDISP, ZB } },   /* pseudo */
  { "ldih",             MEM(0x3F), SW6, ARG_MEM },
  { "unop",             MEM_(0x3F) | (30 << 16), MEM_MASK, SW6 , { ZA } }
};

const unsigned sw_64_num_opcodes = sizeof(sw_64_opcodes)/sizeof(*sw_64_opcodes);

/* OSF register names.  */

static const char * const osf_regnames[64] = {
  "$r0", "$r1", "$r2", "$r3" , "$r4", "$r5", "$r6", "$r7",
  "$r8", "$r9", "$r10", "$r11" , "$r12", "$r13", "$r14", "fp",
  "$r16", "$r17", "$r18", "$r19" , "$r20", "$r21", "$r22", "$r23",
  "$r24", "$r25", "ra", "$r27" , "$r28", "$r29", "sp", "$r31",
  "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7",
  "$f8", "$f9", "$f10", "$f11", "$f12", "$f13", "$f14", "$f15",
  "$f16", "$f17", "$f18", "$f19", "$f20", "$f21", "$f22", "$f23",
  "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31"
};

/* VMS register names.  */

static const char * const vms_regnames[64] = {
  "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
  "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
  "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23",
  "R24", "AI", "RA", "PV", "AT", "FP", "SP", "RZ",
  "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
  "F8", "F9", "F10", "F11", "F12", "F13", "F14", "F15",
  "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23",
  "F24", "F25", "F26", "F27", "F28", "F29", "F30", "FZ"
};

/* Disassemble Sw_64 instructions.  */

int
print_insn_sw_64 (bfd_vma memaddr, struct disassemble_info *info)
{
  static const struct sw_64_opcode *opcode_index[AXP_NOPS+1];
  const char * const * regnames;
  const struct sw_64_opcode *opcode, *opcode_end;
  const unsigned char *opindex;
  unsigned insn, op, isa_mask;
  int need_comma;

  /* Initialize the majorop table the first time through */
  if (!opcode_index[0])
    {
      opcode = sw_64_opcodes;
      opcode_end = opcode + sw_64_num_opcodes;

      for (op = 0; op < AXP_NOPS; ++op)
	{
	  opcode_index[op] = opcode;
          if ((AXP_LITOP (opcode->opcode) != 0x10)
              && (AXP_LITOP (opcode->opcode) != 0x11))
            {
              while (opcode < opcode_end && op == AXP_OP (opcode->opcode))
                ++opcode;
            }
          else
            {
              while (opcode < opcode_end && op == AXP_LITOP (opcode->opcode))
                ++opcode;
            }
	}
      opcode_index[op] = opcode;
    }

  if (info->flavour == bfd_target_evax_flavour)
    regnames = vms_regnames;
  else
    regnames = osf_regnames;

  isa_mask = AXP_OPCODE_NOPAL;
  switch (info->mach)
    {
    case bfd_mach_sw_64:
      isa_mask |= AXP_OPCODE_SW6;
      break;
    }

  /* Read the insn into a host word */
  {
    bfd_byte buffer[4];
    int status = (*info->read_memory_func) (memaddr, buffer, 4, info);
    if (status != 0)
      {
	(*info->memory_error_func) (status, memaddr, info);
	return -1;
      }
    insn = bfd_getl32 (buffer);
  }

  /* Get the major opcode of the instruction.  */
  if((AXP_LITOP (insn)==0x10) || (AXP_LITOP (insn)==0x11))
       op = AXP_LITOP (insn);
  else if((AXP_OP(insn) & 0x3C) == 0x14 ) //logx
       op=0x14;
  else
       op = AXP_OP (insn);
  /* Find the first match in the opcode table.  */
  opcode_end = opcode_index[op + 1];
  for (opcode = opcode_index[op]; opcode < opcode_end; ++opcode)
    {
      if ((insn ^ opcode->opcode) & opcode->mask)
	continue;

      if (!(opcode->flags & isa_mask))
	continue;

      /* Make two passes over the operands.  First see if any of them
	 have extraction functions, and, if they do, make sure the
	 instruction is valid.  */
      {
	int invalid = 0;
	for (opindex = opcode->operands; *opindex != 0; opindex++)
	  {
	    const struct sw_64_operand *operand = sw_64_operands + *opindex;
	    if (operand->extract)
	      (*operand->extract) (insn, &invalid);
	  }
	if (invalid)
	  continue;
      }

      /* The instruction is valid.  */
      goto found;
    }

  /* No instruction found */
  (*info->fprintf_func) (info->stream, ".long %#08x", insn);

  return 4;

found:
  if (!strncmp ("sys_call", opcode->name,8))
    {
      if (insn & (0x1 << 25))
        (*info->fprintf_func) (info->stream, "%s", "sys_call");
      else
        (*info->fprintf_func) (info->stream, "%s", "sys_call/b");
    }
  else
    (*info->fprintf_func) (info->stream, "%s", opcode->name);

/* get zz[7:6] and zz[5:0] to form truth for vlog */
  if (!strcmp(opcode->name,"vlog"))
    {
      unsigned int truth;
      char tr[4];
      truth = (AXP_OP (insn) & 3) << 6;
      truth = truth | ((insn & 0xFC00) >> 10);
      sprintf (tr,"%x",truth);
      (*info->fprintf_func) (info->stream, "%s", tr);
    }

  if (opcode->operands[0] != 0)
    (*info->fprintf_func) (info->stream, "\t");

  /* Now extract and print the operands.  */
  need_comma = 0;
  for (opindex = opcode->operands; *opindex != 0; opindex++)
    {
      const struct sw_64_operand *operand = sw_64_operands + *opindex;
      int value;

      /* Operands that are marked FAKE are simply ignored.  We
	 already made sure that the extract function considered
	 the instruction to be valid.  */
      if ((operand->flags & AXP_OPERAND_FAKE) != 0)
	continue;

      /* Extract the value from the instruction.  */
      if (operand->extract)
	value = (*operand->extract) (insn, (int *) NULL);
      else
	{
	  value = (insn >> operand->shift) & ((1 << operand->bits) - 1);
	  if (operand->flags & AXP_OPERAND_SIGNED)
	    {
	      int signbit = 1 << (operand->bits - 1);
	      value = (value ^ signbit) - signbit;
	    }
	}

      if (need_comma &&
	  ((operand->flags & (AXP_OPERAND_PARENS | AXP_OPERAND_COMMA))
	   != AXP_OPERAND_PARENS))
	{
	  (*info->fprintf_func) (info->stream, ",");
	}
      if (operand->flags & AXP_OPERAND_PARENS)
	(*info->fprintf_func) (info->stream, "(");

      /* Print the operand as directed by the flags.  */
      if (operand->flags & AXP_OPERAND_IR)
	(*info->fprintf_func) (info->stream, "%s", regnames[value]);
      else if (operand->flags & AXP_OPERAND_FPR)
	(*info->fprintf_func) (info->stream, "%s", regnames[value + 32]);
      else if (operand->flags & AXP_OPERAND_RELATIVE)
	(*info->print_address_func) (memaddr + 4 + value, info);
      else if (operand->flags & AXP_OPERAND_SIGNED)
	(*info->fprintf_func) (info->stream, "%d", value);
      else
	(*info->fprintf_func) (info->stream, "%#x", value);

      if (operand->flags & AXP_OPERAND_PARENS)
	(*info->fprintf_func) (info->stream, ")");
      need_comma = 1;
    }

  return 4;
}
