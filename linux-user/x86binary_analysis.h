/**
 * @file x86binary_analysis.h
 * @brief x86 二进制分析模块 - 动态库函数替换和PLT优化
 */

#ifndef X86BINARY_ANALYSIS_H
#define X86BINARY_ANALYSIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "exec/user/abitypes.h"

#if (defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) ||  \
     defined(CONFIG_NATIVE_LIBS_CALL_DEBUG) ||                                 \
     defined(CONFIG_INDIRECT_JUMP_OPT_PLT) ||                                  \
     defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)) &&                           \
    defined(__sw_64__)

/*============================================================================
 * 常量定义
 *============================================================================*/

#define PLT_WITHOUT_CET 0x50CC /* 'P' 0xCC - 非CET模式 (小端序) */
#define PLT_WITH_CET 0x45CC    /* 'E' 0xCC - CET模式 (小端序) */
#define PLT_ENTRY_SIZE 16

/*============================================================================
 * PLT trap 协议
 *============================================================================*/

typedef struct X86PLTDecode {
  uint64_t dynsym_addr;
  uint64_t plt_begin_va;
  bool unresolved;
} X86PLTDecode;

/*============================================================================
 * 参数传递规则
 *============================================================================*/

typedef enum {
  ARG_GPR = 1,    /* 通用寄存器 */
  ARG_FPR = 2,    /* 浮点寄存器 */
  ARG_STACK = 3,  /* 栈传递 */
  ARG_FPR_GPR = 4 /* 混合传递 */
} ArgPassType;

typedef enum {
  RET_VOID = 0,  /* 无返回值 */
  RET_GPR = 1,   /* 通用寄存器 */
  RET_FPR = 2,   /* 浮点寄存器 */
  RET_STRUCT = 3 /* 栈传递 */
} RetType;

typedef struct ArchCallingRule {
  int args_count;
  ArgPassType arg;
  RetType ret;
} ArchCallingRule;

/*============================================================================
 * 函数映射结构
 *============================================================================*/

typedef struct sw64_method_item {
  const char *funcname;
  ArchCallingRule rule;
} sw64_method_item;

typedef struct sw64_lib_item {
  const char *lib_name;
  sw64_method_item *methods;
  size_t num_methods;
} sw64_lib_item;

typedef struct Bridge {
  uintptr_t hostaddr;
  ArchCallingRule rule;
} Bridge;

typedef struct FunctionMetadata {
  char *libname;
  char *funcname;
  Bridge bridge;
} FunctionMetadata;

typedef struct Libraris {
  char *libname;
  GHashTable *funcs; /* 键: targetaddr, 值: FunctionMetadata* */
  uintptr_t minaddr;
  uintptr_t maxaddr;
  int done;
  dev_t dev; /* Inode 去重 */
  ino_t ino;
} Libraris;

/*============================================================================
 * 全局变量
 *============================================================================*/

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
extern char native_libs_write_path[256];
#endif

/*============================================================================
 * 函数声明
 *============================================================================*/

void free_libentries(void);
void analyze_x86binary(int fd, abi_ulong start, abi_ulong len,
                       abi_ulong fd_offset);
bool x86_decode_plt_stub(uint64_t pc, X86PLTDecode *decode);
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
void x86binary_analysis_dump_stats(void);
void x86binary_analysis_note_plt_stub_patched(void);
void x86binary_analysis_note_plt_stub_skipped(void);
void x86binary_analysis_note_plt_trap_hit(void);
void x86binary_analysis_note_plt_trap_unresolved(void);
void x86binary_analysis_note_plt_trap_resolved(void);
#else
static inline void x86binary_analysis_note_plt_stub_patched(void) {}
static inline void x86binary_analysis_note_plt_stub_skipped(void) {}
static inline void x86binary_analysis_note_plt_trap_hit(void) {}
static inline void x86binary_analysis_note_plt_trap_unresolved(void) {}
static inline void x86binary_analysis_note_plt_trap_resolved(void) {}
#endif
void native_libs_lock(void);
void native_libs_unlock(void);
void native_libs_fork_start(void);
void native_libs_fork_end(int child);
FunctionMetadata *find_function_metadata_by_address(uintptr_t targetaddr);

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
void native_libs_write_to_file(uintptr_t targetaddr, FunctionMetadata *meta);
#endif

#endif /* CONFIG_NATIVE_LIBS || ... */

#endif /* X86BINARY_ANALYSIS_H */
