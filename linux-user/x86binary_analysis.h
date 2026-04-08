#ifndef X86BINARY_ANALYSIS_H
#define X86BINARY_ANALYSIS_H
#include "exec/user/abitypes.h"

#if defined(CONFIG_NATIVE_LIBS)  || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG) || defined(CONFIG_INDIRECT_JUMP_OPT_PLT)

#define PLT_WITHOUT_CET 0x50CC // 'P' 0xCC (小端序)
#define PLT_WITH_CET 0x45CC // 'E' 0xCC

/* 值结构体：保存函数名和虚拟地址 */
/* 值结构体 */
typedef struct PLT_HashValue
{
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    char *module_name;
    char *funcname;
#endif
    uint64_t plt_begin_va;
    int with_cet;
} PLT_HashValue;

extern GHashTable *global_plt_table;
extern GHashTable *dynsym_table;
extern int is_plt_stub;
extern struct Libraris *libraries;
#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
extern char native_libs_write_path[256];
#endif

typedef enum {
        ARG_GPR = 1, // 通用寄存器（如 R0-R7）
        ARG_FPR = 2, // 浮点寄存器（如 F0-F3）
        ARG_STACK = 3,    // 栈传递
        ARG_FPR_GPR = 4
} ArgPassType;
typedef enum
{
    RET_VOID = 0, // 没有返回值
    RET_GPR = 1, // 通用寄存器 RAX
    RET_FPR = 2, // 浮点寄存器 XMM0
    RET_STRUCT = 3   // 栈传递
} RetType;

typedef struct ArchCallingRule 
{
    int args_count;     // 参数数量
    ArgPassType arg;    // 参数类型
    RetType ret; // 返回值类型
} ArchCallingRule;

typedef struct sw64_method_item
{
    const char *funcname;  // 函数名（如 "memcpy"）
    ArchCallingRule rule;   // 跨架构调用规则
} sw64_method_item;

typedef struct sw64_lib_item {
    const char*     lib_name;     // 库名（如 "libc"）
    sw64_method_item*    methods;      // 函数列表（动态数组）
    size_t          num_methods; // 函数数量
} sw64_lib_item;

extern struct sw64_lib_item sw64_libs[];
extern const ArchCallingRule LIBC_GPR_RULE_3;
extern const ArchCallingRule LIBC_GPR_RULE_2;
extern const ArchCallingRule LIBC_GPR_RULE_1;
extern const ArchCallingRule LIBC_FPR_RULE_3;
extern const ArchCallingRule LIBC_FPR_RULE_2;
extern const ArchCallingRule LIBC_FPR_RULE_1;


typedef struct Bridge
{
    uintptr_t hostaddr;
    ArchCallingRule rule; // 跨架构调用规则
} Bridge;

/* 函数元数据（名称和桥接信息） */
typedef struct FunctionMetadata
{
    char *libname;
    char *funcname; // 函数名
    Bridge bridge;  // 桥接信息
} FunctionMetadata;

typedef struct Libraris
{
    char *libname;
    GHashTable *funcs; // 键: targetaddr (uintptr_t), 值: FunctionMetadata*
    uintptr_t minaddr;
    uintptr_t maxaddr;
    int done;
} Libraris;

void free_libentries();
void analyze_x86binary(int fd, abi_ulong start, abi_ulong len, abi_ulong fd_offset);
void native_libs_fork_start(void);
void native_libs_fork_end(int child);
FunctionMetadata *find_function_metadata_by_address(uintptr_t targetaddr);
#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
void native_libs_write_to_file(uintptr_t targetaddr, FunctionMetadata *meta);
#endif

#endif //#if defined(CONFIG_NATIVE_LIBS)  || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
#endif // X86BINARY_ANALYSIS_H
