#include <glib.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include "x86binary_analysis.h"
#include "exec/user/abitypes.h"
#include <pthread.h>

#if defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG) || defined(CONFIG_INDIRECT_JUMP_OPT_PLT)
GHashTable *global_plt_table = NULL; // 保存所有重定位函数信息，键：PLT 桩地址(plt_stub_va),  值为（PLT_HashValue*）：函数名和虚拟地址
GHashTable *current_plt_table = NULL; // 保存当前库函数的重定位信息
GHashTable *dynsym_table = NULL; // 创建哈希表: key=funcname(string), value=target_addr(uint64_t)
int is_plt_stub = 0;
// 全局互斥锁
static pthread_mutex_t native_libs_write_mutex = PTHREAD_MUTEX_INITIALIZER;
static int is_gobal_table_mutex_initialized = 0;
static GMutex global_table_mutex;

static pthread_mutex_t native_libs_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int native_libs_lock_count;


struct Libraris *libraries = NULL;
size_t libs_capacity = 0;
size_t libs_count = 0;

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
char native_libs_write_path[256];
#endif
//-----------------------------------------
// 宏定义（简化条目声明）
//-----------------------------------------
const ArchCallingRule LIB_GPR_RULE_6 = {
    .args_count = 6,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
const ArchCallingRule LIB_GPR_RULE_4 = {
    .args_count = 4,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
const ArchCallingRule LIB_GPR_RULE_3 = {
    .args_count = 3,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
const ArchCallingRule LIB_GPR_RULE_2 = {
    .args_count = 2,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
const ArchCallingRule LIB_GPR_RULE_1 = {
    .args_count = 1,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
const ArchCallingRule LIB_GPR_RULE_0 = {
    .args_count = 0,
    .arg = ARG_GPR,
    .ret = RET_GPR
};
//------------int-----ret=VOID----------------
const ArchCallingRule LIB_GPR_VOID_RULE_1 = {
    .args_count = 1,
    .arg = ARG_GPR,
    .ret = RET_VOID
};
//------------float----------------------
const ArchCallingRule LIB_FPR_RULE_2 = {
    .args_count = 2,
    .arg = ARG_FPR,
    .ret = RET_FPR
};
const ArchCallingRule LIB_FPR_RULE_1 = {
    .args_count = 1,
    .arg = ARG_FPR,
    .ret = RET_FPR
};
//----------float-------ret=void---------------
const ArchCallingRule LIB_FPR_VOID_RULE_3 = {
    .args_count = 3,
    .arg = ARG_FPR,
    .ret = RET_VOID
};
//-------float---int---int----ret=int-------------
const ArchCallingRule LIB_FPR_GPR_RULE_3 = {
    .args_count = 3,
    .arg = ARG_FPR_GPR,
    .ret = RET_GPR
};
//-------float---int---int----ret=void-------------
const ArchCallingRule LIB_FPR_GPR_RULE_3_VOID = {
    .args_count = 3,
    .arg = ARG_FPR_GPR,
    .ret = RET_VOID
};
//-------float---float---int---int----ret=void-------------
const ArchCallingRule LIB_FPR_GPR_RULE_4_VOID = {
    .args_count = 4,
    .arg = ARG_FPR_GPR,
    .ret = RET_VOID
};

#define DEF_METHOD(func, rule_ptr) \
    {                          \
        .funcname = (func),   \
        .rule = rule_ptr       \
    }

//-----------------------------------------
// 硬编码函数表（示例：libc + libm）
//-----------------------------------------
static sw64_method_item libc_methods[] = {
    DEF_METHOD("memcpy", LIB_GPR_RULE_3),
    DEF_METHOD("memove", LIB_GPR_RULE_3),
    DEF_METHOD("memset", LIB_GPR_RULE_3),
    DEF_METHOD("clock", LIB_GPR_RULE_0),
    DEF_METHOD("clock_gettime", LIB_GPR_RULE_2),
    DEF_METHOD("__clock_gettime", LIB_GPR_RULE_2),
    DEF_METHOD("write", LIB_GPR_RULE_3),
    DEF_METHOD("getpid", LIB_GPR_RULE_0),
    DEF_METHOD("__pread64", LIB_GPR_RULE_4),
    DEF_METHOD("localtime_r", LIB_GPR_RULE_2),
    DEF_METHOD("localtime", LIB_GPR_RULE_1),
    DEF_METHOD("mktime", LIB_GPR_RULE_1),
 //     DEF_METHOD("isalpha", LIB_GPR_RULE_1),
 //     DEF_METHOD("isspace", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_unlock", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_lock", LIB_GPR_RULE_1),
    DEF_METHOD("__mbrtowc", LIB_GPR_RULE_4),
    DEF_METHOD("__strxfrm_l", LIB_GPR_RULE_4),
    DEF_METHOD("pthread_mutex_trylock", LIB_GPR_RULE_1),

    DEF_METHOD("wcrtomb", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_str_underflow", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_signal", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_broadcast", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_destroy", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_destroy", LIB_GPR_RULE_1),

    DEF_METHOD("inet_ntop", LIB_GPR_RULE_4),
    DEF_METHOD("inet_pton", LIB_GPR_RULE_3),
 //    DEF_METHOD("isxdigit", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutexattr_destroy", LIB_GPR_RULE_1),
 //    DEF_METHOD("isgraph", LIB_GPR_RULE_1),
    DEF_METHOD("pwrite", LIB_GPR_RULE_4),
//tianx add for nbench
    DEF_METHOD("__strcpy_chk", LIB_GPR_RULE_3),
//tianx add for spec2006
    DEF_METHOD("__ctype_toupper_loc", LIB_GPR_RULE_0),
    DEF_METHOD("uselocale", LIB_GPR_RULE_1),
    DEF_METHOD("__ctype_b_loc", LIB_GPR_RULE_0),
    DEF_METHOD("strtoll", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_file_read", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_file_write", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_file_stat", LIB_GPR_RULE_2),
    DEF_METHOD("_IO_file_close", LIB_GPR_RULE_1),
    DEF_METHOD("_IO_file_finish", LIB_GPR_RULE_1),
    DEF_METHOD("register_printf_specifier", LIB_GPR_RULE_3),
    DEF_METHOD("getenv", LIB_GPR_RULE_1),
};

static sw64_method_item libm_methods[] = {
    DEF_METHOD("pow", LIB_FPR_RULE_2),
    DEF_METHOD("log", LIB_FPR_RULE_1),
    DEF_METHOD("exp", LIB_FPR_RULE_1),
    DEF_METHOD("roundf64", LIB_FPR_RULE_1),
    DEF_METHOD("sincos", LIB_FPR_GPR_RULE_3_VOID),
//tianx add for nbench
    DEF_METHOD("expf64", LIB_FPR_RULE_1),
//tianx add for spec2006
    DEF_METHOD("powf64", LIB_FPR_RULE_2),
    DEF_METHOD("sincosf64", LIB_FPR_GPR_RULE_3_VOID),
    DEF_METHOD("fmodf32x", LIB_FPR_RULE_2),
    DEF_METHOD("asinf64", LIB_FPR_RULE_1),
};
static sw64_method_item libz_methods[] = {
    DEF_METHOD("adler32", LIB_GPR_RULE_3),
    DEF_METHOD("crc32", LIB_GPR_RULE_3),
    DEF_METHOD("inflateResetKeep", LIB_GPR_RULE_1),
    DEF_METHOD("deflateInit_", LIB_GPR_RULE_4),
#ifdef __sw_64_sw8a__
    DEF_METHOD("deflate", LIB_GPR_RULE_2),
#endif
    DEF_METHOD("compress", LIB_GPR_RULE_4),
    DEF_METHOD("uncompress", LIB_GPR_RULE_4),
};

static sw64_method_item libxcb_methods[] = {
    DEF_METHOD("xcb_xkb_key_sym_map_sizeof", LIB_GPR_RULE_1),
};

static sw64_method_item libglib2_methods[] = {
    DEF_METHOD("g_main_context_wakeup", LIB_GPR_VOID_RULE_1),
};

struct sw64_lib_item sw64_libs[] = {
    {.lib_name = "libc",
     .methods = libc_methods,
     .num_methods = sizeof(libc_methods) / sizeof(sw64_method_item)
    },

    {.lib_name = "libm",
     .methods = libm_methods,
     .num_methods = sizeof(libm_methods) / sizeof(sw64_method_item)
    },

    {.lib_name = "libz",
     .methods = libz_methods,
     .num_methods = sizeof(libz_methods) / sizeof(sw64_method_item)
    },

    {.lib_name = "libxcb",
     .methods = libxcb_methods,
     .num_methods = sizeof(libxcb_methods) / sizeof(sw64_method_item)
    },

    {.lib_name = "libglib-2",
     .methods = libglib2_methods,
     .num_methods = sizeof(libglib2_methods) / sizeof(sw64_method_item)
    },

    {NULL, NULL, 0} // 结束标记
};

static sw64_lib_item* in_sw64libs(const char* libname)
{
    for (sw64_lib_item *lib = sw64_libs; lib->lib_name != NULL; lib++)
    {
        if (!strcmp(libname, lib->lib_name))
        {
            return lib;
        }
    }
    return NULL;
}

static sw64_method_item *in_sw64methods(sw64_lib_item *lib, const char *funcname)
{
    if(lib == NULL) return NULL;
    for(int i = 0; i < lib->num_methods; i ++)
    {
        sw64_method_item *method = &(lib->methods[i]);
        if (!strcmp(funcname, method->funcname))
        {
            return method;
        }
    }
    return NULL;
}

void native_libs_lock(void)
{
    if (native_libs_lock_count++ == 0)
    {
        pthread_mutex_lock(&native_libs_mutex);
    }
}

void native_libs_unlock(void)
{
    if (--native_libs_lock_count == 0)
    {
        pthread_mutex_unlock(&native_libs_mutex);
    }
}

/* Grab lock to make sure things are in a consistent state after fork().  */
void native_libs_fork_start(void)
{
    if (native_libs_lock_count)
        abort();
    pthread_mutex_lock(&native_libs_mutex);
}

void native_libs_fork_end(int child)
{
    if (child)
        pthread_mutex_init(&native_libs_mutex, NULL);
    else
        pthread_mutex_unlock(&native_libs_mutex);
}

//-----------------------------------------------------------------------------
//                   内存管理函数
//-----------------------------------------------------------------------------

static void free_metadata(gpointer data)
{
    FunctionMetadata *funcmeta = (FunctionMetadata *)data;
    if (funcmeta)
    {
        g_free(funcmeta->libname); // 新增：需要释放库名字符串
        g_free(funcmeta->funcname);
        g_free(funcmeta);
    }
}

void free_libentries()
{
    native_libs_lock();
    for (int i = 0; i < libs_count; i++)
    {
        if (libraries[i].libname)
        {
            free(libraries[i].libname);
            libraries[i].libname = NULL;
        }
        if (libraries[i].funcs)
        {
            g_hash_table_destroy(libraries[i].funcs);
            libraries[i].funcs = NULL;
        }
        libraries[i].done = 0;
    }
    if (global_plt_table)
    {
        g_hash_table_destroy(global_plt_table);
        global_plt_table = NULL;
    }
    if(dynsym_table)
    {
        g_hash_table_destroy(dynsym_table);
        dynsym_table = NULL;
    }
    libs_count = 0;
    libs_capacity = 0;

    if(is_gobal_table_mutex_initialized == 1)
    {
        g_mutex_clear(&global_table_mutex);
       is_gobal_table_mutex_initialized = 0;
    }

    native_libs_unlock();
}

//-----------------------------------------------------------------------------
//                   初始化函数
//-----------------------------------------------------------------------------

static inline void init_libentries()
{
    if (libraries == NULL || global_plt_table == NULL || dynsym_table == NULL)
    {
        native_libs_lock();
        libs_count = 0;
        libs_capacity = 10;
        if (libraries == NULL)
        {
            libraries = malloc(libs_capacity * sizeof(struct Libraris));
            memset(libraries, 0, libs_capacity * sizeof(struct Libraris));
        }
        if (global_plt_table == NULL)
        {
            global_plt_table = g_hash_table_new_full(g_direct_hash, // 键的哈希函数
                                             g_direct_equal,       // 键的比较函数
                                             NULL,                // 键的释放函数（无需）
                                             NULL);              // 值的释放函数
        }
        if (dynsym_table == NULL)
        {
            dynsym_table = g_hash_table_new_full(
                g_str_hash,         // 哈希函数 (针对字符串优化)
                g_str_equal,        // 键比较函数
                g_free,             // 自动释放键内存 (funcname)
                NULL                // 值无需特殊释放 (uint64_t 是基础类型)
            );
        }
        if(is_gobal_table_mutex_initialized == 0)
        {
            g_mutex_init(&global_table_mutex);
            is_gobal_table_mutex_initialized = 1;
        }                                             
        native_libs_unlock();
    }
}

//-----------------------------------------------------------------------------
//                   打印
//-----------------------------------------------------------------------------
#if defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
static inline void print_metadata(gpointer key, gpointer value, gpointer user_data)
{
    uintptr_t targetaddr = (uintptr_t)key;              // 键是 targetaddr
    FunctionMetadata *meta = (FunctionMetadata *)value; // 值是 FunctionMetadata*
    FILE *f = (FILE *)user_data;
    fprintf(f, " %-20s  %-40s targetaddr = 0x%016lx, hostaddr = 0x%lx\n", meta->libname, meta->funcname, targetaddr, meta->bridge.hostaddr);
}
#endif

//-----------------------------------------------------------------------------
//                   根据地址查询 FunctionMetadata 指针
//-----------------------------------------------------------------------------
FunctionMetadata *find_function_metadata_by_address(uintptr_t targetaddr)
{
    FunctionMetadata *meta = NULL;

    for (int i = 0; i < libs_count; i++)
    {
        if(libraries[i].funcs)
        {
            meta = g_hash_table_lookup(libraries[i].funcs, GUINT_TO_POINTER(targetaddr));
            if(meta)
                return meta;
        }
    }
    return NULL;
}
#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
void native_libs_write_to_file(uintptr_t targetaddr, FunctionMetadata *meta)
{
    // 加锁
    pthread_mutex_lock(&native_libs_write_mutex);

    // 执行文件写入操作
    FILE *fp = fopen(native_libs_write_path, "a"); // 以追加模式打开
    if (fp != NULL)
    {
        print_metadata(targetaddr, meta, fp);
        fclose(fp);
    }

    // 解锁
    pthread_mutex_unlock(&native_libs_write_mutex);
}
#endif

#if defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG)
static inline void print_library(struct Libraris *lib)
{
    if(lib)
    {
        printf("===== Libraries and Functions =====\n");
        printf("--%-20s\n", lib->libname);
        g_hash_table_foreach(lib->funcs, print_metadata, stderr);
        printf("===================================\n");
    }
}
#endif

#if defined(CONFIG_NATIVE_LIBS)
static inline void do_replace_x86func_with_sw64Bridge(gpointer key, gpointer value, gpointer user_data)
{
    uintptr_t targetaddr = (uintptr_t)key;              // 键是 targetaddr
    FunctionMetadata *meta = (FunctionMetadata *)value; // 值是 FunctionMetadata*

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    sw64_lib_item* lib_item = (sw64_lib_item *)(user_data);
    if(in_sw64methods(lib_item, meta->funcname) == NULL)
    {
        return;
    }
#endif

#if 0 //for debug
    printf("0x%lx call %s\n", targetaddr, meta->funcname);
#endif
    // 写入单字节 0xCC 到 targetaddr 地址
    *(uint8_t *)targetaddr = 0xCC;

    // 写入字符 'S' 到 targetaddr + 1 的位置（第二个字节）
    *(uint8_t *)((char *)targetaddr + 1) = 'S';

    // 写入字符 'S' 到 targetaddr + 2 的位置（第三个字节）
    *(uint8_t *)((char *)targetaddr + 2) = 'C';

    /* 
    不要写入Bridge结构体，等匹配到0xcc之后通过查表获取brideg
    每个函数第一条指令为 endbr64, 机器码为 0xf30f1efa
    确保我们的修改只影响第一条空指令
    在printf函数中复用 memcpy+7指令
    */
    // 写入 Bridge 结构指针到 targetaddr + 4 的位置（对齐）
    //*(Bridge **)((char *)targetaddr + 4) = &(meta->bridge);
}
static inline void replace_x86func_with_sw64Bridge(struct Libraris *lib, sw64_lib_item* lib_item)
{
    if(lib)
    {
        size_t page_size = sysconf(_SC_PAGESIZE);

        // 将起始地址向下对齐到页边界
        uintptr_t start_addr = (uintptr_t)lib->minaddr;
        uintptr_t aligned_start = start_addr & ~(page_size - 1);

        // 将结束地址向上对齐到页边界
        uintptr_t end_addr = (uintptr_t)lib->maxaddr;
        uintptr_t aligned_end = (end_addr + page_size - 1) & ~(page_size - 1);

        // 计算对齐后的内存长度
        size_t length = aligned_end - aligned_start;

        int original_prot = PROT_READ | PROT_EXEC;
        int new_prot = original_prot | PROT_WRITE;
        if(mprotect((void*)aligned_start, length, new_prot) == -1)
        {
            perror("mprotect PROT_WRITE failed");
            exit(-1);
        }
        if(lib->funcs) {
            g_hash_table_foreach(lib->funcs, do_replace_x86func_with_sw64Bridge, lib_item);
        }
        if(mprotect((void*)aligned_start, length, original_prot) == -1)
        {
            perror("Restore mprotect failed");
            exit(-1);
        }
    }
}
#endif
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT)
static do_replace_plt_with_trap(gpointer key, gpointer value, gpointer user_data)
{
    uintptr_t plt_stub_va = (uintptr_t)key;                    // 键是 plt_stub_va，即PLT 桩地址
    PLT_HashValue *plt_value = (PLT_HashValue *)value; // 值是（PLT_HashValue*）函数名和虚拟地址
    uint32_t offset;

    if(plt_value->with_cet) {
        /*  plt table
        => 0x555555555050 f3 0f 1e fa   endbr64
           0x555555555054 [f2] ff 25 a6 2f 00 00   jmp *0x2fa6(%rip)
           0x55555555505a[b] 66 0f 1f 44 00 00 nopw   0x0(%rax,%rax,1)
           #modifid:
        => 0x555555555050 0xCC 'E' [f2] a6 2f 00 00 xx
           0x555555555058 plt_begin_va
        */
        *(uint16_t *)plt_stub_va = (uint16_t)PLT_WITH_CET;
        if(*(uint8_t *)(plt_stub_va+4) == 0xf2) {
            offset =  *(uint32_t*)(plt_stub_va + 7);
            *(uint8_t *)(plt_stub_va + 2) = (uint8_t)(0xf2);
            *(uint32_t *)(plt_stub_va + 3) = (uint32_t)(offset);
        } else {
            offset =  *(uint32_t*)(plt_stub_va + 6);
            *(uint32_t *)(plt_stub_va + 2) = (uint32_t)(offset);
        }
        *(uint64_t *)(plt_stub_va + 8) = (uint64_t)plt_value->plt_begin_va;
    } else {
        /*  plt table
        => 0x555555555050 ff 25 a6 2f 00 00 jmp    *0x2fa6(%rip)
           0x555555555056 68 01 00 00 00    push $0x1
           0x55555555501b e9 d0 ff ff ff    jmp    3fcff0
           #modifid:
        => 0x555555555050 0xCC 'p' a6 2f 00 00 jmp    *0x2fa6(%rip)
           0x555555555056 68 01 00 00 00    push $0x1
           0x55555555501b e9 d0 ff ff ff    jmp    3fcff0
        */
        *(uint16_t *)plt_stub_va = (uint16_t)PLT_WITHOUT_CET;
    }

}
static inline void replace_plt_with_trap(abi_long start_addr, abi_long end_addr)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    // 将起始地址向下对齐到页边界
    uintptr_t aligned_start = start_addr & ~(page_size - 1);
    // 将结束地址向上对齐到页边界
    uintptr_t aligned_end = (end_addr + page_size - 1) & ~(page_size - 1);
    // 计算对齐后的内存长度
    size_t length = aligned_end - aligned_start;

    int original_prot = PROT_READ | PROT_EXEC;
    int new_prot = original_prot | PROT_WRITE;
    if (mprotect((void *)aligned_start, length, new_prot) == -1)
    {
        perror("mprotect PROT_WRITE failed");
        exit(-1);
    }
    g_hash_table_foreach(current_plt_table, do_replace_plt_with_trap, NULL);
    if (mprotect((void *)aligned_start, length, original_prot) == -1)
    {
        perror("Restore mprotect failed");
        exit(-1);
    }
}
#endif
//-----------------------------------------------------------------------------
//                   保存函数信息到全局哈希表
//-----------------------------------------------------------------------------

/* 保存函数信息到指定库的函数树中 */
static inline void save_function(uintptr_t targetaddr, const char *libname, const char *funcname, sw64_method_item *method)
{
    native_libs_lock();
    FunctionMetadata *meta = g_malloc(sizeof(FunctionMetadata));
    meta->libname = g_strdup(libname); // 深拷贝库名
    meta->funcname = g_strdup(funcname);
    if(method) {
        meta->bridge.rule = (ArchCallingRule){method->rule.args_count, method->rule.arg, method->rule.ret};
        if(!strcmp(funcname,"memcpy"))
            meta->bridge.hostaddr = dlsym(RTLD_DEFAULT, "memmove");
        else
            meta->bridge.hostaddr = dlsym(RTLD_DEFAULT, funcname);
    } else {
        meta->bridge.rule = (ArchCallingRule){0, 0};
        meta->bridge.hostaddr = 0;
    }
    if (libs_count >= libs_capacity) {
        
        libs_capacity *= 2;
        libraries = realloc(libraries, libs_capacity * sizeof(struct Libraris));
        memset(libraries + libs_count, 0, (libs_capacity - libs_count) * sizeof(struct Libraris));
        
    }

    if (libraries[libs_count].funcs == NULL)
    {
        libraries[libs_count].funcs = g_hash_table_new_full(
            g_direct_hash,  // 地址直接作为哈希键
            g_direct_equal, // 直接比较地址
            NULL,           // 键无需释放 (地址是数值)
            free_metadata   // 值销毁函数
        );
    }
    if (!g_hash_table_contains(libraries[libs_count].funcs, GUINT_TO_POINTER(targetaddr)))
    {
        g_hash_table_insert(libraries[libs_count].funcs, GUINT_TO_POINTER(targetaddr), meta);
    }
    native_libs_unlock();
}

static inline void save_library(const char *libname, uintptr_t minaddr, uintptr_t maxaddr)
{
    native_libs_lock();
    libraries[libs_count].minaddr = minaddr;
    libraries[libs_count].maxaddr = maxaddr;
    libraries[libs_count].libname = g_strdup(libname);
    libraries[libs_count].done = 1;
    libs_count++;
    native_libs_unlock();
}
static inline void do_analyze_x86binary(const char *libname, int fd, abi_ulong start, abi_ulong len, abi_ulong fd_offset)
{

    Elf *elf;
    Elf_Scn *scn = NULL;
    Elf_Scn *scn_dynsym = NULL;
    Elf_Scn *scn_rela_plt = NULL;
    int found_dynsym=0;
    int found_rela_plt = 0;
    int found_plt = 0;
    int found_plt_sec = 0;
    char *strtab = NULL;
    GElf_Shdr shdr;
    GElf_Shdr shdr_dynsym;
    GElf_Shdr shdr_rela_plt;
    size_t shstrndx;
//    abi_ulong plt_base_va = 0;
    abi_ulong plt_begin_va = 0;
    abi_ulong plt_sec_va = 0;

    shdr_dynsym.sh_size = 0;   // 将动态符号表的大小设为0
    shdr_rela_plt.sh_size = 0; // 将重定位表的大小设为0
    sw64_method_item *method = NULL;
    sw64_lib_item* lib_item = NULL;

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    const char **sym_names = NULL;  // 符号名称数组
#endif

    init_libentries();

    if (fd < 2)
        return;

    if (libs_count >= 1 && !strcmp(libraries[libs_count-1].libname, libname))
        return;    

    // 初始化 libelf
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        goto cleanup;
    }

    if (!(elf = elf_begin(fd, ELF_C_READ, NULL)))
    {
        goto cleanup;
    }

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
    {
        goto cleanup;
    }

    // 查找动态符号表 (.dynsym)
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) == NULL)
        { // 正确检查
            fprintf(stderr, "Failed to read section header: %s\n", elf_errmsg(elf_errno()));
            elf_end(elf);
            close(fd);
            goto cleanup;
        }
        // 获取节名称
        const char *sname = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!sname) {
            continue;
        }

        if (sname && strcmp(sname, ".dynsym") == 0)
        {
            // We found the .dynsym section
            found_dynsym = 1;
            memcpy(&shdr_dynsym, &shdr, sizeof(GElf_Shdr));
            scn_dynsym = scn;
        }
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT)
        else if (sname && strcmp(sname, ".rela.plt") == 0)
        {
            // We found the .dynsym section
            found_rela_plt = 1;
            memcpy(&shdr_rela_plt, &shdr, sizeof(GElf_Shdr));
            scn_rela_plt = scn;
        }
        else if (sname && strcmp(sname, ".plt") == 0)
        {
            // 计算 .plt 节的虚拟地址
            plt_begin_va = start + (shdr.sh_offset - fd_offset);
            found_plt = 1;
        }
        else if (sname && strcmp(sname, ".plt.sec") == 0)
        {
            // 计算 .plt.sec 节的虚拟地址
            plt_sec_va = start + (shdr.sh_offset - fd_offset);
            found_plt_sec = 1;
        }
        if (found_dynsym == 1 && found_rela_plt == 1 && found_plt == 1 && found_plt_sec == 1)
        {
            break;
        }
#else
        if (found_dynsym == 1)
        {
            break;
        }
#endif
    }

    lib_item = in_sw64libs(libname);
#if (defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_INDIRECT_JUMP_OPT_PLT)) && !defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    if(lib_item)
#endif
    { //dynsym analysis
        // 获取关联的字符串表
        Elf_Scn *strtab_scn = elf_getscn(elf, shdr_dynsym.sh_link);
        if (!strtab_scn)
        {
            fprintf(stderr, "Failed to get string table section\n");
            goto cleanup;
        }

        GElf_Shdr strtab_shdr;
        if (gelf_getshdr(strtab_scn, &strtab_shdr) != &strtab_shdr)
        {
            fprintf(stderr, "Failed to get string table header\n");
            goto cleanup;
        }

        // 读取字符串表内容
        strtab = malloc(strtab_shdr.sh_size);
        if (!strtab || pread(fd, strtab, strtab_shdr.sh_size, strtab_shdr.sh_offset) != strtab_shdr.sh_size)
        {
            fprintf(stderr, "Failed to read string table\n");
            goto cleanup;
        }

        // 获取符号表数据
        Elf_Data *data = elf_getdata(scn_dynsym, NULL);
        if (!data)
        {
            fprintf(stderr, "Failed to get data from section\n");
            goto cleanup;
        }

        /* 遍历符号表 */
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
        sym_names = malloc((shdr_dynsym.sh_size / shdr_dynsym.sh_entsize) * sizeof(char *));
        memset(sym_names, 0, (shdr_dynsym.sh_size / shdr_dynsym.sh_entsize) * sizeof(char *));
#endif
        for (size_t i = 0; i < shdr_dynsym.sh_size / shdr_dynsym.sh_entsize; i++)
        {
            GElf_Sym sym;
            if (gelf_getsym(data, i, &sym) == NULL)
            {
                fprintf(stderr, "Error reading symbol %zu: %s\n", i, elf_errmsg(elf_errno()));
                continue;
            }
            const char *funcname = strtab + sym.st_name;

            /* 保存符号名 */
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
            sym_names[i] = funcname;
#endif

            if (GELF_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF)
            {
                unsigned long target_addr = sym.st_value - fd_offset + start;

                // 复制字符串键 (避免外部指针失效)
                char *key = g_strdup(funcname);
                // 存储地址值 (转换为指针类型存储)
                g_hash_table_insert(dynsym_table, key, GUINT_TO_POINTER(target_addr));

                // 保存到哈希表
                method = in_sw64methods(lib_item, funcname);
#if defined(CONFIG_NATIVE_LIBS) && !defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
                if(method)
#endif
                {
                    save_function(target_addr, libname, funcname, method);
                }
            }
        }
        save_library(libname, start, start + len);

#if defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG)
        //print_library(&libraries[libs_count-1]);
#endif

#if defined(CONFIG_NATIVE_LIBS)
        if(lib_item) {
            replace_x86func_with_sw64Bridge(&libraries[libs_count-1], lib_item);
        }
#endif
    } // end of dynsym analysis

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT)
    // .plt.sec and got.plt exist
    if(scn_rela_plt && (plt_sec_va || plt_begin_va)) {
        PLT_HashValue *plt_value = NULL;
        PLT_HashValue *dup_value = NULL;
        abi_ulong plt_stub_va = 0;
        bool current_plt_not_empty = false;
        int with_cet = 0;

        // 获取 .rela.plt 节的数据
        Elf_Data *rela_data = elf_getdata(scn_rela_plt, NULL);
        if (!rela_data)
        {
            fprintf(stderr, "%s Failed to get data from .rela.plt section\n",libname);
            goto cleanup;
        }

        /* 遍历 .rela.plt 关联 PLT 桩和符号​ */
        if(current_plt_table)
        {
            g_hash_table_destroy(current_plt_table);
            current_plt_table = NULL;
        }

        current_plt_table = g_hash_table_new_full(g_direct_hash, // 键的哈希函数
                                                  g_direct_equal,       // 键的比较函数
                                                  NULL,                // 键的释放函数（无需）
                                                  NULL);              // 值的释放函数
        for (size_t i = 0; i < shdr_rela_plt.sh_size / shdr_rela_plt.sh_entsize; i++)
        {
            GElf_Rela rela;
            GElf_Sym sym;
            if (gelf_getrela(rela_data, i, &rela) == NULL)
            {
                fprintf(stderr, "Error reading relocation entry %zu: %s\n", i, elf_errmsg(elf_errno()));
                continue;
            }
            if (ELF64_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT)
            {
                if(plt_sec_va) {
                    // 计算当前 PLT 桩的地址（.plt.sec 节中的偏移）
                    plt_stub_va = plt_sec_va + (i) * 16;
                    with_cet = 1;
                }  else {
                    // 计算当前 PLT 桩的地址（.plt 节中的偏移）
                    plt_stub_va = plt_begin_va + (i + 1) * 16; //跳过plt0
                    with_cet = 0;
                }

                // 获取符号名（可选）
                int sym_idx = ELF64_R_SYM(rela.r_info);
                if (sym_idx < 0 || sym_idx >= (shdr_dynsym.sh_size / shdr_dynsym.sh_entsize))
                {
                    fprintf(stderr, "Invalid symbol index: %d\n", sym_idx);
                    continue;
                }
                plt_value = g_malloc(sizeof(PLT_HashValue));
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
                const char *sym_name = sym_names[sym_idx] ? sym_names[sym_idx] : NULL;
                plt_value->funcname = g_strdup(sym_name);
                plt_value->module_name = g_strdup(libname);
#endif
                plt_value->plt_begin_va = plt_begin_va;
                plt_value->with_cet = with_cet;
                g_hash_table_insert(current_plt_table, GUINT_TO_POINTER(plt_stub_va), plt_value);
                current_plt_not_empty = true;
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
                printf("[%s]:PLT Stub: %s@plt at VA: 0x%lx\n", libname, sym_name,plt_stub_va);
#endif
            }
        }
        if(current_plt_not_empty == true)
        {
            replace_plt_with_trap(start, start + len);
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
            GHashTableIter iter;
            gpointer key, value;
            g_mutex_lock(&global_table_mutex);
            g_hash_table_iter_init(&iter, current_plt_table);
            while (g_hash_table_iter_next(&iter, &key, &value))
            {
                plt_stub_va = (abi_ulong)(key);
                plt_value = (PLT_HashValue *)value;
                // 深拷贝 PLT_HashValue
                dup_value = g_malloc(sizeof(PLT_HashValue));
                dup_value->funcname = g_strdup(plt_value->funcname);
                dup_value->module_name = g_strdup(plt_value->module_name);
                dup_value->plt_begin_va = plt_value->plt_begin_va;
                dup_value->with_cet = plt_value->with_cet;

                // 插入全局表（若冲突，说明模块重复加载）
                if (!g_hash_table_contains(global_plt_table, GUINT_TO_POINTER(plt_stub_va)))
                {
                    g_hash_table_insert(global_plt_table,
                                        GUINT_TO_POINTER(plt_stub_va),
                                        dup_value);
                }
            }
            g_mutex_unlock(&global_table_mutex);
#endif //endof CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG
        }

    }
#endif

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    free(sym_names);
#endif
    free(strtab);
    return;
cleanup:
    if (strtab)
        free(strtab);
    if (elf)
        elf_end(elf);    
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)
    if(sym_names)
        free(sym_names);     
#endif
    return;
}

void analyze_x86binary(int fd, abi_ulong start, abi_ulong len, abi_ulong fd_offset)
{
    if (fd < 2)
    {
        return;  // Skip standard file descriptors
    }
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char libname_path[1024];
    char libname[1024];
    memset(libname_path, 0, sizeof(libname_path));
    memset(libname, 0, sizeof(libname));


    // get libname from fd
    int libname_len = readlink(path, libname_path, sizeof(libname_path) - 1);
    if (libname_len != -1)
    {
        libname_path[libname_len] = '\0';
        void *last_slash = strrchr(libname_path, '/');
        if (last_slash != NULL)
        {
            strcpy(libname, last_slash + 1);
        }
        else
        {
            strcpy(libname, libname_path);
        }
        char *dot = strchr(libname, '.');
        if (dot != NULL)
        {
            *dot = '\0';
            /* here wo can make sure that x86 lib segment is load to memory
            by target_mmap, save x86 lib infomation to global variable "struct Libraris *libraries" */
        }
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) || defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
        do_analyze_x86binary(libname, fd, start, len, fd_offset);
#endif
    } 
}

#endif // #if defined(CONFIG_NATIVE_LIBS)  || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) || defined(CONFIG_NATIVE_LIBS_CALL_DEBUG) || defined(CONFIG_INDIRECT_JUMP_OPT_PLT)
