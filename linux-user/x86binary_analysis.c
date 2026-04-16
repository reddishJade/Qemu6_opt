#include "x86binary_analysis.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <gelf.h>
#include <glib.h>
#include <libelf.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if (defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) ||  \
     defined(CONFIG_NATIVE_LIBS_CALL_DEBUG) ||                                 \
     defined(CONFIG_INDIRECT_JUMP_OPT_PLT) ||                                  \
     defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG)) &&                           \
    defined(__sw_64__)

#if defined(CONFIG_NATIVE_LIBS) || defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) ||   \
    defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
#define NEED_FULL_DYNSYM_ANALYSIS 1
#else
#define NEED_FULL_DYNSYM_ANALYSIS 0
#endif

/*============================================================================
 * 全局变量
 *============================================================================*/

static GHashTable *global_plt_table = NULL;

typedef struct LoadedInodeKey {
  dev_t dev;
  ino_t ino;
} LoadedInodeKey;

static GHashTable *loaded_inodes = NULL;
static GHashTable *loaded_library_names = NULL;

static GPtrArray *libraries = NULL;

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
typedef struct AnalyzeStats {
  uint64_t calls;
  uint64_t skipped_fd;
  uint64_t skipped_fstat;
  uint64_t skipped_inode;
  uint64_t skipped_name;
  uint64_t skipped_readlink;
  uint64_t analyzed_files;
  uint64_t section_scan_ns;
  uint64_t dynsym_ns;
  uint64_t plt_ns;
  uint64_t save_library_ns;
  uint64_t total_ns;
  uint64_t dynsym_count;
  uint64_t rela_plt_count;
} AnalyzeStats;

static AnalyzeStats analyze_stats;
static int analyze_stats_dumped = 0;

static inline uint64_t analyze_clock_now_ns(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

__attribute__((destructor)) void x86binary_analysis_dump_stats(void) {
  if (analyze_stats_dumped) {
    return;
  }

  analyze_stats_dumped = 1;

  fprintf(stderr,
          "\n=== analyze_x86binary stats ===\n"
          "calls=%llu analyzed=%llu\n"
          "skips: fd=%llu fstat=%llu inode=%llu libname=%llu readlink=%llu\n"
          "time_ms: total=%.3f scan=%.3f dynsym=%.3f plt=%.3f save=%.3f\n"
          "counts: dynsym=%llu rela_plt=%llu\n"
          "===============================\n",
          (unsigned long long)analyze_stats.calls,
          (unsigned long long)analyze_stats.analyzed_files,
          (unsigned long long)analyze_stats.skipped_fd,
          (unsigned long long)analyze_stats.skipped_fstat,
          (unsigned long long)analyze_stats.skipped_inode,
          (unsigned long long)analyze_stats.skipped_name,
          (unsigned long long)analyze_stats.skipped_readlink,
          (double)analyze_stats.total_ns / 1000000.0,
          (double)analyze_stats.section_scan_ns / 1000000.0,
          (double)analyze_stats.dynsym_ns / 1000000.0,
          (double)analyze_stats.plt_ns / 1000000.0,
          (double)analyze_stats.save_library_ns / 1000000.0,
          (unsigned long long)analyze_stats.dynsym_count,
          (unsigned long long)analyze_stats.rela_plt_count);
}

#define ANALYZE_STATS_ENABLED() true
#define ANALYZE_CLOCK_NOW_NS() analyze_clock_now_ns()
#define ANALYZE_STATS_DECLARE_ENABLED()
#define ANALYZE_STATS_DECLARE_TIMERS()                                         \
  uint64_t scan_begin_ns = 0;                                                  \
  uint64_t dynsym_begin_ns = 0;                                                \
  uint64_t plt_begin_ns = 0;                                                   \
  uint64_t save_begin_ns = 0
#define ANALYZE_STATS_DECLARE_TOTAL_TIMER() uint64_t analyze_begin_ns = 0
#define ANALYZE_STATS_DO(code)                                                 \
  do {                                                                         \
    code                                                                       \
  } while (0)
#else
#define ANALYZE_STATS_ENABLED() false
#define ANALYZE_CLOCK_NOW_NS() 0
#define ANALYZE_STATS_DECLARE_ENABLED()
#define ANALYZE_STATS_DECLARE_TIMERS()
#define ANALYZE_STATS_DECLARE_TOTAL_TIMER()
#define ANALYZE_STATS_DO(code)                                                 \
  do {                                                                         \
  } while (0)
#endif

/* 互斥锁 */
static pthread_mutex_t native_libs_mutex = PTHREAD_MUTEX_INITIALIZER;
static int is_global_table_mutex_initialized = 0;
static GMutex global_table_mutex;
static __thread int native_libs_lock_count;

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
static pthread_mutex_t native_libs_write_mutex = PTHREAD_MUTEX_INITIALIZER;
char native_libs_write_path[256];
#endif

/*============================================================================
 * 调用规则定义
 *============================================================================*/

/* 通用寄存器规则 */
const ArchCallingRule LIB_GPR_RULE_6 = {6, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_RULE_4 = {4, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_RULE_3 = {3, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_RULE_2 = {2, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_RULE_1 = {1, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_RULE_0 = {0, ARG_GPR, RET_GPR};
const ArchCallingRule LIB_GPR_VOID_RULE_1 = {1, ARG_GPR, RET_VOID};

/* 浮点寄存器规则 */
const ArchCallingRule LIB_FPR_RULE_2 = {2, ARG_FPR, RET_FPR};
const ArchCallingRule LIB_FPR_RULE_1 = {1, ARG_FPR, RET_FPR};
const ArchCallingRule LIB_FPR_VOID_RULE_3 = {3, ARG_FPR, RET_VOID};

/* 混合传递规则 */
const ArchCallingRule LIB_FPR_GPR_RULE_3 = {3, ARG_FPR_GPR, RET_GPR};
const ArchCallingRule LIB_FPR_GPR_RULE_3_VOID = {3, ARG_FPR_GPR, RET_VOID};
const ArchCallingRule LIB_FPR_GPR_RULE_4_VOID = {4, ARG_FPR_GPR, RET_VOID};

/*============================================================================
 * 函数表定义
 *============================================================================*/

#define DEF_METHOD(func, rule_ptr) {.funcname = (func), .rule = rule_ptr}

/* libc 函数表 */
static sw64_method_item libc_methods[] = {
    /* 内存操作 */
    DEF_METHOD("memcpy", LIB_GPR_RULE_3),
    DEF_METHOD("memmove", LIB_GPR_RULE_3),
    DEF_METHOD("memset", LIB_GPR_RULE_3),

    /* 时间相关 */
    DEF_METHOD("clock", LIB_GPR_RULE_0),
    DEF_METHOD("clock_gettime", LIB_GPR_RULE_2),
    DEF_METHOD("__clock_gettime", LIB_GPR_RULE_2),
    DEF_METHOD("localtime_r", LIB_GPR_RULE_2),
    DEF_METHOD("localtime", LIB_GPR_RULE_1),
    DEF_METHOD("mktime", LIB_GPR_RULE_1),

    /* I/O 操作 */
    DEF_METHOD("write", LIB_GPR_RULE_3),
    DEF_METHOD("__pread64", LIB_GPR_RULE_4),
    DEF_METHOD("pwrite", LIB_GPR_RULE_4),
    DEF_METHOD("_IO_file_read", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_file_write", LIB_GPR_RULE_3),
    DEF_METHOD("_IO_file_stat", LIB_GPR_RULE_2),
    DEF_METHOD("_IO_file_close", LIB_GPR_RULE_1),
    DEF_METHOD("_IO_file_finish", LIB_GPR_RULE_1),
    DEF_METHOD("_IO_str_underflow", LIB_GPR_RULE_1),

    /* 进程/线程 */
    DEF_METHOD("getpid", LIB_GPR_RULE_0),
    DEF_METHOD("pthread_mutex_unlock", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_lock", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_trylock", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutex_destroy", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_mutexattr_destroy", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_signal", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_broadcast", LIB_GPR_RULE_1),
    DEF_METHOD("pthread_cond_destroy", LIB_GPR_RULE_1),

    /* 字符串/字符处理 */
    DEF_METHOD("__mbrtowc", LIB_GPR_RULE_4),
    DEF_METHOD("__strxfrm_l", LIB_GPR_RULE_4),
    DEF_METHOD("wcrtomb", LIB_GPR_RULE_3),
    DEF_METHOD("__strcpy_chk", LIB_GPR_RULE_3),
    DEF_METHOD("strtoll", LIB_GPR_RULE_3),

    /* 网络 */
    DEF_METHOD("inet_ntop", LIB_GPR_RULE_4),
    DEF_METHOD("inet_pton", LIB_GPR_RULE_3),

    /* 其他 */
    DEF_METHOD("__ctype_toupper_loc", LIB_GPR_RULE_0),
    DEF_METHOD("uselocale", LIB_GPR_RULE_1),
    DEF_METHOD("__ctype_b_loc", LIB_GPR_RULE_0),
    DEF_METHOD("register_printf_specifier", LIB_GPR_RULE_3),
    DEF_METHOD("getenv", LIB_GPR_RULE_1),
};

/* libm 函数表 */
static sw64_method_item libm_methods[] = {
    DEF_METHOD("pow", LIB_FPR_RULE_2),
    DEF_METHOD("log", LIB_FPR_RULE_1),
    DEF_METHOD("exp", LIB_FPR_RULE_1),
    DEF_METHOD("roundf64", LIB_FPR_RULE_1),
    DEF_METHOD("sincos", LIB_FPR_GPR_RULE_3_VOID),
    DEF_METHOD("expf64", LIB_FPR_RULE_1),
    DEF_METHOD("powf64", LIB_FPR_RULE_2),
    DEF_METHOD("sincosf64", LIB_FPR_GPR_RULE_3_VOID),
    DEF_METHOD("fmodf32x", LIB_FPR_RULE_2),
    DEF_METHOD("asinf64", LIB_FPR_RULE_1),
};

/* libz 函数表 */
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

/* libxcb 函数表 */
static sw64_method_item libxcb_methods[] = {
    DEF_METHOD("xcb_xkb_key_sym_map_sizeof", LIB_GPR_RULE_1),
};

/* libglib-2 函数表 */
static sw64_method_item libglib2_methods[] = {
    DEF_METHOD("g_main_context_wakeup", LIB_GPR_VOID_RULE_1),
};

/* 库注册表 */
static struct sw64_lib_item sw64_libs[] = {
    {"libc", libc_methods, sizeof(libc_methods) / sizeof(sw64_method_item)},
    {"libm", libm_methods, sizeof(libm_methods) / sizeof(sw64_method_item)},
    {"libz", libz_methods, sizeof(libz_methods) / sizeof(sw64_method_item)},
    {"libxcb", libxcb_methods,
     sizeof(libxcb_methods) / sizeof(sw64_method_item)},
    {"libglib-2", libglib2_methods,
     sizeof(libglib2_methods) / sizeof(sw64_method_item)},
    {NULL, NULL, 0}};

/*============================================================================
 * 辅助函数 - 查找
 *============================================================================*/

static sw64_lib_item *in_sw64libs(const char *libname) {
  for (sw64_lib_item *lib = sw64_libs; lib->lib_name != NULL; lib++) {
    if (!strcmp(libname, lib->lib_name)) {
      return lib;
    }
  }
  return NULL;
}

static sw64_method_item *in_sw64methods(sw64_lib_item *lib,
                                        const char *funcname) {
  if (lib == NULL)
    return NULL;
  for (size_t i = 0; i < lib->num_methods; i++) {
    if (!strcmp(funcname, lib->methods[i].funcname)) {
      return &lib->methods[i];
    }
  }
  return NULL;
}

/*============================================================================
 * 锁管理
 *============================================================================*/

void native_libs_lock(void) {
  if (native_libs_lock_count++ == 0) {
    pthread_mutex_lock(&native_libs_mutex);
  }
}

void native_libs_unlock(void) {
  if (--native_libs_lock_count == 0) {
    pthread_mutex_unlock(&native_libs_mutex);
  }
}

void native_libs_fork_start(void) {
  if (native_libs_lock_count)
    abort();
  pthread_mutex_lock(&native_libs_mutex);
}

void native_libs_fork_end(int child) {
  if (child)
    pthread_mutex_init(&native_libs_mutex, NULL);
  else
    pthread_mutex_unlock(&native_libs_mutex);
}

/*============================================================================
 * 内存管理
 *============================================================================*/

static void free_metadata(gpointer data) {
  FunctionMetadata *meta = (FunctionMetadata *)data;
  if (meta) {
    g_free(meta->libname);
    g_free(meta->funcname);
    g_free(meta);
  }
}

static void free_libitem_ptr(gpointer data) {
  Libraris *lib = (Libraris *)data;
  if (!lib)
    return;
  if (lib->libname)
    g_free(lib->libname);
  if (lib->funcs)
    g_hash_table_destroy(lib->funcs);
  g_free(lib);
}

static guint loaded_inode_hash(gconstpointer key) {
  const LoadedInodeKey *inode_key = key;

  return g_int64_hash(&inode_key->dev) ^ (g_int64_hash(&inode_key->ino) << 1);
}

static gboolean loaded_inode_equal(gconstpointer a, gconstpointer b) {
  const LoadedInodeKey *left = a;
  const LoadedInodeKey *right = b;

  return left->dev == right->dev && left->ino == right->ino;
}

void free_libentries(void) {
  native_libs_lock();

  if (libraries) {
    g_ptr_array_unref(libraries);
    libraries = NULL;
  }

  if (global_plt_table) {
    g_hash_table_destroy(global_plt_table);
    global_plt_table = NULL;
  }
  if (loaded_inodes) {
    g_hash_table_destroy(loaded_inodes);
    loaded_inodes = NULL;
  }
  if (loaded_library_names) {
    g_hash_table_destroy(loaded_library_names);
    loaded_library_names = NULL;
  }

  if (is_global_table_mutex_initialized) {
    g_mutex_clear(&global_table_mutex);
    is_global_table_mutex_initialized = 0;
  }

  native_libs_unlock();
}

/*============================================================================
 * 初始化
 *============================================================================*/

static void free_plt_value(gpointer data) {
  PLT_HashValue *val = (PLT_HashValue *)data;
  if (val) {
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
    if (val->module_name)
      g_free(val->module_name);
    if (val->funcname)
      g_free(val->funcname);
#endif
    g_free(val);
  }
}

static inline void init_libentries(void) {
  if ((!NEED_FULL_DYNSYM_ANALYSIS || libraries != NULL) &&
      global_plt_table != NULL && loaded_inodes != NULL &&
      loaded_library_names != NULL) {
    return;
  }

  native_libs_lock();

  if (NEED_FULL_DYNSYM_ANALYSIS && libraries == NULL) {
    libraries = g_ptr_array_new_with_free_func(free_libitem_ptr);
  }

  if (loaded_inodes == NULL) {
    loaded_inodes = g_hash_table_new_full(loaded_inode_hash, loaded_inode_equal,
                                          g_free, NULL);
  }

  if (loaded_library_names == NULL) {
    loaded_library_names =
        g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  }

  if (global_plt_table == NULL) {
    global_plt_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, free_plt_value);
  }

  if (!is_global_table_mutex_initialized) {
    g_mutex_init(&global_table_mutex);
    is_global_table_mutex_initialized = 1;
  }

  native_libs_unlock();
}

/*============================================================================
 * 调试输出
 *============================================================================*/

#if defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) ||                                  \
    defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
static inline void print_metadata(gpointer key, gpointer value,
                                  gpointer user_data) {
  uintptr_t targetaddr = (uintptr_t)key;
  FunctionMetadata *meta = (FunctionMetadata *)value;
  FILE *f = (FILE *)user_data;
  fprintf(f, " %-20s  %-40s targetaddr = 0x%016lx, hostaddr = 0x%lx\n",
          meta->libname, meta->funcname, targetaddr, meta->bridge.hostaddr);
}
#endif

#if defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG)
static inline void print_library(struct Libraris *lib) {
  if (lib) {
    printf("===== Libraries and Functions =====\n");
    printf("--%-20s\n", lib->libname);
    g_hash_table_foreach(lib->funcs, print_metadata, stderr);
    printf("===================================\n");
  }
}
#endif

#if defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)
void native_libs_write_to_file(uintptr_t targetaddr, FunctionMetadata *meta) {
  pthread_mutex_lock(&native_libs_write_mutex);
  FILE *fp = fopen(native_libs_write_path, "a");
  if (fp) {
    print_metadata((gpointer)targetaddr, meta, fp);
    fclose(fp);
  }
  pthread_mutex_unlock(&native_libs_write_mutex);
}
#endif

/*============================================================================
 * 函数查找
 *============================================================================*/

FunctionMetadata *find_function_metadata_by_address(uintptr_t targetaddr) {
  if (!libraries)
    return NULL;
  for (guint i = 0; i < libraries->len; i++) {
    Libraris *lib = (Libraris *)g_ptr_array_index(libraries, i);
    if (lib->funcs) {
      FunctionMetadata *meta =
          g_hash_table_lookup(lib->funcs, GUINT_TO_POINTER(targetaddr));
      if (meta)
        return meta;
    }
  }
  return NULL;
}

/*============================================================================
 * 库/函数保存
 *============================================================================*/

static int is_inode_already_loaded(dev_t dev, ino_t ino) {
  LoadedInodeKey key = {
      .dev = dev,
      .ino = ino,
  };

  return loaded_inodes != NULL && g_hash_table_contains(loaded_inodes, &key);
}

static inline void save_function(uintptr_t targetaddr, const char *libname,
                                 const char *funcname,
                                 sw64_method_item *method) {
  native_libs_lock();

  FunctionMetadata *meta = g_malloc(sizeof(FunctionMetadata));
  meta->libname = g_strdup(libname);
  meta->funcname = g_strdup(funcname);

  if (method) {
    meta->bridge.rule = method->rule;
    /* memcpy 特殊处理：使用 memmove 实现 */
    meta->bridge.hostaddr = !strcmp(funcname, "memcpy")
                                ? (uintptr_t)dlsym(RTLD_DEFAULT, "memmove")
                                : (uintptr_t)dlsym(RTLD_DEFAULT, funcname);
  } else {
    meta->bridge.rule = (ArchCallingRule){0, 0, 0};
    meta->bridge.hostaddr = 0;
  }

  Libraris *current_lib;
  if (libraries->len == 0 ||
      ((Libraris *)g_ptr_array_index(libraries, libraries->len - 1))->done ==
          1) {
    current_lib = g_malloc0(sizeof(Libraris));
    g_ptr_array_add(libraries, current_lib);
  } else {
    current_lib = (Libraris *)g_ptr_array_index(libraries, libraries->len - 1);
  }

  if (current_lib->funcs == NULL) {
    current_lib->funcs = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                               NULL, free_metadata);
  }

  if (!g_hash_table_contains(current_lib->funcs,
                             GUINT_TO_POINTER(targetaddr))) {
    g_hash_table_insert(current_lib->funcs, GUINT_TO_POINTER(targetaddr), meta);
  } else {
    free_metadata(meta);
  }

  native_libs_unlock();
}

static inline void save_library(const char *libname, uintptr_t minaddr,
                                uintptr_t maxaddr, dev_t dev, ino_t ino) {
  native_libs_lock();

  if (loaded_inodes != NULL) {
    LoadedInodeKey key = {
        .dev = dev,
        .ino = ino,
    };

    if (!g_hash_table_contains(loaded_inodes, &key)) {
      LoadedInodeKey *stored_key = g_new(LoadedInodeKey, 1);
      *stored_key = key;
      g_hash_table_insert(loaded_inodes, stored_key, NULL);
    }
  }

  if (loaded_library_names != NULL &&
      !g_hash_table_contains(loaded_library_names, libname)) {
    g_hash_table_insert(loaded_library_names, g_strdup(libname), NULL);
  }

  if (!NEED_FULL_DYNSYM_ANALYSIS) {
    native_libs_unlock();
    return;
  }

  Libraris *current_lib;
  if (libraries->len == 0 ||
      ((Libraris *)g_ptr_array_index(libraries, libraries->len - 1))->done ==
          1) {
    current_lib = g_malloc0(sizeof(Libraris));
    g_ptr_array_add(libraries, current_lib);
  } else {
    current_lib = (Libraris *)g_ptr_array_index(libraries, libraries->len - 1);
  }

  current_lib->minaddr = minaddr;
  current_lib->maxaddr = maxaddr;
  current_lib->libname = g_strdup(libname);
  current_lib->dev = dev;
  current_lib->ino = ino;
  current_lib->done = 1;

  native_libs_unlock();
}

/*============================================================================
 * 函数替换
 *============================================================================*/

#if defined(CONFIG_NATIVE_LIBS)
static inline void do_replace_x86func_with_sw64Bridge(gpointer key,
                                                      gpointer value,
                                                      gpointer user_data) {
  uintptr_t targetaddr = (uintptr_t)key;
  FunctionMetadata *meta = (FunctionMetadata *)value;

  /* 写入陷阱标识: 0xCC "SC" */
  *(uint8_t *)targetaddr = 0xCC;
  *(uint8_t *)(targetaddr + 1) = 'S';
  *(uint8_t *)(targetaddr + 2) = 'C';
}

static inline void replace_x86func_with_sw64Bridge(struct Libraris *lib,
                                                   sw64_lib_item *lib_item) {

  if (!lib)
    return;

  size_t page_size = sysconf(_SC_PAGESIZE);
  uintptr_t aligned_start = lib->minaddr & ~(page_size - 1);
  uintptr_t aligned_end = (lib->maxaddr + page_size - 1) & ~(page_size - 1);
  size_t length = aligned_end - aligned_start;

  int original_prot = PROT_READ | PROT_EXEC;
  if (mprotect((void *)aligned_start, length, original_prot | PROT_WRITE) ==
      -1) {
    perror("mprotect PROT_WRITE failed");
    exit(-1);
  }

  if (lib->funcs) {
    g_hash_table_foreach(lib->funcs, do_replace_x86func_with_sw64Bridge,
                         lib_item);
  }

  if (mprotect((void *)aligned_start, length, original_prot) == -1) {
    perror("Restore mprotect failed");
    exit(-1);
  }
}
#endif

/*============================================================================
 * PLT 替换
 *============================================================================*/

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) && defined(__sw_64__)
#define PLT_ENTRY_SIZE 16

static bool plt_stub_matches_expected_layout(uintptr_t plt_stub_va,
                                             const PLT_HashValue *plt_value) {
  if (plt_value->with_cet) {
    if (*(uint32_t *)plt_stub_va != 0xfa1e0ff3) {
      return false;
    }

    if (*(uint8_t *)(plt_stub_va + 4) == 0xf2) {
      return *(uint16_t *)(plt_stub_va + 5) == 0x25ff;
    }

    return *(uint16_t *)(plt_stub_va + 4) == 0x25ff;
  }

  return *(uint16_t *)plt_stub_va == 0x25ff;
}

static bool do_replace_plt_with_trap(gpointer key, gpointer value) {
  uintptr_t plt_stub_va = (uintptr_t)key;
  PLT_HashValue *plt_value = (PLT_HashValue *)value;
  uint32_t offset;

  if (!plt_stub_matches_expected_layout(plt_stub_va, plt_value)) {
    return false;
  }

  if (plt_value->with_cet) {
    /* CET: endbr64 + jmp -> 0xCC 'E' + disp32 + plt_begin_va */
    *(uint16_t *)plt_stub_va = (uint16_t)PLT_WITH_CET;
    if (*(uint8_t *)(plt_stub_va + 4) == 0xf2) {
      offset = *(uint32_t *)(plt_stub_va + 7);
      *(uint8_t *)(plt_stub_va + 2) = 0xf2;
      *(uint32_t *)(plt_stub_va + 3) = offset;
    } else {
      offset = *(uint32_t *)(plt_stub_va + 6);
      *(uint32_t *)(plt_stub_va + 2) = offset;
    }
    *(uint64_t *)(plt_stub_va + 8) = plt_value->plt_begin_va;
  } else {
    /* 非CET: jmp -> 0xCC 'P' + disp32 */
    *(uint16_t *)plt_stub_va = (uint16_t)PLT_WITHOUT_CET;
  }

  return true;
}

typedef struct PLTPatchRange {
  uintptr_t min_stub;
  uintptr_t max_stub;
} PLTPatchRange;

static void do_collect_plt_patch_range(gpointer key, gpointer value,
                                       gpointer user_data) {
  uintptr_t plt_stub_va = (uintptr_t)key;
  PLT_HashValue *plt_value = (PLT_HashValue *)value;
  PLTPatchRange *range = user_data;

  if (!plt_stub_matches_expected_layout(plt_stub_va, plt_value)) {
    return;
  }

  if (range->min_stub == 0 || plt_stub_va < range->min_stub) {
    range->min_stub = plt_stub_va;
  }

  if (plt_stub_va > range->max_stub) {
    range->max_stub = plt_stub_va;
  }
}

static void do_filter_invalid_plt_entry(gpointer key, gpointer value,
                                        gpointer user_data) {
  GHashTable *valid_plt_table = user_data;
  uintptr_t plt_stub_va = (uintptr_t)key;
  PLT_HashValue *plt_value = (PLT_HashValue *)value;

  if (plt_stub_matches_expected_layout(plt_stub_va, plt_value)) {
    g_hash_table_insert(valid_plt_table, key, value);
  } else {
    free_plt_value(plt_value);
  }
}

static inline void replace_plt_with_trap(GHashTable *plt_table) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  PLTPatchRange range = {0};

  g_hash_table_foreach(plt_table, do_collect_plt_patch_range, &range);
  if (range.min_stub == 0) {
    return;
  }

  uintptr_t aligned_start = range.min_stub & ~(page_size - 1);
  uintptr_t aligned_end =
      ((range.max_stub + PLT_ENTRY_SIZE) + page_size - 1) & ~(page_size - 1);
  size_t length = aligned_end - aligned_start;

  int original_prot = PROT_READ | PROT_EXEC;
  if (mprotect((void *)aligned_start, length, original_prot | PROT_WRITE) ==
      -1) {
    perror("mprotect PROT_WRITE failed");
    exit(-1);
  }

  GHashTableIter iter;
  gpointer key;
  gpointer value;
  g_hash_table_iter_init(&iter, plt_table);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    if (!do_replace_plt_with_trap(key, value)) {
      g_hash_table_iter_remove(&iter);
      free_plt_value(value);
    }
  }

  if (mprotect((void *)aligned_start, length, original_prot) == -1) {
    perror("Restore mprotect failed");
    exit(-1);
  }
}
#endif

/*============================================================================
 * CONFIG_NATIVE_LIBS: 原生库函数替换分析
 *============================================================================*/

#if defined(CONFIG_NATIVE_LIBS)
/**
 * 遍历动态符号表，匹配白名单方法并创建函数桥接信息。
 * 仅在 CONFIG_NATIVE_LIBS 编译开关启用时生效。
 */
static void do_native_libs_analyze(sw64_lib_item *lib_item, Elf_Data *sym_data,
                                   size_t sym_count, char *strtab,
                                   abi_ulong start, abi_ulong fd_offset,
                                   const char *libname) {
  for (size_t i = 0; i < sym_count; i++) {
    GElf_Sym sym;
    if (gelf_getsym(sym_data, i, &sym) == NULL) {
      fprintf(stderr, "Error reading symbol %zu: %s\n", i,
              elf_errmsg(elf_errno()));
      continue;
    }

    const char *funcname = strtab + sym.st_name;

    if (GELF_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
      unsigned long target_addr = sym.st_value - fd_offset + start;

      sw64_method_item *method = in_sw64methods(lib_item, funcname);
      {
        save_function(target_addr, libname, funcname, method);
      }
    }
  }

  if (lib_item) {
    // replace_x86func_with_sw64Bridge(&libraries[libs_count - 1], lib_item);
  }
}
#endif

/*============================================================================
 * CONFIG_INDIRECT_JUMP_OPT_PLT: PLT 间接跳转优化分析
 *============================================================================*/

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) && defined(__sw_64__)
static void do_plt_merge_to_global(gpointer key, gpointer value,
                                   gpointer user_data) {
  g_hash_table_insert(global_plt_table, key, value);
}

/**
 * 解析 .rela.plt 段，构建 PLT 跳转表并替换为优化陷阱。
 * 仅在 CONFIG_INDIRECT_JUMP_OPT_PLT 编译开关启用时生效。
 */
static void do_plt_opt_analyze(int fd, Elf *elf, Elf_Scn *scn_rela_plt,
                               GElf_Shdr *shdr_rela_plt, Elf_Scn *scn_dynsym,
                               GElf_Shdr *shdr_dynsym, abi_ulong plt_sec_va,
                               abi_ulong plt_begin_va, abi_ulong start,
                               abi_ulong len, const char *libname) {
  if (!scn_rela_plt || (!plt_sec_va && !plt_begin_va))
    return;

  Elf_Data *rela_data = elf_getdata(scn_rela_plt, NULL);
  if (!rela_data) {
    fprintf(stderr, "%s Failed to get data from .rela.plt section\n", libname);
    return;
  }

  GHashTable *current_plt_table =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

  bool current_plt_not_empty = false;
  size_t rela_count = shdr_rela_plt->sh_size / shdr_rela_plt->sh_entsize;

  ANALYZE_STATS_DO(analyze_stats.rela_plt_count += rela_count;);

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
  char *strtab = NULL;
  Elf_Data *dynsym_data = elf_getdata(scn_dynsym, NULL);
  if (shdr_dynsym->sh_link != SHN_UNDEF) {
    Elf_Scn *strtab_scn = elf_getscn(elf, shdr_dynsym->sh_link);
    if (strtab_scn) {
      GElf_Shdr strtab_shdr;
      if (gelf_getshdr(strtab_scn, &strtab_shdr) == &strtab_shdr) {
        strtab = malloc(strtab_shdr.sh_size);
        if (strtab) {
          if (pread(fd, strtab, strtab_shdr.sh_size, strtab_shdr.sh_offset) !=
              strtab_shdr.sh_size) {
            free(strtab);
            strtab = NULL;
          }
        }
      }
    }
  }
#endif

  for (size_t i = 0; i < rela_count; i++) {
    GElf_Rela rela;
    if (gelf_getrela(rela_data, i, &rela) == NULL) {
      fprintf(stderr, "Error reading relocation entry %zu: %s\n", i,
              elf_errmsg(elf_errno()));
      continue;
    }

    if (ELF64_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT) {
      abi_ulong plt_stub_va;
      int with_cet;

      if (plt_sec_va) {
        plt_stub_va = plt_sec_va + i * 16;
        with_cet = 1;
      } else {
        plt_stub_va = plt_begin_va + (i + 1) * 16;
        with_cet = 0;
      }

      int sym_idx = ELF64_R_SYM(rela.r_info);
      if (sym_idx < 0 ||
          sym_idx >= (int)(shdr_dynsym->sh_size / shdr_dynsym->sh_entsize)) {
        fprintf(stderr, "Invalid symbol index: %d\n", sym_idx);
        continue;
      }

      PLT_HashValue *plt_value = g_malloc0(sizeof(PLT_HashValue));
      plt_value->plt_begin_va = plt_begin_va;
      plt_value->with_cet = with_cet;

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
      plt_value->module_name = g_strdup(libname);
      if (strtab && dynsym_data) {
        GElf_Sym sym;
        if (gelf_getsym(dynsym_data, sym_idx, &sym) != NULL) {
          plt_value->funcname = g_strdup(strtab + sym.st_name);
        }
      }
#endif

      g_hash_table_insert(current_plt_table, GUINT_TO_POINTER(plt_stub_va),
                          plt_value);
      current_plt_not_empty = true;
    }
  }

#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT_DEBUG) && defined(__sw_64__)
  if (strtab) {
    free(strtab);
  }
#endif

  if (current_plt_not_empty) {
    GHashTable *valid_plt_table =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    g_hash_table_foreach(current_plt_table, do_filter_invalid_plt_entry,
                         valid_plt_table);
    g_hash_table_destroy(current_plt_table);
    current_plt_table = valid_plt_table;

    if (g_hash_table_size(current_plt_table) > 0) {
      replace_plt_with_trap(current_plt_table);
      g_hash_table_foreach(current_plt_table, do_plt_merge_to_global, NULL);
    }
  }
  g_hash_table_destroy(current_plt_table);
}
#endif

/*============================================================================
 * 核心分析函数（公用入口调度器）
 *============================================================================*/

static void do_analyze_x86binary(const char *libname, int fd, abi_ulong start,
                                 abi_ulong len, abi_ulong fd_offset, dev_t dev,
                                 ino_t ino) {
  Elf *elf = NULL;
  Elf_Scn *scn = NULL;
  Elf_Scn *scn_dynsym = NULL;
  char *strtab = NULL;
  GElf_Shdr shdr, shdr_dynsym;
  size_t shstrndx;
  int found_dynsym = 0;
  ANALYZE_STATS_DECLARE_ENABLED();
  ANALYZE_STATS_DECLARE_TIMERS();
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) && defined(__sw_64__)
  Elf_Scn *scn_rela_plt = NULL;
  GElf_Shdr shdr_rela_plt;
  int found_rela_plt = 0, found_plt = 0, found_plt_sec = 0;
  abi_ulong plt_begin_va = 0, plt_sec_va = 0;
  memset(&shdr_rela_plt, 0, sizeof(GElf_Shdr));
#endif

  memset(&shdr_dynsym, 0, sizeof(GElf_Shdr));

  init_libentries();

  if (elf_version(EV_CURRENT) == EV_NONE)
    goto cleanup;
  if (!(elf = elf_begin(fd, ELF_C_READ, NULL)))
    goto cleanup;
  if (elf_getshdrstrndx(elf, &shstrndx) != 0)
    goto cleanup;

  ANALYZE_STATS_DO(scan_begin_ns = ANALYZE_CLOCK_NOW_NS(););

  /* 查找所需节 */
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) == NULL) {
      fprintf(stderr, "Failed to read section header: %s\n",
              elf_errmsg(elf_errno()));
      elf_end(elf);
      close(fd);
      goto cleanup;
    }

    const char *sname = elf_strptr(elf, shstrndx, shdr.sh_name);
    if (!sname)
      continue;

    if (strcmp(sname, ".dynsym") == 0) {
      found_dynsym = 1;
      memcpy(&shdr_dynsym, &shdr, sizeof(GElf_Shdr));
      scn_dynsym = scn;
    }
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) && defined(__sw_64__)
    else if (strcmp(sname, ".rela.plt") == 0) {
      found_rela_plt = 1;
      memcpy(&shdr_rela_plt, &shdr, sizeof(GElf_Shdr));
      scn_rela_plt = scn;
    } else if (strcmp(sname, ".plt") == 0) {
      plt_begin_va = start + (shdr.sh_offset - fd_offset);
      found_plt = 1;
    } else if (strcmp(sname, ".plt.sec") == 0) {
      plt_sec_va = start + (shdr.sh_offset - fd_offset);
      found_plt_sec = 1;
    }
    if (found_dynsym && found_rela_plt && found_plt && found_plt_sec)
      break;
#else
    if (found_dynsym)
      break;
#endif
  }

  ANALYZE_STATS_DO(analyze_stats.section_scan_ns +=
                   ANALYZE_CLOCK_NOW_NS() - scan_begin_ns;);

  if (NEED_FULL_DYNSYM_ANALYSIS) {
    ANALYZE_STATS_DO(dynsym_begin_ns = ANALYZE_CLOCK_NOW_NS(););

    sw64_lib_item *lib_item = in_sw64libs(libname);

    /* 获取字符串表 */
    Elf_Scn *strtab_scn = elf_getscn(elf, shdr_dynsym.sh_link);
    if (!strtab_scn) {
      fprintf(stderr, "Failed to get string table section\n");
      goto cleanup;
    }

    GElf_Shdr strtab_shdr;
    if (gelf_getshdr(strtab_scn, &strtab_shdr) != &strtab_shdr) {
      fprintf(stderr, "Failed to get string table header\n");
      goto cleanup;
    }

    strtab = malloc(strtab_shdr.sh_size);
    if (!strtab || pread(fd, strtab, strtab_shdr.sh_size,
                         strtab_shdr.sh_offset) != strtab_shdr.sh_size) {
      fprintf(stderr, "Failed to read string table\n");
      goto cleanup;
    }

    Elf_Data *data = elf_getdata(scn_dynsym, NULL);
    if (!data) {
      fprintf(stderr, "Failed to get data from section\n");
      goto cleanup;
    }

    /* 遍历符号表并处理 */
    size_t sym_count = shdr_dynsym.sh_size / shdr_dynsym.sh_entsize;

    ANALYZE_STATS_DO(analyze_stats.dynsym_count += sym_count;);

    /* ---- CONFIG_NATIVE_LIBS: 原生库函数替换处理 ---- */
#if defined(CONFIG_NATIVE_LIBS)
    do_native_libs_analyze(lib_item, data, sym_count, strtab, start, fd_offset,
                           libname);
#else
    /* 非 CONFIG_NATIVE_LIBS 模式下的符号处理（调试模式） */
    for (size_t i = 0; i < sym_count; i++) {
      GElf_Sym sym;
      if (gelf_getsym(data, i, &sym) == NULL) {
        fprintf(stderr, "Error reading symbol %zu: %s\n", i,
                elf_errmsg(elf_errno()));
        continue;
      }

      const char *funcname = strtab + sym.st_name;

      if (GELF_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
        unsigned long target_addr = sym.st_value - fd_offset + start;
        save_function(target_addr, libname, funcname,
                      in_sw64methods(lib_item, funcname));
      }
    }
#endif

    ANALYZE_STATS_DO(analyze_stats.dynsym_ns +=
                     ANALYZE_CLOCK_NOW_NS() - dynsym_begin_ns;);
  }

  /* ---- CONFIG_INDIRECT_JUMP_OPT_PLT: PLT 间接跳转优化处理 ---- */
#if defined(CONFIG_INDIRECT_JUMP_OPT_PLT) && defined(__sw_64__)
  ANALYZE_STATS_DO(plt_begin_ns = ANALYZE_CLOCK_NOW_NS(););
  do_plt_opt_analyze(fd, elf, scn_rela_plt, &shdr_rela_plt, scn_dynsym,
                     &shdr_dynsym, plt_sec_va, plt_begin_va, start, len,
                     libname);
  ANALYZE_STATS_DO(analyze_stats.plt_ns +=
                   ANALYZE_CLOCK_NOW_NS() - plt_begin_ns;);
#endif

cleanup:
  if (strtab)
    free(strtab);
  if (elf)
    elf_end(elf);

  ANALYZE_STATS_DO(save_begin_ns = ANALYZE_CLOCK_NOW_NS(););
  save_library(libname, start, start + len, dev, ino);
  ANALYZE_STATS_DO(analyze_stats.save_library_ns +=
                   ANALYZE_CLOCK_NOW_NS() - save_begin_ns;);
}

/*============================================================================
 * 公共接口
 *============================================================================*/

void analyze_x86binary(int fd, abi_ulong start, abi_ulong len,
                       abi_ulong fd_offset) {
#if (defined(CONFIG_INDIRECT_JUMP_OPT_PLT) || defined(CONFIG_NATIVE_LIBS) ||   \
     defined(CONFIG_NATIVE_LIBS_LOAD_DEBUG) ||                                 \
     defined(CONFIG_NATIVE_LIBS_CALL_DEBUG)) &&                                \
    defined(__sw_64__)
  ANALYZE_STATS_DECLARE_ENABLED();
  ANALYZE_STATS_DECLARE_TOTAL_TIMER();

  ANALYZE_STATS_DO(analyze_stats.calls++;
                   analyze_begin_ns = ANALYZE_CLOCK_NOW_NS(););

  if (fd < 2) {
    ANALYZE_STATS_DO(analyze_stats.skipped_fd++;);
    return;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    ANALYZE_STATS_DO(analyze_stats.skipped_fstat++;);
    return;
  }
  if (is_inode_already_loaded(st.st_dev, st.st_ino)) {
    ANALYZE_STATS_DO(analyze_stats.skipped_inode++;);
    return;
  }

  char path[256];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

  char libname_path[1024] = {0};
  char libname[1024] = {0};

  int libname_len = readlink(path, libname_path, sizeof(libname_path) - 1);
  if (libname_len != -1) {
    libname_path[libname_len] = '\0';
    char *last_slash = strrchr(libname_path, '/');
    strcpy(libname, last_slash ? last_slash + 1 : libname_path);

    char *dot = strchr(libname, '.');
    if (dot)
      *dot = '\0';

    do_analyze_x86binary(libname, fd, start, len, fd_offset, st.st_dev,
                         st.st_ino);
    ANALYZE_STATS_DO(analyze_stats.analyzed_files++;
                     analyze_stats.total_ns +=
                     ANALYZE_CLOCK_NOW_NS() - analyze_begin_ns;);
  } else {
    ANALYZE_STATS_DO(analyze_stats.skipped_readlink++;
                     analyze_stats.total_ns +=
                     ANALYZE_CLOCK_NOW_NS() - analyze_begin_ns;);
  }
#endif
}

#endif /* CONFIG_NATIVE_LIBS || ... */
