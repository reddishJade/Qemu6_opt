/* Runtime profile for non-return x86 indirect branches. */
#include "qemu/osdep.h"
#include "exec/indirect-profile.h"
#include "qemu/thread.h"

#define INDIRECT_PROFILE_BUCKETS 65536
#define INDIRECT_PROFILE_TOPK 4

typedef struct IndirectTarget {
    uint64_t target;
    uint64_t count;
    uint64_t error;
} IndirectTarget;

typedef struct IndirectSite {
    uint64_t site_pc;
    uint64_t executions;
    uint64_t target_changes;
    uint64_t last_target;
    uint64_t replacements;
    uint32_t type;
    IndirectTarget top[INDIRECT_PROFILE_TOPK];
    struct IndirectSite *next;
} IndirectSite;

static IndirectSite *site_buckets[INDIRECT_PROFILE_BUCKETS];
static QemuMutex profile_lock;
static gsize profile_initialized;
static pid_t profile_owner_pid;

static void indirect_profile_init(void)
{
    if (g_once_init_enter(&profile_initialized)) {
        qemu_mutex_init(&profile_lock);
        profile_owner_pid = getpid();
        g_once_init_leave(&profile_initialized, 1);
    }
}

static void indirect_profile_check_fork(void)
{
    pid_t pid = getpid();

    if (pid != profile_owner_pid) {
        /* The child must not report the parent's pre-fork observations. */
        memset(site_buckets, 0, sizeof(site_buckets));
        qemu_mutex_destroy(&profile_lock);
        qemu_mutex_init(&profile_lock);
        profile_owner_pid = pid;
    }
}

static unsigned site_hash(uint64_t pc, uint32_t type)
{
    uint64_t x = pc ^ ((uint64_t)type << 61);

    x ^= x >> 33;
    x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33;
    return x & (INDIRECT_PROFILE_BUCKETS - 1);
}

static IndirectSite *find_or_create_site(uint64_t pc, uint32_t type)
{
    unsigned bucket = site_hash(pc, type);
    IndirectSite *site;

    for (site = site_buckets[bucket]; site; site = site->next) {
        if (site->site_pc == pc && site->type == type) {
            return site;
        }
    }

    site = g_new0(IndirectSite, 1);
    site->site_pc = pc;
    site->type = type;
    site->next = site_buckets[bucket];
    site_buckets[bucket] = site;
    return site;
}

void indirect_profile_record(uint64_t site_pc, uint64_t target, uint32_t type)
{
    IndirectSite *site;
    unsigned i, minimum = 0;

    indirect_profile_init();
    indirect_profile_check_fork();
    qemu_mutex_lock(&profile_lock);
    site = find_or_create_site(site_pc, type);

    site->executions++;
    if (site->executions > 1 && site->last_target != target) {
        site->target_changes++;
    }
    site->last_target = target;

    for (i = 0; i < INDIRECT_PROFILE_TOPK; i++) {
        if (site->top[i].count && site->top[i].target == target) {
            site->top[i].count++;
            qemu_mutex_unlock(&profile_lock);
            return;
        }
        if (!site->top[i].count) {
            site->top[i].target = target;
            site->top[i].count = 1;
            qemu_mutex_unlock(&profile_lock);
            return;
        }
        if (site->top[i].count < site->top[minimum].count) {
            minimum = i;
        }
    }

    site->replacements++;
    site->top[minimum].error = site->top[minimum].count;
    site->top[minimum].target = target;
    site->top[minimum].count++;
    qemu_mutex_unlock(&profile_lock);
}

static int target_count_cmp(const void *a, const void *b)
{
    const IndirectTarget *ta = a;
    const IndirectTarget *tb = b;

    return ta->count < tb->count ? 1 : ta->count > tb->count ? -1 : 0;
}

static const char *indirect_profile_type_name(uint32_t type)
{
    switch (type) {
    case INDIRECT_PROFILE_CALL:
        return "indirect_call";
    case INDIRECT_PROFILE_JMP:
        return "indirect_jmp";
    case INDIRECT_PROFILE_RET:
        return "indirect_ret";
    default:
        return "unknown";
    }
}

void indirect_profile_dump(void)
{
    const char *configured_path = getenv("QEMU_INDIRECT_PROFILE_OUT");
    g_autofree char *default_path = NULL;
    g_autofree char *expanded_path = NULL;
    FILE *out;
    unsigned bucket;

    indirect_profile_init();
    indirect_profile_check_fork();
    if (!configured_path || !*configured_path) {
        default_path = g_strdup_printf("indirect-profile-%ld.csv", (long)getpid());
        configured_path = default_path;
    } else {
        const char *pid_marker = strstr(configured_path, "%p");

        if (pid_marker) {
            expanded_path = g_strdup_printf("%.*s%ld%s",
                (int)(pid_marker - configured_path), configured_path,
                (long)getpid(), pid_marker + 2);
            configured_path = expanded_path;
        }
    }

    out = fopen(configured_path, "w");
    if (!out) {
        fprintf(stderr, "indirect profile: cannot open %s: %s\n",
                configured_path, strerror(errno));
        return;
    }

    fprintf(out, "site_pc,type,executions,target_changes,replacements,");
    fprintf(out, "top1_target,top1_count,top1_error,top2_target,top2_count,");
    fprintf(out, "top2_error,top3_target,top3_count,top3_error,");
    fprintf(out, "top4_target,top4_count,top4_error\n");

    qemu_mutex_lock(&profile_lock);
    for (bucket = 0; bucket < INDIRECT_PROFILE_BUCKETS; bucket++) {
        IndirectSite *site;

        for (site = site_buckets[bucket]; site; site = site->next) {
            IndirectTarget sorted[INDIRECT_PROFILE_TOPK];
            unsigned i;

            memcpy(sorted, site->top, sizeof(sorted));
            qsort(sorted, INDIRECT_PROFILE_TOPK, sizeof(sorted[0]),
                  target_count_cmp);
            fprintf(out, "0x%016" PRIx64 ",%s,%" PRIu64 ",%" PRIu64
                    ",%" PRIu64,
                    site->site_pc,
                    indirect_profile_type_name(site->type),
                    site->executions, site->target_changes,
                    site->replacements);
            for (i = 0; i < INDIRECT_PROFILE_TOPK; i++) {
                fprintf(out, ",0x%016" PRIx64 ",%" PRIu64 ",%" PRIu64,
                        sorted[i].target, sorted[i].count, sorted[i].error);
            }
            fputc('\n', out);
        }
    }
    qemu_mutex_unlock(&profile_lock);
    fclose(out);
    fprintf(stderr, "indirect profile: wrote %s\n", configured_path);
}
