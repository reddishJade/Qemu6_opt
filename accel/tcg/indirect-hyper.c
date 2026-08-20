/* Online feedback state for the QEMU TCG indirect-branch Hyperchaining
 * experiment.  The module deliberately keeps the policy small: it learns a
 * bounded set of targets for a site, marks the site linked after a short
 * warm-up, and asks the current CPU to retranslate the source page.  There is
 * no offline profile and no separate prediction helper on a linked hit path.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/indirect-hyper.h"
#include "qemu/thread.h"

#define INDIRECT_HYPER_BUCKETS 4096
#define INDIRECT_HYPER_LEARN_THRESHOLD 64

typedef struct HyperTarget {
    target_ulong target;
    uint64_t count;
} HyperTarget;

typedef struct HyperSite {
    uint64_t site_pc;
    uint32_t type;
    uint64_t executions;
    uint64_t target_changes;
    uint64_t linked_fallback_executions;
    uint64_t retranslation_count;
    target_ulong last_target;
    bool linked;
    HyperTarget targets[INDIRECT_HYPER_MAX_TARGETS];
    struct HyperSite *next;
} HyperSite;

static HyperSite *site_buckets[INDIRECT_HYPER_BUCKETS];
static QemuMutex hyper_lock;
static gsize hyper_initialized;
static pid_t hyper_owner_pid;

static void indirect_hyperchain_init(void)
{
    if (g_once_init_enter(&hyper_initialized)) {
        qemu_mutex_init(&hyper_lock);
        hyper_owner_pid = getpid();
        g_once_init_leave(&hyper_initialized, 1);
    }
}

static void indirect_hyperchain_check_fork(void)
{
    pid_t pid = getpid();

    if (pid != hyper_owner_pid) {
        /* The child must learn its own targets. */
        memset(site_buckets, 0, sizeof(site_buckets));
        qemu_mutex_destroy(&hyper_lock);
        qemu_mutex_init(&hyper_lock);
        hyper_owner_pid = pid;
    }
}

static unsigned hyper_site_hash(uint64_t site_pc, uint32_t type)
{
    uint64_t x = site_pc ^ ((uint64_t)type << 61);

    x ^= x >> 33;
    x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33;
    return x & (INDIRECT_HYPER_BUCKETS - 1);
}

static HyperSite *find_or_create_site(uint64_t site_pc, uint32_t type)
{
    unsigned bucket = hyper_site_hash(site_pc, type);
    HyperSite *site;

    for (site = site_buckets[bucket]; site; site = site->next) {
        if (site->site_pc == site_pc && site->type == type) {
            return site;
        }
    }

    site = g_new0(HyperSite, 1);
    site->site_pc = site_pc;
    site->type = type;
    site->next = site_buckets[bucket];
    site_buckets[bucket] = site;
    return site;
}

static int hyper_target_cmp(const void *a, const void *b)
{
    const HyperTarget *ta = a;
    const HyperTarget *tb = b;

    if (ta->count < tb->count) {
        return 1;
    }
    if (ta->count > tb->count) {
        return -1;
    }
    return ta->target < tb->target ? -1 : ta->target > tb->target;
}

static int hyper_target_index(const HyperSite *site, target_ulong target)
{
    for (unsigned i = 0; i < ARRAY_SIZE(site->targets); i++) {
        if (site->targets[i].count && site->targets[i].target == target) {
            return i;
        }
    }
    return -1;
}

static int hyper_empty_index(const HyperSite *site)
{
    for (unsigned i = 0; i < ARRAY_SIZE(site->targets); i++) {
        if (!site->targets[i].count) {
            return i;
        }
    }
    return -1;
}

bool indirect_hyperchain_get_targets(uint64_t site_pc, uint32_t type,
                                     target_ulong targets[], unsigned *count)
{
    HyperSite *site;
    HyperTarget sorted[INDIRECT_HYPER_MAX_TARGETS];
    unsigned n = 0;

    *count = 0;
    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    if (!site->linked) {
        qemu_mutex_unlock(&hyper_lock);
        return false;
    }

    memcpy(sorted, site->targets, sizeof(sorted));
    qsort(sorted, ARRAY_SIZE(sorted), sizeof(sorted[0]), hyper_target_cmp);
    for (unsigned i = 0; i < ARRAY_SIZE(sorted); i++) {
        if (!sorted[i].count) {
            break;
        }
        targets[n++] = sorted[i].target;
    }
    *count = n;
    qemu_mutex_unlock(&hyper_lock);
    return n != 0;
}

void indirect_hyperchain_record(CPUState *cpu, uint64_t site_pc,
                                target_ulong target, uint32_t type)
{
    HyperSite *site;
    bool retranslate = false;
    int index;

    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    site->executions++;
    if (site->linked) {
        site->linked_fallback_executions++;
    }
    if (site->executions > 1 && site->last_target != target) {
        site->target_changes++;
    }
    site->last_target = target;

    index = hyper_target_index(site, target);
    if (index >= 0) {
        site->targets[index].count++;
    } else {
        index = hyper_empty_index(site);
        if (index >= 0) {
            site->targets[index].target = target;
            site->targets[index].count = 1;
            retranslate = site->linked;
        }
    }

    if (!site->linked && site->executions >= INDIRECT_HYPER_LEARN_THRESHOLD) {
        site->linked = true;
        retranslate = true;
    }
    if (retranslate) {
        site->retranslation_count++;
    }
    qemu_mutex_unlock(&hyper_lock);

    if (retranslate) {
        /* The translator will observe the new target list on the next TB. */
        tb_invalidate_phys_addr(site_pc);
        cpu_loop_exit_noexc(cpu);
    }
}

static const char *hyper_type_name(uint32_t type)
{
    switch (type) {
    case INDIRECT_HYPER_CALL:
        return "indirect_call";
    case INDIRECT_HYPER_JMP:
        return "indirect_jmp";
    default:
        return "unknown";
    }
}

void indirect_hyperchain_dump(void)
{
    const char *configured_path = getenv("QEMU_INDIRECT_HYPERCHAIN_OUT");
    g_autofree char *default_path = NULL;
    g_autofree char *expanded_path = NULL;
    FILE *out;

    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    if (!configured_path || !*configured_path) {
        default_path = g_strdup_printf("indirect-hyperchain-%ld.csv",
                                       (long)getpid());
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
        fprintf(stderr, "indirect hyperchain: cannot open %s: %s\n",
                configured_path, strerror(errno));
        return;
    }

    fprintf(out, "site_pc,type,executions,target_changes,linked,"
                 "linked_fallback_executions,retranslations");
    for (unsigned i = 0; i < INDIRECT_HYPER_MAX_TARGETS; i++) {
        fprintf(out, ",target%u,target%u_count", i + 1, i + 1);
    }
    fputc('\n', out);

    qemu_mutex_lock(&hyper_lock);
    for (unsigned bucket = 0; bucket < INDIRECT_HYPER_BUCKETS; bucket++) {
        for (HyperSite *site = site_buckets[bucket]; site; site = site->next) {
            HyperTarget sorted[INDIRECT_HYPER_MAX_TARGETS];

            memcpy(sorted, site->targets, sizeof(sorted));
            qsort(sorted, ARRAY_SIZE(sorted), sizeof(sorted[0]),
                  hyper_target_cmp);
            fprintf(out, "0x%016" PRIx64 ",%s,%" PRIu64 ",%" PRIu64
                         ",%u,%" PRIu64 ",%" PRIu64,
                    site->site_pc, hyper_type_name(site->type),
                    site->executions, site->target_changes, site->linked,
                    site->linked_fallback_executions,
                    site->retranslation_count);
            for (unsigned i = 0; i < ARRAY_SIZE(sorted); i++) {
                fprintf(out, ",0x%016" PRIx64 ",%" PRIu64,
                        sorted[i].target, sorted[i].count);
            }
            fputc('\n', out);
        }
    }
    qemu_mutex_unlock(&hyper_lock);
    fclose(out);
    fprintf(stderr, "indirect hyperchain: wrote %s\n", configured_path);
}
