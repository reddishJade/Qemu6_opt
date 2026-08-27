/* Online feedback state for the QEMU TCG indirect-branch Hyperchaining
 * experiment.  The module deliberately keeps the policy small: it learns a
 * bounded set of targets for a site, marks the site linked after a short
 * warm-up, and asks the current CPU to retranslate the source page.  Linked
 * hits execute a patched host-TB jump from the translated compare chain.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/indirect-hyper.h"
#include "qemu/thread.h"

#define INDIRECT_HYPER_BUCKETS 4096
#define INDIRECT_HYPER_LEARN_THRESHOLD 32
#define INDIRECT_HYPER_ACTIVE_TARGETS 3
#define INDIRECT_HYPER_MIN_TRACKED_PERCENT 90
#define INDIRECT_HYPER_FALLBACK_DISABLE_THRESHOLD 32

typedef struct HyperTarget {
    target_ulong target;
    uint64_t count;
} HyperTarget;

typedef struct HyperSite {
    uint64_t site_pc;
    uint32_t type;
    uint64_t executions;
    uint64_t target_changes;
    uint64_t untracked_executions;
    uint64_t linked_fallback_executions;
    uint64_t retranslation_count;
    target_ulong last_target;
    bool linked;
    bool disabled;
    HyperTarget targets[INDIRECT_HYPER_MAX_TARGETS];
    struct HyperSite *next;
} HyperSite;

static HyperSite *site_buckets[INDIRECT_HYPER_BUCKETS];
static QemuMutex hyper_lock;
static gsize hyper_initialized;
static volatile sig_atomic_t hyper_forked;

static void indirect_hyperchain_atfork_child(void)
{
    hyper_forked = 1;
}

static void indirect_hyperchain_init(void)
{
    if (g_once_init_enter(&hyper_initialized)) {
        int ret;

        qemu_mutex_init(&hyper_lock);
        ret = pthread_atfork(NULL, NULL, indirect_hyperchain_atfork_child);
        g_assert(ret == 0);
        g_once_init_leave(&hyper_initialized, 1);
    }
}

static void indirect_hyperchain_check_fork(void)
{
    if (unlikely(hyper_forked)) {
        /* The child must learn its own targets. */
        memset(site_buckets, 0, sizeof(site_buckets));
        qemu_mutex_destroy(&hyper_lock);
        qemu_mutex_init(&hyper_lock);
        hyper_forked = 0;
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
    for (unsigned i = 0; i < INDIRECT_HYPER_ACTIVE_TARGETS; i++) {
        if (site->targets[i].count && site->targets[i].target == target) {
            return i;
        }
    }
    return -1;
}

static int hyper_empty_index(const HyperSite *site)
{
    for (unsigned i = 0; i < INDIRECT_HYPER_ACTIVE_TARGETS; i++) {
        if (!site->targets[i].count) {
            return i;
        }
    }
    return -1;
}

IndirectHyperPlan indirect_hyperchain_get_plan(uint64_t site_pc,
                                               uint32_t type,
                                               target_ulong targets[],
                                               unsigned *count)
{
    HyperSite *site;
    HyperTarget sorted[INDIRECT_HYPER_MAX_TARGETS];
    IndirectHyperPlan plan;
    unsigned n = 0;

    *count = 0;
    if (type != INDIRECT_HYPER_CALL) {
        return INDIRECT_HYPER_DISABLED;
    }
    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    if (site->disabled) {
        plan = INDIRECT_HYPER_DISABLED;
        goto out;
    }
    if (!site->linked) {
        plan = INDIRECT_HYPER_OBSERVE;
        goto out;
    }

    memcpy(sorted, site->targets, sizeof(sorted));
    qsort(sorted, ARRAY_SIZE(sorted), sizeof(sorted[0]), hyper_target_cmp);
    for (unsigned i = 0; i < INDIRECT_HYPER_ACTIVE_TARGETS; i++) {
        if (!sorted[i].count) {
            break;
        }
        targets[n++] = sorted[i].target;
    }
    *count = n;
    plan = n ? INDIRECT_HYPER_LINKED : INDIRECT_HYPER_OBSERVE;

out:
    qemu_mutex_unlock(&hyper_lock);
    return plan;
}

void indirect_hyperchain_record(CPUState *cpu, uint64_t site_pc,
                                target_ulong target, uint32_t type)
{
    HyperSite *site;
    bool retranslate = false;
    int index;

    if (type != INDIRECT_HYPER_CALL) {
        return;
    }
    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    if (site->disabled) {
        qemu_mutex_unlock(&hyper_lock);
        return;
    }
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
        } else {
            site->untracked_executions++;
        }
    }

    if (!site->linked && site->executions >= INDIRECT_HYPER_LEARN_THRESHOLD) {
        uint64_t tracked = site->executions - site->untracked_executions;

        if (tracked * 100 >=
            site->executions * INDIRECT_HYPER_MIN_TRACKED_PERCENT) {
            site->linked = true;
        } else {
            site->disabled = true;
        }
        retranslate = true;
    } else if (site->linked &&
               site->linked_fallback_executions >=
               INDIRECT_HYPER_FALLBACK_DISABLE_THRESHOLD) {
        site->linked = false;
        site->disabled = true;
        retranslate = true;
    }
    if (retranslate) {
        site->retranslation_count++;
    }
    qemu_mutex_unlock(&hyper_lock);

    if (retranslate) {
        /* The translator will observe the new policy on the next TB. */
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
    const char *configured_path = getenv("QEMU_RFICH_OUT");
    g_autofree char *expanded_path = NULL;
    FILE *out;

    if (!configured_path || !*configured_path) {
        return;
    }

    indirect_hyperchain_init();
    indirect_hyperchain_check_fork();
    {
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

    fprintf(out, "site_pc,type,executions,target_changes,untracked_executions,"
                 "linked,disabled,linked_fallback_executions,retranslations");
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
                         ",%" PRIu64 ",%u,%u,%" PRIu64 ",%" PRIu64,
                    site->site_pc, hyper_type_name(site->type),
                    site->executions, site->target_changes,
                    site->untracked_executions, site->linked,
                    site->disabled, site->linked_fallback_executions,
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
