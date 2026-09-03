/* Online feedback state for the QEMU TCG indirect-call Hyperchaining
 * experiment.  A bounded exact observation epoch selects the active targets.
 * The hottest target keeps a helper-free direct path; non-head traffic feeds a
 * bounded relearning policy before continuing through the remaining slots.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/indirect-hyper.h"
#include "qemu/thread.h"

#define INDIRECT_HYPER_BUCKETS 4096
#ifndef INDIRECT_HYPER_LEARN_THRESHOLD
#define INDIRECT_HYPER_LEARN_THRESHOLD 32
#endif
#ifndef INDIRECT_HYPER_MIN_LEARN_SAMPLES
#define INDIRECT_HYPER_MIN_LEARN_SAMPLES 8
#endif
#ifndef INDIRECT_HYPER_RELEARN_SAMPLES
#define INDIRECT_HYPER_RELEARN_SAMPLES 16
#endif
#ifndef INDIRECT_HYPER_REORDER_HYSTERESIS
#define INDIRECT_HYPER_REORDER_HYSTERESIS 4
#endif
#ifndef INDIRECT_HYPER_TRACKED_TARGETS
#define INDIRECT_HYPER_TRACKED_TARGETS 3
#endif
#ifndef INDIRECT_HYPER_ACTIVE_TARGETS
#define INDIRECT_HYPER_ACTIVE_TARGETS 3
#endif
#ifndef INDIRECT_HYPER_MIN_TRACKED_PERCENT
#define INDIRECT_HYPER_MIN_TRACKED_PERCENT 90
#endif
#ifndef INDIRECT_HYPER_RELEARN_BASE
#define INDIRECT_HYPER_RELEARN_BASE 48
#endif
#ifndef INDIRECT_HYPER_RELEARN_MAX
#define INDIRECT_HYPER_RELEARN_MAX 3072
#endif
#ifndef INDIRECT_HYPER_MAX_RELEARNS
#define INDIRECT_HYPER_MAX_RELEARNS 1
#endif
#ifndef INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_MIN
#define INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_MIN 1
#endif
#ifndef INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_PERCENT
#define INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_PERCENT 5
#endif

#define INDIRECT_HYPER_CANDIDATE_CAPACITY 16
#define INDIRECT_HYPER_REQUIRED_SAMPLES(n) \
    (((n) * INDIRECT_HYPER_MIN_TRACKED_PERCENT + 99) / 100)
#define INDIRECT_HYPER_MAX_DISTINCT(n) \
    (INDIRECT_HYPER_TRACKED_TARGETS + (n) - \
     INDIRECT_HYPER_REQUIRED_SAMPLES(n) + 1)

QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MIN_TRACKED_PERCENT == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MIN_TRACKED_PERCENT > 100);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MIN_LEARN_SAMPLES == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MIN_LEARN_SAMPLES >
                  INDIRECT_HYPER_LEARN_THRESHOLD);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_RELEARN_SAMPLES == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MAX_DISTINCT(
                      INDIRECT_HYPER_LEARN_THRESHOLD) >
                  INDIRECT_HYPER_CANDIDATE_CAPACITY);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MAX_DISTINCT(
                      INDIRECT_HYPER_RELEARN_SAMPLES) >
                  INDIRECT_HYPER_CANDIDATE_CAPACITY);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_RELEARN_BASE == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_RELEARN_BASE >
                  INDIRECT_HYPER_RELEARN_MAX);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MAX_RELEARNS == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_MIN == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_PERCENT == 0);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_PERCENT > 100);
/* The TCG opcode and SW64 backend carry exactly four target operands. */
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_MAX_TARGETS != 4);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_TRACKED_TARGETS >
                  INDIRECT_HYPER_MAX_TARGETS);
QEMU_BUILD_BUG_ON(INDIRECT_HYPER_ACTIVE_TARGETS >
                  INDIRECT_HYPER_TRACKED_TARGETS);

typedef struct HyperTarget {
    target_ulong target;
    uint64_t count;
} HyperTarget;

typedef enum HyperSiteState {
    HYPER_SITE_OBSERVE,
    HYPER_SITE_LINKED,
    HYPER_SITE_DISABLED,
} HyperSiteState;

typedef struct HyperSite {
    uint64_t site_pc;
    uint32_t type;
    HyperSiteState state;

    /* Lifetime diagnostics.  Direct head hits deliberately remain invisible. */
    uint64_t observations;
    uint64_t target_changes;
    uint64_t untracked_executions;
    uint64_t linked_fallback_executions;
    uint64_t tail_feedback_executions;
    uint64_t retranslation_count;
    uint64_t relearn_count;
#if defined(CONFIG_RFICH_LOG)
    uint64_t linked_attempts;
#endif
    target_ulong last_target;

    /* Exact, bounded observation epoch. */
    HyperTarget candidates[INDIRECT_HYPER_CANDIDATE_CAPACITY];
    unsigned candidate_count;
    unsigned sample_count;

    /* Membership evidence gathered only on bounded non-head probes. */
    HyperTarget feedback_candidates[INDIRECT_HYPER_MAX_TARGETS];
    unsigned feedback_candidate_count;

    /* Currently deployed plan, already sorted by descending frequency. */
    HyperTarget targets[INDIRECT_HYPER_MAX_TARGETS];
    unsigned target_count;
    bool has_linked;
    bool tail_probe;

    /* Non-head feedback budget.  An unchanged plan backs off geometrically. */
    uint64_t feedback_events;
    uint64_t feedback_limit;

    struct HyperSite *next;
} HyperSite;

static HyperSite *site_buckets[INDIRECT_HYPER_BUCKETS];
static QemuMutex hyper_lock;
static gsize hyper_initialized;
static unsigned hyper_global_admitted_sites;
static unsigned hyper_global_phase_failures;
static bool hyper_global_disabled;

#if defined(CONFIG_RFICH_LOG)
typedef struct RFICHPatchLog {
    uint64_t attempts;
    uint64_t successes;
    uint64_t skips;
    uint64_t resets;
} RFICHPatchLog;

static RFICHPatchLog rfich_patch_log;
#endif

/* Keep the inherited guest-target policy and inherited TB code consistent.
 * Locking around fork avoids inheriting a mutex owned by a vanished thread.
 * linux-user execve replaces the host QEMU process, so a successful image
 * replacement cannot reuse this in-process policy table. */
static void indirect_hyperchain_atfork_prepare(void)
{
    qemu_mutex_lock(&hyper_lock);
}

static void indirect_hyperchain_atfork_parent(void)
{
    qemu_mutex_unlock(&hyper_lock);
}

static void indirect_hyperchain_atfork_child(void)
{
#if defined(CONFIG_RFICH_LOG)
    memset(&rfich_patch_log, 0, sizeof(rfich_patch_log));
#endif
    qemu_mutex_unlock(&hyper_lock);
}

static void indirect_hyperchain_init(void)
{
    if (g_once_init_enter(&hyper_initialized)) {
        int ret;

        qemu_mutex_init(&hyper_lock);
        ret = pthread_atfork(indirect_hyperchain_atfork_prepare,
                             indirect_hyperchain_atfork_parent,
                             indirect_hyperchain_atfork_child);
        g_assert(ret == 0);
        g_once_init_leave(&hyper_initialized, 1);
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
    site->state = HYPER_SITE_OBSERVE;
    site->feedback_limit = INDIRECT_HYPER_RELEARN_BASE;
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

static int hyper_target_index(const HyperTarget targets[], unsigned count,
                              target_ulong target)
{
    for (unsigned i = 0; i < count; i++) {
        if (targets[i].count && targets[i].target == target) {
            return i;
        }
    }
    return -1;
}

static void hyper_record_candidate(HyperSite *site, target_ulong target)
{
    int index = hyper_target_index(site->candidates, site->candidate_count,
                                   target);

    if (index >= 0) {
        site->candidates[index].count++;
        return;
    }

    /* The coverage lower bound disables an epoch before this bounded exact
     * table can overflow, even when the maximum sample window is larger. */
    g_assert(site->candidate_count < ARRAY_SIZE(site->candidates));
    index = site->candidate_count++;
    site->candidates[index].target = target;
    site->candidates[index].count = 1;
}

static void hyper_record_feedback_candidate(HyperSite *site,
                                            target_ulong target)
{
    int index = hyper_target_index(site->feedback_candidates,
                                   site->feedback_candidate_count, target);

    if (index >= 0) {
        site->feedback_candidates[index].count++;
    } else if (site->feedback_candidate_count <
               ARRAY_SIZE(site->feedback_candidates)) {
        index = site->feedback_candidate_count++;
        site->feedback_candidates[index].target = target;
        site->feedback_candidates[index].count = 1;
    }
}

static void hyper_note_phase_failure(const HyperSite *site)
{
    if (hyper_global_phase_failures < UINT_MAX) {
        hyper_global_phase_failures++;
    }
    if (!hyper_global_disabled &&
        hyper_global_phase_failures >=
            INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_MIN &&
        (uint64_t)hyper_global_phase_failures * 100 >=
            (uint64_t)hyper_global_admitted_sites *
            INDIRECT_HYPER_GLOBAL_PHASE_FAILURE_PERCENT) {
        hyper_global_disabled = true;
#if defined(CONFIG_RFICH_DEBUG)
        fprintf(stderr,
                "RFICH-DEBUG circuit site=0x%" PRIx64
                " failures=%u admitted=%u percent=%.3f decision=disabled\n",
                site->site_pc, hyper_global_phase_failures,
                hyper_global_admitted_sites,
                hyper_global_admitted_sites ?
                    100.0 * hyper_global_phase_failures /
                    hyper_global_admitted_sites : 0.0);
#endif
    }
}

/* Called with hyper_lock held after the process-level circuit breaker trips. */
static target_ulong *hyper_disable_all_sites(unsigned *count)
{
    target_ulong *sites;
    unsigned n = 0;

    for (unsigned bucket = 0; bucket < INDIRECT_HYPER_BUCKETS; bucket++) {
        for (HyperSite *site = site_buckets[bucket]; site; site = site->next) {
            if (site->has_linked) {
                n++;
            }
        }
    }
    sites = g_new(target_ulong, n);
    n = 0;
    for (unsigned bucket = 0; bucket < INDIRECT_HYPER_BUCKETS; bucket++) {
        for (HyperSite *site = site_buckets[bucket]; site; site = site->next) {
            if (site->has_linked) {
                sites[n++] = site->site_pc;
                site->state = HYPER_SITE_DISABLED;
                site->target_count = 0;
                memset(site->targets, 0, sizeof(site->targets));
            }
        }
    }
    *count = n;
    return sites;
}

static void hyper_reset_epoch(HyperSite *site)
{
    memset(site->candidates, 0, sizeof(site->candidates));
    site->candidate_count = 0;
    site->sample_count = 0;
}

static bool hyper_same_plan(const HyperSite *site,
                            const HyperTarget plan[], unsigned count)
{
    if (!site->has_linked || site->target_count != count) {
        return false;
    }
    for (unsigned i = 0; i < count; i++) {
        if (site->targets[i].target != plan[i].target) {
            return false;
        }
    }
    return true;
}

static void hyper_finish_epoch(HyperSite *site)
{
    HyperTarget sorted[INDIRECT_HYPER_CANDIDATE_CAPACITY] = { };
    HyperTarget plan[INDIRECT_HYPER_MAX_TARGETS] = { };
    target_ulong old_head = site->has_linked ? site->targets[0].target : 0;
    uint64_t tracked = 0;
    unsigned recent_tracked_count;
    unsigned sorted_count = site->candidate_count;
    unsigned count;
    bool same;

    memcpy(sorted, site->candidates,
           site->candidate_count * sizeof(sorted[0]));
    qsort(sorted, sorted_count, sizeof(sorted[0]), hyper_target_cmp);
    recent_tracked_count = MIN(sorted_count,
                               (unsigned)INDIRECT_HYPER_TRACKED_TARGETS);
    for (unsigned i = 0; i < recent_tracked_count; i++) {
        tracked += sorted[i].count;
    }

#ifndef INDIRECT_HYPER_MIN_HEAD_PERCENT
#define INDIRECT_HYPER_MIN_HEAD_PERCENT 0
#endif
    if (!recent_tracked_count ||
        tracked * 100 <
            (uint64_t)site->sample_count *
            INDIRECT_HYPER_MIN_TRACKED_PERCENT ||
        sorted[0].count * 100 <
            (uint64_t)site->sample_count *
            INDIRECT_HYPER_MIN_HEAD_PERCENT) {
#if defined(CONFIG_RFICH_DEBUG)
        fprintf(stderr,
                "RFICH-DEBUG epoch site=0x%" PRIx64
                " samples=%u distinct=%u top=[%" PRIu64 ",%" PRIu64
                ",%" PRIu64 "] tracked=%" PRIu64
                " decision=disabled\n",
                site->site_pc, site->sample_count, site->candidate_count,
                sorted[0].count, sorted[1].count, sorted[2].count, tracked);
#endif
        site->state = HYPER_SITE_DISABLED;
        site->target_count = 0;
        memset(site->targets, 0, sizeof(site->targets));
        site->feedback_candidate_count = 0;
        memset(site->feedback_candidates, 0,
               sizeof(site->feedback_candidates));
        if (site->relearn_count) {
            hyper_note_phase_failure(site);
        }
        return;
    }

    /* A short relearn window can alias a periodic tail burst.  Preserve every
     * target seen by the preceding bounded feedback probe as membership-only
     * evidence, but rank primarily with the exact recent-window counts. */
    if (site->relearn_count) {
        for (unsigned i = 0; i < site->feedback_candidate_count; i++) {
            target_ulong target = site->feedback_candidates[i].target;

            if (hyper_target_index(sorted, sorted_count, target) < 0 &&
                sorted_count < ARRAY_SIZE(sorted)) {
                sorted[sorted_count].target = target;
                sorted[sorted_count].count = 1;
                sorted_count++;
            }
        }
        qsort(sorted, sorted_count, sizeof(sorted[0]), hyper_target_cmp);

        /* Do not reorder on a narrow sample tie.  A competing target must
         * beat the previous head by a clear margin; a true phase replacement
         * that excludes the old head still promotes immediately. */
        int old_index = hyper_target_index(sorted, sorted_count, old_head);

        if (old_index > 0 &&
            sorted[0].count <
                sorted[old_index].count + INDIRECT_HYPER_REORDER_HYSTERESIS) {
            HyperTarget tmp = sorted[0];

            sorted[0] = sorted[old_index];
            sorted[old_index] = tmp;
        }
    }

    count = MIN(sorted_count, (unsigned)INDIRECT_HYPER_ACTIVE_TARGETS);
    for (unsigned i = 0; i < count; i++) {
        plan[i] = sorted[i];
    }
    same = hyper_same_plan(site, plan, count);
    memset(site->targets, 0, sizeof(site->targets));
    memcpy(site->targets, plan, count * sizeof(plan[0]));
    site->target_count = count;
    site->state = HYPER_SITE_LINKED;
    if (!site->has_linked) {
        hyper_global_admitted_sites++;
    }
    site->has_linked = true;
    site->tail_probe = count > 1 &&
                       site->relearn_count < INDIRECT_HYPER_MAX_RELEARNS;
    site->feedback_events = 0;
    site->feedback_candidate_count = 0;
    memset(site->feedback_candidates, 0,
           sizeof(site->feedback_candidates));
    if (same && site->relearn_count < INDIRECT_HYPER_MAX_RELEARNS) {
        site->feedback_limit = MIN(site->feedback_limit * 4,
                                   (uint64_t)INDIRECT_HYPER_RELEARN_MAX);
    } else {
        site->feedback_limit = INDIRECT_HYPER_RELEARN_BASE;
    }
#if defined(CONFIG_RFICH_DEBUG)
    fprintf(stderr,
            "RFICH-DEBUG epoch site=0x%" PRIx64
            " samples=%u distinct=%u top=[%" PRIu64 ",%" PRIu64
            ",%" PRIu64 "] tracked=%" PRIu64
            " decision=linked same=%d limit=%" PRIu64 "\n",
            site->site_pc, site->sample_count, site->candidate_count,
            sorted[0].count, sorted[1].count, sorted[2].count, tracked, same,
            site->feedback_limit);
#endif
}

static bool hyper_begin_relearn(HyperSite *site)
{
    if (site->state != HYPER_SITE_LINKED ||
        site->feedback_events < site->feedback_limit) {
        return false;
    }

    if (site->relearn_count >= INDIRECT_HYPER_MAX_RELEARNS) {
        site->state = HYPER_SITE_DISABLED;
        site->target_count = 0;
        memset(site->targets, 0, sizeof(site->targets));
        hyper_note_phase_failure(site);
#if defined(CONFIG_RFICH_DEBUG)
        fprintf(stderr,
                "RFICH-DEBUG relearn-limit site=0x%" PRIx64
                " relearns=%" PRIu64 " decision=disabled\n",
                site->site_pc, site->relearn_count);
#endif
    } else {
        site->state = HYPER_SITE_OBSERVE;
        site->relearn_count++;
        hyper_reset_epoch(site);
    }
    return true;
}

IndirectHyperPlan indirect_hyperchain_get_plan(uint64_t site_pc,
                                               uint32_t type,
                                               target_ulong targets[],
                                               unsigned *count)
{
    HyperSite *site;
    IndirectHyperPlan plan;

    *count = 0;
    if (type != INDIRECT_HYPER_CALL) {
        return INDIRECT_HYPER_DISABLED;
    }
    indirect_hyperchain_init();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    if (hyper_global_disabled) {
        plan = INDIRECT_HYPER_DISABLED;
        goto out;
    }
    switch (site->state) {
    case HYPER_SITE_DISABLED:
        plan = INDIRECT_HYPER_DISABLED;
        break;
    case HYPER_SITE_OBSERVE:
        plan = INDIRECT_HYPER_OBSERVE;
        break;
    case HYPER_SITE_LINKED:
        for (unsigned i = 0; i < site->target_count; i++) {
            targets[i] = site->targets[i].target;
        }
        *count = site->target_count;
        plan = *count ? (site->tail_probe ?
                         INDIRECT_HYPER_LINKED_FEEDBACK :
                         INDIRECT_HYPER_LINKED) :
                        INDIRECT_HYPER_OBSERVE;
        break;
    default:
        g_assert_not_reached();
    }

out:
#if defined(CONFIG_RFICH_DEBUG)
    fprintf(stderr,
            "RFICH-DEBUG plan site=0x%" PRIx64
            " type=%u plan=%u targets=%u feedback=%" PRIu64
            "/%" PRIu64 "\n",
            site_pc, type, plan, *count, site->feedback_events,
            site->feedback_limit);
#endif
    qemu_mutex_unlock(&hyper_lock);
    return plan;
}

static void hyper_request_retranslation(CPUState *cpu, uint64_t site_pc)
{
    tb_invalidate_phys_addr(site_pc);
    cpu_loop_exit_noexc(cpu);
}

void indirect_hyperchain_record(CPUState *cpu, uint64_t site_pc,
                                target_ulong target, uint32_t type)
{
    HyperSite *site;
    bool retranslate = false;
    bool global_was_disabled;
    bool circuit_tripped;
    target_ulong *invalidate_sites = NULL;
    unsigned invalidate_count = 0;

    if (type != INDIRECT_HYPER_CALL) {
        return;
    }
    indirect_hyperchain_init();
    qemu_mutex_lock(&hyper_lock);
    global_was_disabled = hyper_global_disabled;
    site = find_or_create_site(site_pc, type);
    if (hyper_global_disabled) {
        site->state = HYPER_SITE_DISABLED;
        site->target_count = 0;
        qemu_mutex_unlock(&hyper_lock);
        /* This call can only come from stale observe code.  Retire that
         * source lazily instead of eagerly retranslating every cold site when
         * the process-level circuit breaker trips. */
        hyper_request_retranslation(cpu, site_pc);
    }
    if (site->state == HYPER_SITE_DISABLED) {
        qemu_mutex_unlock(&hyper_lock);
        return;
    }

    site->observations++;
    if (site->observations > 1 && site->last_target != target) {
        site->target_changes++;
    }
    site->last_target = target;

    if (site->state == HYPER_SITE_OBSERVE) {
        unsigned epoch_limit = site->relearn_count ?
            INDIRECT_HYPER_RELEARN_SAMPLES :
            INDIRECT_HYPER_LEARN_THRESHOLD;
        unsigned required_tracked =
            (epoch_limit * INDIRECT_HYPER_MIN_TRACKED_PERCENT + 99) / 100;
        unsigned allowed_outliers = epoch_limit - required_tracked;

        hyper_record_candidate(site, target);
        site->sample_count++;
        /* Each distinct target outside the tracked Top-N contributes at
         * least one irrevocable outlier.  Once that lower bound exceeds the
         * epoch's coverage budget, no continuation of this exact window can
         * pass, so stop paying observation-helper cost immediately. */
        if (site->candidate_count >
            INDIRECT_HYPER_TRACKED_TARGETS + allowed_outliers) {
            site->state = HYPER_SITE_DISABLED;
            site->target_count = 0;
            memset(site->targets, 0, sizeof(site->targets));
            retranslate = true;
#if defined(CONFIG_RFICH_DEBUG)
            fprintf(stderr,
                    "RFICH-DEBUG early-disable site=0x%" PRIx64
                    " samples=%u distinct=%u max-distinct=%u\n",
                    site->site_pc, site->sample_count,
                    site->candidate_count,
                    INDIRECT_HYPER_TRACKED_TARGETS + allowed_outliers);
#endif
        } else if (site->sample_count >=
                   (site->relearn_count ?
                    INDIRECT_HYPER_RELEARN_SAMPLES :
                    INDIRECT_HYPER_MIN_LEARN_SAMPLES)) {
            uint64_t tracked = 0;
            HyperTarget ranked[INDIRECT_HYPER_CANDIDATE_CAPACITY];
            unsigned n;

            memcpy(ranked, site->candidates, sizeof(ranked));
            qsort(ranked, site->candidate_count, sizeof(ranked[0]),
                  hyper_target_cmp);
            n = MIN(site->candidate_count,
                    (unsigned)INDIRECT_HYPER_TRACKED_TARGETS);
            for (unsigned i = 0; i < n; i++) {
                tracked += ranked[i].count;
            }
            /* Finish as soon as an exact prefix establishes the requested
             * Top-N coverage.  Ambiguous prefixes keep sampling, up to the
             * bounded maximum, so late dominant targets can still displace
             * early one-off targets. */
            if (tracked * 100 >=
                    (uint64_t)site->sample_count *
                    INDIRECT_HYPER_MIN_TRACKED_PERCENT ||
                site->sample_count >= epoch_limit) {
                hyper_finish_epoch(site);
                retranslate = true;
            }
        }
    } else {
        /* This path is used only for a linked site that could not own the
         * current TB descriptor.  Treat it as non-head feedback. */
        int index = hyper_target_index(site->targets, site->target_count,
                                       target);

        if (index < 0 &&
            site->target_count < INDIRECT_HYPER_ACTIVE_TARGETS) {
            if (site->relearn_count >= INDIRECT_HYPER_MAX_RELEARNS) {
                /* A target disappeared during the bounded relearn and then
                 * returned.  That is direct evidence of recurring phases,
                 * not spare stable capacity.  Stop after the one adaptation
                 * instead of retaining a permanently misordered union. */
                site->state = HYPER_SITE_DISABLED;
                site->target_count = 0;
                memset(site->targets, 0, sizeof(site->targets));
                hyper_note_phase_failure(site);
                retranslate = true;
            } else {
                /* The initial exact epoch may observe fewer than Top-N
                 * distinct targets.  Fill unused startup capacity once. */
                unsigned slot = site->target_count++;

                site->targets[slot].target = target;
                site->targets[slot].count = 1;
                site->tail_probe = site->target_count > 1;
                retranslate = true;
            }
        } else {
            if (index < 0) {
                site->linked_fallback_executions++;
                site->untracked_executions++;
            } else if (index > 0) {
                site->tail_feedback_executions++;
            }
            if (index != 0) {
                hyper_record_feedback_candidate(site, target);
                site->feedback_events++;
                retranslate = hyper_begin_relearn(site);
            }
        }
    }

    if (retranslate) {
        site->retranslation_count++;
    }
    circuit_tripped = !global_was_disabled && hyper_global_disabled;
    if (circuit_tripped) {
        invalidate_sites = hyper_disable_all_sites(&invalidate_count);
    }
#if defined(CONFIG_RFICH_DEBUG)
    fprintf(stderr,
            "RFICH-DEBUG record site=0x%" PRIx64
            " target=0x" TARGET_FMT_lx " observations=%" PRIu64
            " state=%u retranslate=%d\n",
            site_pc, target, site->observations, site->state, retranslate);
#endif
    qemu_mutex_unlock(&hyper_lock);

    if (circuit_tripped) {
        for (unsigned i = 0; i < invalidate_count; i++) {
            tb_invalidate_phys_addr(invalidate_sites[i]);
        }
        g_free(invalidate_sites);
        cpu_loop_exit_noexc(cpu);
    } else if (retranslate) {
        hyper_request_retranslation(cpu, site_pc);
    }
}

void indirect_hyperchain_feedback(CPUState *cpu, uint64_t site_pc,
                                  target_ulong target, uint32_t type)
{
    HyperSite *site;
    bool retranslate = false;
    bool global_was_disabled;
    bool circuit_tripped;
    target_ulong *invalidate_sites = NULL;
    unsigned invalidate_count = 0;
    int index;

    if (type != INDIRECT_HYPER_CALL) {
        return;
    }
    indirect_hyperchain_init();
    qemu_mutex_lock(&hyper_lock);
    global_was_disabled = hyper_global_disabled;
    site = find_or_create_site(site_pc, type);
    if (hyper_global_disabled) {
        site->state = HYPER_SITE_DISABLED;
        site->target_count = 0;
        qemu_mutex_unlock(&hyper_lock);
        hyper_request_retranslation(cpu, site_pc);
    }
    if (site->state != HYPER_SITE_LINKED) {
        qemu_mutex_unlock(&hyper_lock);
        return;
    }

    index = hyper_target_index(site->targets, site->target_count, target);
    if (index == 0) {
        /* A not-yet-patched head slot may temporarily fall through. */
        qemu_mutex_unlock(&hyper_lock);
        return;
    }

    site->observations++;
    if (site->observations > 1 && site->last_target != target) {
        site->target_changes++;
    }
    site->last_target = target;
    hyper_record_feedback_candidate(site, target);
    site->feedback_events++;
    if (index > 0) {
        site->tail_feedback_executions++;
    } else {
        site->linked_fallback_executions++;
        site->untracked_executions++;
    }

    retranslate = hyper_begin_relearn(site);
    if (retranslate) {
        site->retranslation_count++;
    }
    circuit_tripped = !global_was_disabled && hyper_global_disabled;
    if (circuit_tripped) {
        invalidate_sites = hyper_disable_all_sites(&invalidate_count);
    }
#if defined(CONFIG_RFICH_DEBUG)
    fprintf(stderr,
            "RFICH-DEBUG feedback site=0x%" PRIx64
            " target=0x" TARGET_FMT_lx " index=%d feedback=%" PRIu64
            "/%" PRIu64 " retranslate=%d\n",
            site_pc, target, index, site->feedback_events,
            site->feedback_limit, retranslate);
#endif
    qemu_mutex_unlock(&hyper_lock);

    if (circuit_tripped) {
        for (unsigned i = 0; i < invalidate_count; i++) {
            tb_invalidate_phys_addr(invalidate_sites[i]);
        }
        g_free(invalidate_sites);
        cpu_loop_exit_noexc(cpu);
    } else if (retranslate) {
        hyper_request_retranslation(cpu, site_pc);
    }
}

#if defined(CONFIG_RFICH_LOG)
void rfich_log_linked_attempt(uint64_t site_pc, uint32_t type)
{
    HyperSite *site;

    indirect_hyperchain_init();
    qemu_mutex_lock(&hyper_lock);
    site = find_or_create_site(site_pc, type);
    site->linked_attempts++;
    qemu_mutex_unlock(&hyper_lock);
}

void rfich_log_patch_attempt(void)
{
    qatomic_inc(&rfich_patch_log.attempts);
}

void rfich_log_patch_success(void)
{
    qatomic_inc(&rfich_patch_log.successes);
}

void rfich_log_patch_skip(void)
{
    qatomic_inc(&rfich_patch_log.skips);
}

void rfich_log_patch_reset(void)
{
    qatomic_inc(&rfich_patch_log.resets);
}

void rfich_log_dump(void)
{
    uint64_t sites = 0;
    uint64_t linked_sites = 0;
    uint64_t disabled_sites = 0;
    uint64_t observations = 0;
    uint64_t target_changes = 0;
    uint64_t untracked = 0;
    uint64_t linked_attempts = 0;
    uint64_t fallbacks = 0;
    uint64_t tail_feedback = 0;
    uint64_t retranslations = 0;
    uint64_t relearns = 0;

    indirect_hyperchain_init();
    qemu_mutex_lock(&hyper_lock);
    for (unsigned bucket = 0; bucket < INDIRECT_HYPER_BUCKETS; bucket++) {
        for (HyperSite *site = site_buckets[bucket]; site; site = site->next) {
            sites++;
            linked_sites += site->state == HYPER_SITE_LINKED;
            disabled_sites += site->state == HYPER_SITE_DISABLED;
            observations += site->observations;
            target_changes += site->target_changes;
            untracked += site->untracked_executions;
            linked_attempts += site->linked_attempts;
            fallbacks += site->linked_fallback_executions;
            tail_feedback += site->tail_feedback_executions;
            retranslations += site->retranslation_count;
            relearns += site->relearn_count;
        }
    }
    qemu_mutex_unlock(&hyper_lock);

    fprintf(stderr,
            "\n=== RFICH Log ===\n"
            "[sites]\n"
            "  total              : %" PRIu64 "\n"
            "  linked             : %" PRIu64 "\n"
            "  disabled           : %" PRIu64 "\n"
            "  observing          : %" PRIu64 "\n"
            "[runtime feedback]\n"
            "  observations       : %" PRIu64 "\n"
            "  target changes     : %" PRIu64 "\n"
            "  untracked targets  : %" PRIu64 "\n"
            "  tail feedback      : %" PRIu64 "\n"
            "  relearns           : %" PRIu64 "\n"
            "  retranslations     : %" PRIu64 "\n"
            "[linked execution]\n"
            "  attempts           : %" PRIu64 "\n"
            "  unobserved direct  : %" PRIu64 "\n"
            "  non-head events    : %" PRIu64 "\n"
            "  fallbacks          : %" PRIu64 "\n"
            "[patch]\n"
            "  attempts           : %" PRIu64 "\n"
            "  successes          : %" PRIu64 "\n"
            "  skips              : %" PRIu64 "\n"
            "  resets             : %" PRIu64 "\n"
            "=================\n",
            sites, linked_sites, disabled_sites,
            sites - linked_sites - disabled_sites,
            observations, target_changes, untracked, tail_feedback,
            relearns, retranslations, linked_attempts,
            linked_attempts >= tail_feedback + fallbacks
                ? linked_attempts - tail_feedback - fallbacks : 0,
            tail_feedback + fallbacks, fallbacks,
            qatomic_read(&rfich_patch_log.attempts),
            qatomic_read(&rfich_patch_log.successes),
            qatomic_read(&rfich_patch_log.skips),
            qatomic_read(&rfich_patch_log.resets));
    fflush(stderr);
}
#endif
