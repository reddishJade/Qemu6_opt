/* Minimal RFICH policy: observe one bounded window, then freeze.
 *
 * The plan table is immutable after publication.  Translation reads it with
 * an RCU-style pointer walk and never takes the learning mutex.  A linked
 * compare miss falls through to QEMU's original indirect path; no RFICH
 * helper, feedback, allocation, or state transition runs on that miss.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/indirect-hyper.h"
#include "qemu/thread.h"

#define RFICH_BUCKETS 4096
#define RFICH_LEARN_SAMPLES 32
#define RFICH_CANDIDATE_CAPACITY 4
#define RFICH_ACTIVE_TARGETS 3
#define RFICH_MIN_COVERAGE 90

enum {
    RFICH_SITE_OBSERVE,
    RFICH_SITE_LINKED,
    RFICH_SITE_DISABLED,
};

typedef struct RFICHTarget {
    target_ulong pc;
    unsigned count;
} RFICHTarget;

typedef struct RFICHSite RFICHSite;
struct RFICHSite {
    uint64_t site_pc;
    RFICHSite *next;

    RFICHTarget candidates[RFICH_CANDIDATE_CAPACITY];
    unsigned candidate_count;
    unsigned sample_count;

    target_ulong targets[RFICH_ACTIVE_TARGETS];
    unsigned target_count;
    int state;

#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
    uint64_t observations;
    uint64_t retranslations;
    uint64_t linked_attempts;
    uint64_t linked_misses;
    uint64_t candidate_overflows;
    uint64_t coverage;
#endif
};

static RFICHSite *rfich_buckets[RFICH_BUCKETS];
static QemuMutex rfich_lock;
static gsize rfich_initialized;

#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
static uint64_t rfich_plan_lookups;
static uint64_t rfich_plan_observe;
static uint64_t rfich_plan_linked;
static uint64_t rfich_plan_disabled;
static uint64_t rfich_observe_calls;
static uint64_t rfich_retranslations;
static uint64_t rfich_linked_attempts;
static uint64_t rfich_linked_misses;
#endif

#if defined(CONFIG_RFICH_LOG)
static uint64_t rfich_patch_attempts;
static uint64_t rfich_patch_successes;
static uint64_t rfich_patch_skips;
static uint64_t rfich_patch_resets;
#endif

static unsigned rfich_hash(uint64_t site_pc)
{
    site_pc ^= site_pc >> 33;
    site_pc *= UINT64_C(0xff51afd7ed558ccd);
    site_pc ^= site_pc >> 33;
    return site_pc & (RFICH_BUCKETS - 1);
}

/* Sites are never freed.  Published bucket chains are safe to walk without
 * taking rfich_lock from translation. */
static RFICHSite *rfich_find(uint64_t site_pc)
{
    RFICHSite *site = qatomic_rcu_read(&rfich_buckets[rfich_hash(site_pc)]);

    while (site) {
        if (site->site_pc == site_pc) {
            return site;
        }
        site = qatomic_rcu_read(&site->next);
    }
    return NULL;
}

static RFICHSite *rfich_find_or_create(uint64_t site_pc)
{
    unsigned bucket = rfich_hash(site_pc);
    RFICHSite *site = rfich_find(site_pc);

    if (site) {
        return site;
    }

    site = g_new0(RFICHSite, 1);
    site->site_pc = site_pc;
    site->state = RFICH_SITE_OBSERVE;
    site->next = qatomic_read(&rfich_buckets[bucket]);
    qatomic_rcu_set(&rfich_buckets[bucket], site);
    return site;
}

static void rfich_atfork_prepare(void)
{
    qemu_mutex_lock(&rfich_lock);
}

static void rfich_atfork_parent(void)
{
    qemu_mutex_unlock(&rfich_lock);
}

static void rfich_atfork_child(void)
{
#if defined(CONFIG_RFICH_LOG)
    rfich_patch_attempts = 0;
    rfich_patch_successes = 0;
    rfich_patch_skips = 0;
    rfich_patch_resets = 0;
#endif
    qemu_mutex_unlock(&rfich_lock);
}

static void rfich_init(void)
{
    if (g_once_init_enter(&rfich_initialized)) {
        int ret;

        qemu_mutex_init(&rfich_lock);
        ret = pthread_atfork(rfich_atfork_prepare, rfich_atfork_parent,
                             rfich_atfork_child);
        g_assert(ret == 0);
        g_once_init_leave(&rfich_initialized, 1);
    }
}

static bool rfich_add_candidate(RFICHSite *site, target_ulong target)
{
    for (unsigned i = 0; i < site->candidate_count; i++) {
        if (site->candidates[i].pc == target) {
            site->candidates[i].count++;
            return true;
        }
    }
    if (site->candidate_count == RFICH_CANDIDATE_CAPACITY) {
        return false;
    }
    site->candidates[site->candidate_count++] =
        (RFICHTarget) { .pc = target, .count = 1 };
    return true;
}

static void rfich_publish_plan(RFICHSite *site)
{
    RFICHTarget ranked[RFICH_CANDIDATE_CAPACITY];
    unsigned active;
    uint64_t covered = 0;

    memcpy(ranked, site->candidates, sizeof(ranked));
    for (unsigned i = 0; i < site->candidate_count; i++) {
        unsigned best = i;

        for (unsigned j = i + 1; j < site->candidate_count; j++) {
            if (ranked[j].count > ranked[best].count) {
                best = j;
            }
        }
        if (best != i) {
            RFICHTarget tmp = ranked[i];
            ranked[i] = ranked[best];
            ranked[best] = tmp;
        }
    }

    active = MIN(site->candidate_count, (unsigned)RFICH_ACTIVE_TARGETS);
    for (unsigned i = 0; i < active; i++) {
        covered += ranked[i].count;
    }

    if (!active || covered * 100 <
                       (uint64_t)site->sample_count * RFICH_MIN_COVERAGE) {
        qatomic_store_release(&site->state, RFICH_SITE_DISABLED);
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
        site->coverage = site->sample_count ?
            covered * 100 / site->sample_count : 0;
#endif
        return;
    }

    for (unsigned i = 0; i < active; i++) {
        site->targets[i] = ranked[i].pc;
    }
    site->target_count = active;
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
    site->coverage = covered * 100 / site->sample_count;
#endif
    /* All plan fields are visible before the state becomes LINKED. */
    qatomic_store_release(&site->state, RFICH_SITE_LINKED);
}

IndirectHyperPlan indirect_hyperchain_get_plan(uint64_t site_pc,
                                               target_ulong targets[],
                                               unsigned *count)
{
    RFICHSite *site;
    int state;

    *count = 0;
    site = rfich_find(site_pc);
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
    qatomic_inc(&rfich_plan_lookups);
#endif
    if (!site) {
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
        qatomic_inc(&rfich_plan_observe);
#endif
        return INDIRECT_HYPER_OBSERVE;
    }

    state = qatomic_load_acquire(&site->state);
    if (state == RFICH_SITE_OBSERVE) {
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
        qatomic_inc(&rfich_plan_observe);
#endif
        return INDIRECT_HYPER_OBSERVE;
    }
    if (state == RFICH_SITE_DISABLED) {
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
        qatomic_inc(&rfich_plan_disabled);
#endif
        return INDIRECT_HYPER_DISABLED;
    }

    *count = site->target_count;
    memcpy(targets, site->targets, *count * sizeof(targets[0]));
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
    qatomic_inc(&rfich_plan_linked);
#endif
    return INDIRECT_HYPER_LINKED;
}

static void rfich_retranslate(CPUState *cpu, uint64_t site_pc)
{
    tb_invalidate_phys_addr(site_pc);
    cpu_loop_exit_noexc(cpu);
}

void indirect_hyperchain_record(CPUState *cpu, uint64_t site_pc,
                                target_ulong target)
{
    RFICHSite *site;
    bool retranslate = false;
    int state;

    rfich_init();
    qemu_mutex_lock(&rfich_lock);
    site = rfich_find_or_create(site_pc);
    state = qatomic_read(&site->state);

    if (state != RFICH_SITE_OBSERVE) {
        /* Retire an observe TB that was translated before the plan froze. */
        retranslate = true;
    } else {
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
        site->observations++;
        qatomic_inc(&rfich_observe_calls);
#endif
        if (!rfich_add_candidate(site, target)) {
            qatomic_store_release(&site->state, RFICH_SITE_DISABLED);
#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
            site->candidate_overflows++;
#endif
            retranslate = true;
        } else if (++site->sample_count == RFICH_LEARN_SAMPLES) {
            rfich_publish_plan(site);
            retranslate = true;
        }
    }

#if defined(CONFIG_RFICH_LOG) || defined(CONFIG_RFICH_DEBUG)
    if (retranslate) {
        site->retranslations++;
        qatomic_inc(&rfich_retranslations);
    }
#endif
#if defined(CONFIG_RFICH_DEBUG)
    fprintf(stderr,
            "RFICH-DEBUG observe site=0x%" PRIx64
            " state=%d samples=%u candidates=%u targets=%u coverage=%" PRIu64
            " retranslate=%d\n", site_pc, qatomic_read(&site->state),
            site->sample_count, site->candidate_count, site->target_count,
            site->coverage, retranslate);
#endif
    qemu_mutex_unlock(&rfich_lock);

    if (retranslate) {
        rfich_retranslate(cpu, site_pc);
    }
}

#if defined(CONFIG_RFICH_LOG)
void rfich_log_linked_attempt(uint64_t site_pc)
{
    RFICHSite *site;

    rfich_init();
    qemu_mutex_lock(&rfich_lock);
    site = rfich_find(site_pc);
    if (site) {
        site->linked_attempts++;
    }
    qatomic_inc(&rfich_linked_attempts);
    qemu_mutex_unlock(&rfich_lock);
}

void rfich_log_linked_miss(uint64_t site_pc)
{
    RFICHSite *site;

    rfich_init();
    qemu_mutex_lock(&rfich_lock);
    site = rfich_find(site_pc);
    if (site) {
        site->linked_misses++;
    }
    qatomic_inc(&rfich_linked_misses);
    qemu_mutex_unlock(&rfich_lock);
}

void rfich_log_patch_attempt(void) { qatomic_inc(&rfich_patch_attempts); }
void rfich_log_patch_success(void) { qatomic_inc(&rfich_patch_successes); }
void rfich_log_patch_skip(void) { qatomic_inc(&rfich_patch_skips); }
void rfich_log_patch_reset(void) { qatomic_inc(&rfich_patch_resets); }

void rfich_log_dump(void)
{
    uint64_t sites = 0;
    uint64_t observing = 0;
    uint64_t linked = 0;
    uint64_t disabled = 0;
    uint64_t observations = 0;
    uint64_t retranslations = 0;
    uint64_t overflows = 0;

    rfich_init();
    qemu_mutex_lock(&rfich_lock);
    for (unsigned i = 0; i < RFICH_BUCKETS; i++) {
        for (RFICHSite *site = rfich_buckets[i]; site;
             site = site->next) {
            int state = qatomic_load_acquire(&site->state);

            sites++;
            observing += state == RFICH_SITE_OBSERVE;
            linked += state == RFICH_SITE_LINKED;
            disabled += state == RFICH_SITE_DISABLED;
            observations += site->observations;
            retranslations += site->retranslations;
            overflows += site->candidate_overflows;
            fprintf(stderr,
                    "RFICH site=0x%" PRIx64 " state=%d samples=%u"
                    " candidates=%u targets=%u coverage=%" PRIu64
                    " observations=%" PRIu64 " retranslations=%" PRIu64
                    " linked_attempts=%" PRIu64 " linked_misses=%" PRIu64
                    " overflows=%" PRIu64 "\n",
                    site->site_pc, state, site->sample_count,
                    site->candidate_count, site->target_count, site->coverage,
                    site->observations, site->retranslations,
                    site->linked_attempts, site->linked_misses,
                    site->candidate_overflows);
        }
    }
    qemu_mutex_unlock(&rfich_lock);

    fprintf(stderr,
            "RFICH totals sites=%" PRIu64 " observing=%" PRIu64
            " linked=%" PRIu64 " disabled=%" PRIu64
            " plan_lookups=%" PRIu64 " plan_observe=%" PRIu64
            " plan_linked=%" PRIu64 " plan_disabled=%" PRIu64
            " observe_calls=%" PRIu64 " retranslations=%" PRIu64
            " linked_attempts=%" PRIu64 " linked_misses=%" PRIu64
            " linked_hits=%" PRIu64 " overflows=%" PRIu64 "\n"
            "RFICH patch attempts=%" PRIu64 " successes=%" PRIu64
            " skips=%" PRIu64 " resets=%" PRIu64 "\n",
            sites, observing, linked, disabled,
            qatomic_read(&rfich_plan_lookups),
            qatomic_read(&rfich_plan_observe), qatomic_read(&rfich_plan_linked),
            qatomic_read(&rfich_plan_disabled),
            qatomic_read(&rfich_observe_calls),
            qatomic_read(&rfich_retranslations),
            qatomic_read(&rfich_linked_attempts),
            qatomic_read(&rfich_linked_misses),
            qatomic_read(&rfich_linked_attempts) >=
                qatomic_read(&rfich_linked_misses) ?
                qatomic_read(&rfich_linked_attempts) -
                qatomic_read(&rfich_linked_misses) : 0,
            overflows,
            qatomic_read(&rfich_patch_attempts),
            qatomic_read(&rfich_patch_successes),
            qatomic_read(&rfich_patch_skips), qatomic_read(&rfich_patch_resets));
    fflush(stderr);
}
#endif
