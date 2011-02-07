// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <junkie/cpp.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/cap.h>
#include <junkie/tools/cli.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ext.h>

static unsigned opt_max_syn   = 1;
static unsigned opt_period    = 1;
static unsigned opt_probation = 5 * 60;

EXT_PARAM_RW(opt_max_syn,   "max-syn",   uint, "blacklist if the number of SYN per sampling period exceeds this");
EXT_PARAM_RW(opt_period,    "period",    uint, "duration (in seconds) of the sampling period");
EXT_PARAM_RW(opt_probation, "probation", uint, "duration (in seconds) of the blacklist");

static struct cli_opt options[] = {
    { { "max-syn",   NULL }, true, "blacklist if the number of SYN per sampling period exceeds this", CLI_SET_UINT, { .uint = &opt_max_syn } },
    { { "period",    NULL }, true, "duration (in seconds) of the sampling period",                    CLI_SET_UINT, { .uint = &opt_period } },
    { { "probation", NULL }, true, "duration (in seconds) of the blacklist",                          CLI_SET_UINT, { .uint = &opt_probation } },
};

static struct mutex synbl_lock; // protects access to quit, syners and siners
static pthread_t clearer_pth, forgiver_pth;
static bool quit;

LOG_CATEGORY_DEF(synbl)
#undef LOG_CAT
#define LOG_CAT synbl_log_category

/*
 * A syner is a client IP and a target port, corresponding to a TCP SYN we have seen.
 */

struct syner {
    HASH_ENTRY(syner) entry;
    struct syner_key {
        struct ip_addr ip;
        uint16_t dport;
    } key;
    unsigned nb_syns;
};

static HASH_TABLE(syners, syner) syners;

static void syner_key_ctor(struct syner_key *key, struct ip_addr const *ip, uint16_t dport)
{
    memset(key, 0, sizeof(*key));
    key->ip = *ip;
    key->dport = dport;
}

static int syner_ctor(struct syner *syner, struct syner_key const *key)
{
    SLOG(LOG_DEBUG, "Constructing new syner@%p for %s, dport %"PRIu16, syner, ip_addr_2_str(&key->ip), key->dport);

    syner->key = *key;
    syner->nb_syns = 0;

    HASH_INSERT(&syners, syner, &syner->key, entry);

    return 0;
}

static struct syner *syner_new(struct syner_key const *key)
{
    PTHREAD_ASSERT_LOCK(&synbl_lock.mutex);

    MALLOCER(syners);
    struct syner *syner = MALLOC(syners, sizeof(*syner));
    if (! syner) return NULL;

    if (0 != syner_ctor(syner, key)) {
        FREE(syner);
        return NULL;
    }

    return syner;
}

static void syner_dtor(struct syner *syner)
{
    SLOG(LOG_DEBUG, "Destructing syner@%p", syner);

    HASH_REMOVE(&syners, syner, entry);
}

static void syner_del(struct syner *syner)
{
    PTHREAD_ASSERT_LOCK(&synbl_lock.mutex);
    syner_dtor(syner);
    FREE(syner);
}

static void syners_del_all(void)
{
    SLOG(LOG_DEBUG, "Deleting all syners");

    // Deletes every syners
    mutex_lock(&synbl_lock);
    struct syner *syner, *tmp;
    HASH_FOREACH_SAFE(syner, &syners, entry, tmp) {
        syner_del(syner);
    }
    mutex_unlock(&synbl_lock);
}

/*
 * A siner is a syner that have commited the sin of sending too much SYNs
 * and have been blacklisted.
 */

struct siner {
    TAILQ_ENTRY(siner) entry;   // entry in siners list
    struct syner_key key;
    struct timeval bl;
};

static TAILQ_HEAD(siners, siner) siners;    // sorted in least recently blacklisted first

static int siner_ctor(struct siner *siner, struct syner_key const *key)
{
    SLOG(LOG_DEBUG, "Constructing new siner@%p for %s, dport %"PRIu16, siner, ip_addr_2_str(&key->ip), key->dport);

    siner->key = *key;
    timeval_set_now(&siner->bl);
    TAILQ_INSERT_TAIL(&siners, siner, entry);

    return 0;
}

static struct siner *siner_new(struct syner_key const *key)
{
    PTHREAD_ASSERT_LOCK(&synbl_lock.mutex);

    MALLOCER(siners);
    struct siner *siner = MALLOC(siners, sizeof(*siner));
    if (! siner) return NULL;

    if (0 != siner_ctor(siner, key)) {
        FREE(siner);
        return NULL;
    }

    return siner;
}

static void siner_dtor(struct siner *siner)
{
    SLOG(LOG_DEBUG, "Destructing siner@%p", siner);

    TAILQ_REMOVE(&siners, siner, entry);
}

static void siner_del(struct siner *siner)
{
    PTHREAD_ASSERT_LOCK(&synbl_lock.mutex);
    siner_dtor(siner);
    FREE(siner);
}

static void siners_del_all(void)
{
    SLOG(LOG_DEBUG, "Deleting all siners");

    // Deletes every siners
    mutex_lock(&synbl_lock);
    struct siner *siner;
    while (NULL != (siner = TAILQ_FIRST(&siners))) {
        siner_del(siner);
        // Notice that blacklisted siners stay blacklisted
    }
    mutex_unlock(&synbl_lock);
}

/*
 * Packet callback
 */

static void *call_f(char const *func, struct syner_key *key)
{
    char const *ip = ip_addr_2_str(&key->ip);
    SLOG(LOG_DEBUG, "Calling %s for IP %s", func, ip);

    SCM synbl_module = scm_c_resolve_module("junkie synbl");
    SCM var = scm_c_module_lookup(synbl_module, func);
    SCM proc = scm_variable_ref(var);

    (void)scm_call_2(proc, scm_from_locale_string(ip), scm_from_uint16(key->dport));

    return (void *)1;
}

static void *ban(void *key_)
{
    return call_f("synbl-ban", key_);
}

static void *unban(void *key_)
{
    return call_f("synbl-unban", key_);
}

// This function is called once for each captured packet
int parse_callback(struct proto_info const *info, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    // We need tcp (a SYN), ip and capture infos to proceed (capture is needed for timestamp)
    ASSIGN_INFO_CHK(tcp, info, 0);
    if (! tcp->syn) return 0;
    ASSIGN_INFO_CHK2(ip, ip6, &tcp->info, 0);    // ip or ip6 is OK
    if (! ip) ip = ip6;                         // but from now on, we use "ip"
    ASSIGN_INFO_CHK(cap, &ip->info, 0);

    // So we have a syner. Look it up this syners hash
    struct syner_key key;
    syner_key_ctor(&key, ip->key.addr+0, tcp->key.port[1]);

    mutex_lock(&synbl_lock);
    struct syner *syner;
    HASH_LOOKUP(syner, &syners, &key, key, entry);
    if (! syner) syner = syner_new(&key);
    mutex_unlock(&synbl_lock);

    if (! syner) return 0;

    EXT_LOCK(opt_max_syn);
    unsigned const max_syn = opt_max_syn;
    EXT_UNLOCK(opt_max_syn);

    if (++ syner->nb_syns > max_syn) {
        scm_with_guile(ban, &syner->key);
        mutex_lock(&synbl_lock);
        (void)siner_new(&syner->key);
        syner_del(syner);   // Avoid retrigering the blacklisting at next SYN (just in case blacklisting will not be effective enough)
        mutex_unlock(&synbl_lock);
    }

    return 0;
}

/*
 * Clearer thread
 * this thread clears all syners that survived a sampling period
 */

static void *clearer_thread(void unused_ *dummy)
{
    set_thread_name("J-synbl-clearer");

    while (! quit) {
        EXT_LOCK(opt_period);
        unsigned const period = opt_period;
        EXT_UNLOCK(opt_period);
        sleep(period);
        syners_del_all();
    }

    return NULL;
}

/*
 * Forgiver thread
 * this thread removes clients from blacklist once their probation period has expired
 */

static void *forgiver_thread(void unused_ *dummy)
{
    set_thread_name("J-synbl-forgiver");

    while (! quit) {
        EXT_LOCK(opt_probation);
        int_least64_t const probation = opt_probation * 1000000LL;
        EXT_UNLOCK(opt_probation);

        struct timeval now;
        timeval_set_now(&now);

        mutex_lock(&synbl_lock);
        struct siner *siner;
        while (NULL != (siner = TAILQ_FIRST(&siners))) {
            int64_t const age = timeval_sub(&now, &siner->bl);
            if (age < probation) break;
            SLOG(LOG_DEBUG, "Probation of %"PRIdLEAST64"us expired for %s", probation, ip_addr_2_str(&siner->key.ip));
            scm_with_guile(unban, &siner->key);
            siner_del(siner);
        }
        mutex_unlock(&synbl_lock);

        sleep(1);
    }

    return NULL;
}

/*
 * Init
 */

void on_load(void)
{
    log_category_synbl_init();
    SLOG(LOG_DEBUG, "Loading synbl");

    ext_param_opt_max_syn_init();
    ext_param_opt_period_init();
    ext_param_opt_probation_init();

    mutex_ctor(&synbl_lock, "synbl");

    (void)cli_register("synbl", options, NB_ELEMS(options));

    HASH_INIT(&syners, 1000, "syners");
    TAILQ_INIT(&siners);

    if (0 != pthread_create(&clearer_pth, NULL, clearer_thread, NULL)) {
        SLOG(LOG_ERR, "Cannot start clearer thread");
        // I'd rather like to return an error code in this situation
    }
    if (0 != pthread_create(&forgiver_pth, NULL, forgiver_thread, NULL)) {
        SLOG(LOG_ERR, "Cannot start forgiver thread");
    }
}

void on_unload(void)
{
    SLOG(LOG_DEBUG, "Unloading synbl");

    mutex_lock(&synbl_lock);
    quit = true;
    mutex_unlock(&synbl_lock);
    (void)pthread_join(clearer_pth, NULL);
    (void)pthread_join(forgiver_pth, NULL);

    siners_del_all();
    syners_del_all();
    HASH_DEINIT(&syners);

    (void)cli_unregister(options);

    mutex_dtor(&synbl_lock);

    ext_param_opt_probation_fini();
    ext_param_opt_period_fini();
    ext_param_opt_max_syn_fini();
    log_category_synbl_fini();
}
