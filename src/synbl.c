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
#include <junkie/cpp.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/cap.h>
#include <junkie/tools/cli.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/tools/mallocer.h>

static unsigned opt_max_syn   = 1;
static unsigned opt_period    = 1;
static unsigned opt_probation = 5 * 60;

static struct cli_opt options[] = {
    { { "max-syn",   NULL }, true, "blacklist if the number of SYN per sampling period exceeds this", CLI_SET_UINT, { .uint = &opt_max_syn } },
    { { "period",    NULL }, true, "Duration (in seconds) of the sampling period",                    CLI_SET_UINT, { .uint = &opt_period } },
    { { "probation", NULL }, true, "Duration (in seconds) of the blacklist",                          CLI_SET_UINT, { .uint = &opt_probation } },
};

/*
 * A syner is a client IP and a target port, corresponding to a TCP SYN we have seen.
 */

struct syner {
    HASH_ENTRY(syner) entry;
    struct syner_key {
        struct ip_addr ip;
        uint16_t dport;
    } key;
    // ...
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
    HASH_INSERT(&syners, syner, &syner->key, entry);

    return 0;
}

static struct syner *syner_new(struct syner_key const *key)
{
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
    HASH_REMOVE(&syners, syner, entry);
}

static void syner_del(struct syner *syner)
{
    syner_dtor(syner);
    FREE(syner);
}

/*
 * Packet callback
 */

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

    struct syner *syner;
    HASH_LOOKUP(syner, &syners, &key, key, entry);

    if (! syner) {
        syner = syner_new(&key);
        if (! syner) return 0;
    }

    // Now do something with this syner
    // ...

    return 0;
}

/*
 * Init
 */

void on_load(void)
{
	SLOG(LOG_DEBUG, "Loading synbl");

    (void)cli_register("synbl", options, NB_ELEMS(options));

    HASH_INIT(&syners, 1000, "syners");
}

void on_unload(void)
{
	SLOG(LOG_DEBUG, "Unloading synbl");

    // Deletes every syners
    struct syner *syner, *tmp;
    HASH_FOREACH_SAFE(syner, &syners, entry, tmp) {
        syner_del(syner);
    }
    HASH_DEINIT(&syners);

    (void)cli_unregister(options);
}
