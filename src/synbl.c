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

static int syner_ctor(struct syner *syner, struct ip_addr const *ip, uint16_t dport)
{
    SLOG(LOG_DEBUG, "Constructing new syner@%p for %s, dport %"PRIu16, syner, ip_addr_2_str(ip), dport);

    memset(syner.key, 0, sizeof(syner.key));    // because we will memcmp keys
    syner->key.ip = *ip;
    syner->key.dport = dport;

    HASH_INSERT(&syners, syner, &syner->key, entry);

    return 0;
}

static struct syner *syner_new(struct ip_addr const *ip, uint16_t dport)
{
    MALLOCER(syners);
    struct syner *syner = MALLOC(syners, sizeof(*syner));
    if (! syner) return NULL;

    if (0 != syner_ctor(syner, ip, dport)) {
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
