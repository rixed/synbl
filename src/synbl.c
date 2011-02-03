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
#include <junkie/cpp.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/cli.h>

static unsigned opt_max_syn   = 1;
static unsigned opt_period    = 1;
static unsigned opt_probation = 5 * 60;

static struct cli_opt options[] = {
    { { "max-syn",   NULL }, true, "blacklist if the number of SYN per sampling period exceeds this", CLI_SET_UINT, { .uint = &opt_max_syn } },
    { { "period",    NULL }, true, "Duration (in seconds) of the sampling period",                    CLI_SET_UINT, { .uint = &opt_period } },
    { { "probation", NULL }, true, "Duration (in seconds) of the blacklist",                          CLI_SET_UINT, { .uint = &opt_probation } },
};

void on_load(void)
{
	SLOG(LOG_DEBUG, "Loading synbl");

    (void)cli_register("synbl", options, NB_ELEMS(options));
}

void on_unload(void)
{
	SLOG(LOG_DEBUG, "Unloading synbl");

    (void)cli_unregister(options);
}
