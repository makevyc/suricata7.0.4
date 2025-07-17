/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "../suricata-common.h"

#include "../output-json-stats.h"

#include "../util-unittest.h"

static int OutputJsonStatsTest01(void)
{
    StatsRecord global_records[] = { { 0 }, { 0 } };
    StatsRecord thread_records[2];
    thread_records[0].name = "capture.kernel_packets";
    thread_records[0].short_name = "kernel_packets";
    thread_records[0].tm_name = "W#01-bond0.30";
    thread_records[0].value = 42;
    thread_records[1].name = "capture.kernel_drops";
    thread_records[1].short_name = "kernel_drops";
    thread_records[1].tm_name = "W#01-bond0.30";
    thread_records[1].value = 4711;

    StatsTable table = {
        .nstats = 2,
        .stats = &global_records[0],
        .ntstats = 1,
        .tstats = &thread_records[0],
    };

    json_t *r = StatsToJSON(&table, JSON_STATS_TOTALS | JSON_STATS_THREADS);
    if (!r)
        return 0;

    // Remove variable content
    json_object_del(r, "uptime");

    char *serialized = json_dumps(r, 0);

    // Cheesy comparison
    const char *expected = "{\"threads\": {\"W#01-bond0.30\": {\"capture\": {\"kernel_packets\": "
                           "42, \"kernel_drops\": 4711}}}}";

    int cmp_result = strcmp(expected, serialized);
    if (cmp_result != 0)
        printf("unexpected result\nexpected=%s\ngot=%s\n", expected, serialized);

    free(serialized);
    json_decref(r);

    return cmp_result == 0;
}

void OutputJsonStatsRegisterTests(void)
{
    UtRegisterTest("OutputJsonStatsTest01", OutputJsonStatsTest01);
}
