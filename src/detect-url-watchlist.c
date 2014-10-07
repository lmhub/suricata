/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
 
/**
 * \file
 *
 * \author Paul Gofran <paul.gofran@lmco.com>
 *
 * Detection for URL watchlist
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "util-spm.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "detect-url-watchlist.h"

#include "util-debug.h"
#include "util-radix-tree.h"

#include "util-url-watchlist.h"
#include "host.h"

#include "util-unittest.h"

int DetectURLWatchListMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectURLWatchlistSetup(DetectEngineCtx *, Signature *, char *);

void DetectURLWatchListRegister(void)
{
    sigmatch_table[DETECT_STIX_URLWATCH].name = "stixurl";
    sigmatch_table[DETECT_STIX_URLWATCH].Match = DetectURLWatchListMatch;
    sigmatch_table[DETECT_STIX_URLWATCH].Setup = DetectURLWatchlistSetup;
    sigmatch_table[DETECT_STIX_URLWATCH].Free = NULL;
    sigmatch_table[DETECT_STIX_URLWATCH].RegisterTests = URLWatchListRegisterTests;
    sigmatch_table[DETECT_STIX_URLWATCH].flags |= SIGMATCH_URLONLY_COMPAT;
}

static int DetectURLWatchlistSetup(DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
SCLogInfo("PJG: detect URL setup invoked.");
    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    CreateURLWatchListCtx();
    sm->type = DETECT_STIX_URLWATCH;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
SCLogInfo("PJG: detect URL setup completed successfully.");

    return 0;
error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}


int DetectURLWatchListMatch(ThreadVars * tv, DetectEngineThreadCtx * de_ctx,
        Packet * p, Signature * s, SigMatch *sm)
{
SCLogInfo("PJG: URL watch list match invoked.");
    char* url = sigmatch_table[DETECT_STIX_IPWATCH].url;
SCLogInfo("PJG: url: %s", url);
    
    sl = IsURLWatched(url);
    if (sl != NULL) {
    SCLogInfo("PJG: url matched, return 1.");
        return 1;
    }
SCLogInfo("PJG: url did not match, return 0.");
    return 0;
}
