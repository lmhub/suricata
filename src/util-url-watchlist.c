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
 * Implementation for URL watchlist
 */

#include "util-url-watchlist.h"

URLWatchListCtx* g_url_watchlist_ctx = NULL;

static int AddURLToWatchList(const char* url, URLWatchListData* data);


/**
 *  \brief Create global URL watch list context
 *
 *  \retval 1 error
 *  \retval 0 success
 */
int CreateURLWatchListCtx()
{
SCLogInfo("PJG: Create URL context invoked.");
    if (g_url_watchlist_ctx == NULL) {
        g_url_watchlist_ctx = (URLWatchListCtx *) SCMalloc(sizeof(URLWatchListCtx));
        if (unlikely(g_url_watchlist_ctx == NULL))
            goto error;

        memset(g_url_watchlist_ctx, 0, sizeof(URLWatchListCtx));

        // Initialize URL Watchlist module
        g_url_watchlist_ctx->url_watch_list_tree = SCRadixCreateRadixTree(
                SCURLWatchListFreeData, NULL);
        if (g_url_watchlist_ctx->url_watch_list_tree == NULL) {
            SCLogDebug("Error initializing STIX URL Watchlist.");
            return 1;
        }
        if (SCMutexInit(&g_url_watchlist_ctx->url_watch_list_lock, NULL) != 0) {
            SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
            exit(EXIT_FAILURE);
        }
        SCLogDebug("STIX URL Watchlist module initialized");
SCLogInfo("PJG: Create URL context initialized.");        
    }
    return 0;

error:
    SCFree(g_url_watchlist_ctx);
    g_url_watchlist_ctx = NULL;

    return 1;
}


/**
 *  \brief Free global URL watch list context
 */
int CreateURLWatchListCtxFree()
{
SCLogInfo("PJG: Create URL context Free invoked.");
    SCRadixReleaseRadixTree(g_url_watchlist_ctx->url_watch_list_tree);
    SCMutexDestroy(&g_url_watchlist_ctx->url_watch_list_lock);
    SCFree(g_url_watchlist_ctx);
    g_url_watchlist_ctx = NULL;
    SCLogInfo("PJG: Create URL context Free complete.");
    return 1;
}


/**
 *  \brief Adds an array of URLs to the URL watch list
 *
 *  \param msg The indicator title copy from the Taxii message
 *  \param urls The array of URLs to be added to the watch list
 *  \param len The number of URLs to be added to the watchlist
 *
 *  \retval 1 error
 *  \retval 0 success
 */
int AddURLsToWatchList(char* msg, char* urls[], int len)
{
SCLogInfo("PJG: Add URLs to watch list invoked.");
    URLWatchListData * data = SCMalloc(sizeof(URLWatchListData));
    if (unlikely(data == NULL))
        return 1;
    memset(data, 0, sizeof(URLWatchListData));
    data->msg = msg;
    for (int i = 0; i < len; i++) {
SCLogInfo("PJG: Add URL to watch list: %s", urls[i]);
        AddURLToWatchList(urls[i], data);
    }
    return 0;
}


/**
 *  \brief Adds an individual URL to the URL watch list
 *
 *  \param url The URL to be added to the watch list
 *  \param data URL Watch list data struct
 */
static int AddURLToWatchList(const char* url, URLWatchListData* data)
{
SCLogInfo("PJG: Add URL to watch list invoked.");
    int return_val = 0;
    if (g_url_watchlist_ctx == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "STIX Add to URL Watch List was called when Context was Null.");
        return 0;
    }
    SCMutex *mutex;

    SCLogDebug("STIX URL Watch List adding url %s", url);
    mutex = &g_url_watchlist_ctx->url_watch_list_lock;

    SCMutexLock(mutex);
    void *user_data = NULL;
SCLogInfo("PJG: Find URL...");
    (void)SCRadixFindKeyURLExactMatch(url,
            g_url_watchlist_ctx->url_watch_list_tree, &user_data);
    if (user_data == NULL) {
        data->ref_count++;
SCLogInfo("PJG: Add URL string...");
        if (SCRadixAddKeyURLString(url,
                g_url_watchlist_ctx->url_watch_list_tree, data) == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE, 
                    "STIX failed to add URL %s, ignoring", url);
            return_val = 1;
        }
    }

    SCMutexUnlock(mutex);
SCLogInfo("PJG: URL add complete");
    return return_val;
}


/**
 *  \brief Free URL watch list data struct
 *
 *  \param user URL Watch list data struct
 */
void SCURLWatchListFreeData(void * user)
{
SCLogInfo("PJG: SCURLWatchListFreeData invoked.");
    URLWatchListData * data = (URLWatchListData *) user;
    data->ref_count--;
    if (data->ref_count == 0) {
        data->msg = NULL;
    } else if (unlikely(data->ref_count < 0 && data->msg != NULL)) {
        SCLogDebug(SC_ERR_INVALID_VALUE,
                "Freeing STIX URL Watch List ref count of %i with non NULL msg",
                data->ref_count);
        data->msg = NULL;
        data->ref_count = 0;
    } else if (unlikely(data->ref_count < 0 && data->msg == NULL)) {
        SCLogDebug(SC_ERR_INVALID_VALUE,
                "Freeing STIX URL Watch List ref count of %i with NULL msg",
                data->ref_count);
        data->ref_count = 0;
    }
}


/**
 *  \brief Adds an individual URL to the URL watch list
 *
 *  \param url The URL to be added to the watch list
 *  \param data URL Watch list data struct
 */
char* InitURLWatchDataFully(char* msg_header, URLWatchListData* data)
{
    if (!data->inited) {

        if (msg_header != NULL) {
            int header_len = strlen(msg_header);
            int data_len = strlen(data->msg);
            int size = header_len + data_len + 2 + 1;
            char *msg;
            msg = SCMalloc(sizeof(char) * size);
            if (unlikely(msg == NULL))
                return NULL;
            memset(msg, 0, sizeof(char) * size);
            memcpy(msg, msg_header, header_len);
            memcpy(msg+header_len, "(", 1);
            memcpy(msg+header_len+1, data->msg, data_len);
            memcpy(msg+header_len+1+data_len, ")", 2); // 2 is For ')' and null terminator
            data->msg = msg;
            SCFree(msg);
        }

        data->inited = 1;
    }
    return data->msg;
}


char* IsURLWatched(char* url, char* msg_header)
{
SCLogInfo("PJG: IsURLWatched: invoked.");
SCLogInfo("PJG: IsURLWatched: url: %s", url);
    void *user_data = NULL;
    (void)SCRadixFindKeyURLBestMatch(url,
            g_url_watchlist_ctx->url_watch_list_tree, &user_data);
    if (user_data != NULL) {
        return InitURLWatchDataFully(msg_header, user_data);
    }
    break;
    
    return NULL;
}


#ifdef UNITTESTS
int AddToURLWatchListTest01(void)
{
    int result = 1;
    CreateURLWatchListCtx();

    char* urls[3];
    urls[0] = "http://www.google.com";
    urls[1] = "http://www.yahoo.com";
    urls[2] = "http://www.example.org/wiki/Main_Page";

    if (AddURLsToWatchList("Test URL Watch List", urls, 3))
        result = 0;

    CreateURLWatchListCtxFree();
    return result;
}

int IsInURLWatchListTest01(void)
{
    int result = 1;
    CreateURLWatchListCtx();

    int size = 3;
    char* urls[size];
    urls[0] = "http://www.google.com";
    urls[1] = "http://www.yahoo.com";
    urls[2] = "http://www.example.org/wiki/Main_Page";

    if (AddURLsToWatchList("Test URL Watch List", urls, 3))
        result = 0;

    int i=0;
    for (i=0; i<size; i++){
        if (IsURLWatched(urls[i], "Test Header") != NULL)
        {
            result = 1;
        }
        else
        {
            result = 0;
            goto end;
        }
    }

end:
    CreateURLWatchListCtxFree();

    return result;
}
#endif

void WatchListRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AddToURLWatchListTest01", AddToURLWatchListTest01, 1);
    UtRegisterTest("IsInURLWatchListTest01", IsInURLWatchListTest01, 1);
#endif
}
