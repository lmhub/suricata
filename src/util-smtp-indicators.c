/* Copyright (C) 2013 Open Information Security Foundation
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

/**
 * \file
 *
 * \author David Cameron <dave@davesomebody.com>
 *
 * SMTP STIX Indicator
 */

#include "util-smtp-indicators.h"

static SMTPIndicatorsCtx *g_smtpindicators_ctx;

SMTPAddressIndicator *SMTPIndicatorCreateAddressIndicator(const uint8_t *value,
        enum SMTPIndicatorAddressValueCondition condition)
{
    if (value != NULL) {
        SMTPAddressIndicator *indicator = SCMalloc(sizeof(SMTPAddressIndicator));
        if (unlikely(indicator == NULL))
            return NULL;
        memset(indicator, 0, sizeof(SMTPAddressIndicator));

        indicator->value = SCMalloc(strlen((const char*) value) + 1);
        if (unlikely(indicator->value == NULL)) {
            SCFree(indicator);
            return NULL;
        }
        memcpy((char*) indicator->value, (const char*) value, strlen((const char*) value) + 1);

        indicator->condition = condition;

        return indicator;
    }

    return NULL;
}

int SMTPIndicatorDestroyAddressIndicator(SMTPAddressIndicator *indicator)
{
    if (indicator->value != NULL) {
        SCFree(indicator->value);
    }

    return 0;
}

SMTPIndicatorsFileObject * SMTPIndicatorCreateFileObject(
        const uint8_t *file_extension, uint8_t **hashes, int hash_count,
        uint16_t size_in_bytes, int use_size_in_bytes)
{
    SMTPIndicatorsFileObject *result = SCMalloc(sizeof(SMTPIndicatorsFileObject));
    if (unlikely(result == NULL))
        return NULL;
    memset(result, 0, sizeof(SMTPIndicatorsFileObject));
    if (file_extension != NULL) {
        result->file_extension = SCMalloc(strlen((const char*) file_extension) + 1);
        if (unlikely(result->file_extension == NULL)) {
            SCFree(result);
            return NULL;
        }
        memcpy((char*) (result->file_extension), (const char*) file_extension,
                strlen((const char*) file_extension) + 1);
        result->fields_used |= SMTP_FILE_OBJECT_FILE_EXTENSION;
    }

    if (hashes != NULL) {
        result->hashes = SCMalloc(sizeof(uint8_t*) * (hash_count + 1));
        if (unlikely(result->hashes == NULL)) {
            SCFree(result);
            return NULL;
        }
        int hash_idx = 0;

        // NUll terminated list of hashes
        while (hash_idx < hash_count) {
            result->hashes[hash_idx] = SCMalloc(
                    strlen((const char*) (hashes[hash_idx])) + 1);
            if (unlikely(result->hashes[hash_idx] == NULL)) {
                SCFree(result);
                return NULL;  
            }      
            memcpy((char*) (result->hashes[hash_idx]),
                    (const char*) (hashes[hash_idx]), strlen((const char*) (hashes[hash_idx])) + 1);
            hash_idx++;
        }
        result->hashes[hash_count] = NULL;

        result->fields_used |= SMTP_FILE_OBJECT_HASHES;
    }

    if (use_size_in_bytes) {
        result->size_in_bytes = size_in_bytes;
        result->fields_used |= SMTP_FILE_OBJECT_SIZE_IN_BYTES;
    }

    return result;
}

int SMTPIndicatorDestroyFileObject(SMTPIndicatorsFileObject *indicator)
{
    if (indicator->file_extension != NULL)
        SCFree(indicator->file_extension);
    if (indicator->hashes) {
        // NULL terminated array of pointers
        uint8_t **hash_ptr = indicator->hashes;
        while (*hash_ptr != NULL) {
            SCFree(*hash_ptr);
            hash_ptr++;
        }
    }

    return 0;
}


/**
 *  \brief Create SMTP indicator
 */
SMTPIndicator *SMTPIndicatorCreateIndicator(const uint8_t *name,
        SMTPAddressIndicator *from,
        SMTPIndicatorsFileObject *related_file_objects)
{
    if (name != NULL) {
        SMTPIndicator *result = SCMalloc(sizeof(SMTPIndicator));
        if (unlikely(result == NULL))
            return NULL; 
        memset(result, 0, sizeof(SMTPIndicator));

        result->name = SCMalloc(strlen((const char*) name) + 1);
        if (unlikely(result->name == NULL)) {
            SCFree(result);
            return NULL; 
        }
        memcpy((char*) result->name, (const char*) name, strlen((const char*) name) + 1);

        result->related_file_objects = related_file_objects;

        result->from = from;

        return result;
    }

    return NULL;
}


/**
 *  \brief Free SMTP indicator
 */
int SMTPIndicatorDestroyIndicator(SMTPIndicator *indicator)
{
    if (indicator->from != NULL) {
        SMTPIndicatorDestroyAddressIndicator(indicator->from);
    }

    if (indicator->name != NULL)
        SCFree(indicator->name);

    SMTPIndicatorsFileObject *next_file_object = indicator->related_file_objects;
    while (next_file_object != NULL) {
        SMTPIndicatorDestroyFileObject(next_file_object);
    }

    return 0;
}


SMTPIndicator *SMTPIndicatorGetRootIndicator()
{
    if (g_smtpindicators_ctx == NULL)
        return NULL;

    return g_smtpindicators_ctx->smtp_indicators;
}


/**
 *  \brief Takes ownership of the indicator and adds it to the front
 * of the list of indicators.
 */
int SMTPIndicatorAddIndicator(SMTPIndicator *indicator)
{
    // Returns 0 on success, like all good posix libraries do
    if (SCMutexLock(&(g_smtpindicators_ctx->mutex)))
        goto error;

    // add the new indicator at the front of the linked list
    indicator->next = g_smtpindicators_ctx->smtp_indicators;
    g_smtpindicators_ctx->smtp_indicators = indicator;

    SCMutexUnlock(&(g_smtpindicators_ctx->mutex));

    return 0;

error:

    return -1;
}


/**
 *  \brief Create SMTP watch list data struct
 */
int SMTPIndicatorsCreateContext()
{
    g_smtpindicators_ctx = SCMalloc(sizeof(SMTPIndicatorsCtx));

    if (g_smtpindicators_ctx == NULL)
        return 0;

    memset(g_smtpindicators_ctx, 0, sizeof(SMTPIndicatorsCtx));

    SCMutexInit(&(g_smtpindicators_ctx->mutex), NULL);

    return 0;

}


/**
 *  \brief Free SMTP watch list data struct
 */
int SMTPIndicatorDestroyContext()
{
    if (g_smtpindicators_ctx != NULL) {
        SMTPIndicator *next_indicator = g_smtpindicators_ctx->smtp_indicators;

        // Free each indicator under the lock
        SCMutexLock(&g_smtpindicators_ctx->mutex);
        while (next_indicator != NULL) {
            SMTPIndicatorDestroyIndicator(next_indicator);
            next_indicator = next_indicator->next;
        }
        SCMutexUnlock(&g_smtpindicators_ctx->mutex);
        SCMutexDestroy(&g_smtpindicators_ctx->mutex);

        SCFree(g_smtpindicators_ctx);
    }  

    return 0;
}
