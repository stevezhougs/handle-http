/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */
/*
#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp.h"
#include "app-layer-htp-file.h"
#include "util-time.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

#include "util-memcmp.h"
*/

#include "common.h"
#include "detect-http.h"
#include "log.h"

/**
 * \brief Append a chunk of body to the HtpBody struct
 *
 * \param body pointer to the HtpBody holding the list
 * \param data pointer to the data of the chunk
 * \param len length of the chunk pointed by data
 *
 * \retval 0 ok
 * \retval -1 error
 */
int HtpBodyAppendChunk(HtpTxUserData *htud, HtpBody *body, uint8_t *data, uint32_t len)
{
	zEnter("Enter");

    HtpBodyChunk *bd = NULL;

    if (len == 0 || data == NULL) {
        return 0;
    }

    if (body->first == NULL) {
        /* New chunk */
        bd = (HtpBodyChunk *)malloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = 0;
        bd->next = NULL;

        bd->data = malloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->first = body->last = bd;

        body->content_len_so_far = len;
    } else {
        bd = (HtpBodyChunk *)malloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = body->content_len_so_far;
        bd->next = NULL;

        bd->data = malloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->last->next = bd;
        body->last = bd;

        body->content_len_so_far += len;
    }
    zLogDebug("Body %p; data %p, len %"PRIu32, body, bd->data, (uint32_t)bd->len);

    return 0;

error:
    if (bd != NULL) {
        if (bd->data != NULL) {
            //HTPFree(bd->data, bd->len);
            SAFE_FREE(bd->data);
        }
        //HTPFree(bd, sizeof(HtpBodyChunk));
        SAFE_FREE(bd);
    }
	zLogError("memory allocate failed!");
    return -1;
}

/**
 * \brief Print the information and chunks of a Body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
 /*
void HtpBodyPrint(HtpBody *body)
{
    if (SCLogDebugEnabled()||1) {
        SCEnter();

        if (body->first == NULL)
            return;

        HtpBodyChunk *cur = NULL;
        SCLogDebug("--- Start body chunks at %p ---", body);
        printf("--- Start body chunks at %p ---\n", body);
        for (cur = body->first; cur != NULL; cur = cur->next) {
            SCLogDebug("Body %p; data %p, len %"PRIu32, body, cur->data, (uint32_t)cur->len);
            printf("Body %p; data %p, len %"PRIu32"\n", body, cur->data, (uint32_t)cur->len);
            PrintRawDataFp(stdout, (uint8_t*)cur->data, cur->len);
        }
        SCLogDebug("--- End body chunks at %p ---", body);
    }
}
*/
/**
 * \brief Free the information held in the request body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyFree(HtpBody *body)
{
    if (body->first == NULL)
        return;

    zLogDebug("Removing chunks of Body %p; data %p, len %"PRIu32, body,
            body->last->data, (uint32_t)body->last->len);

    HtpBodyChunk *cur = NULL;
    HtpBodyChunk *prev = NULL;

    prev = body->first;
    while (prev != NULL) {
        cur = prev->next;
        if (prev->data != NULL){
            //HTPFree(prev->data, prev->len);
			SAFE_FREE(prev->data);
        }
        //PFree(prev, sizeof(HtpBodyChunk));
        free(prev);
        prev = cur;
    }
    body->first = body->last = NULL;
}

/**
 * \brief Free request body chunks that are already fully parsed.
 *
 * \param htud pointer to the HtpTxUserData holding the body
 *
 * \retval none
 */
void HtpBodyPrune(HtpBody *body)
{

    if (body == NULL || body->first == NULL) {
        return;
	}

    if (body->body_parsed == 0) {
        return;
    }

    zLogDebug("Pruning chunks of Body %p; data %p, len %"PRIu32, body,
            body->last->data, (uint32_t)body->last->len);

    HtpBodyChunk *cur = body->first;
    while (cur != NULL) {
        HtpBodyChunk *next = cur->next;

        zLogDebug("cur->stream_offset %"PRIu64" + cur->len %u = %"PRIu64", "
                "body->body_parsed %"PRIu64, cur->stream_offset, cur->len,
                cur->stream_offset + cur->len, body->body_parsed);
		/*****************dt  begin**********************/
        //if (cur->stream_offset >= body->body_inspected) {
            //break;
        //}
		/*****************dt  end***********************/

        body->first = next;
        if (body->last == cur) {
            body->last = next;
        }

        if (cur->data != NULL) {
            //PFree(cur->data, cur->len);
            SAFE_FREE(cur->data);
        }
        //HTPFree(cur, sizeof(HtpBodyChunk));
		free(cur);
        cur = next;
    }

    return;
}
