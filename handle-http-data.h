/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __HANDLE_HTTP_DATA_H__
#define __HANDLE_HTTP_DATA_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct stSocketInput_
{
	uint8_t *buf;
	uint32_t buf_len;
	int conn;
	void *htp_state;
	int (*send_sock)(int, const char *, uint32_t);
}stSocketInput;

/**
 *@error return -1,success return 0
 */ 
int DTInitHTTP();

/**
 *@error return -1,success return 0
 */
int DTRequestData(stSocketInput *stsi);

/**
 *@error return -1,success return 0
 */
int DTResponseData(stSocketInput *stsi);

int DTFreeHTTPState(void *stsi);

#ifdef	__cplusplus
}
#endif

#endif

