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

#ifndef __ZUTIL_H__
#define __ZUTIL_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

#define HAVE_ASSERT_H 1

#ifdef HAVE_ASSERT_H
#include <assert.h>
#define BUG_ON(x) assert(!(x))
#else
#define BUG_ON(x)
#endif


#if defined(_WIN32)
#include <windows.h>
typedef	unsigned long u_long;
#define SCGetThreadIdLong(...) ({ \
    u_long tid = (u_long)GetCurrentThreadId(); \
	tid; \
})
#else
#include <sys/syscall.h>
#include <sys/types.h>
#define SCGetThreadIdLong(...) ({ \
   pid_t tmpthid; \
   tmpthid = syscall(SYS_gettid); \
   u_long tid = (u_long)tmpthid; \
   tid; \
})
#endif

#define zGetLocalTime(...) ({ \
   	char lt[32] = {0};\
	zGetLocalTimeEx(lt);\
	lt;\
})

inline int32_t zGetTimestamp();
void  zGetLocalTimeEx(char tt[]);
void zPrintRawDataFp(FILE *fp, uint8_t *buf, uint32_t buflen);

void zPrintData(uint8_t *buf, uint32_t buflen);


/* this is faster than the table lookup */
#include <ctype.h>
#define u8_tolower(c) tolower((uint8_t)(c))

static inline int
MemcmpLowercase(const void *s1, const void *s2, size_t n)
{
    ssize_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i >= 0; i--) {
        if (((uint8_t *)s1)[i] != u8_tolower(*(((uint8_t *)s2)+i)))
            return 1;
    }

    return 0;
}

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t len) {
    return MemcmpLowercase(s1, s2, len);
}

//if uint8_t *s = "1234",then *d = 1234; error return 0,else return 1
static inline int ConvertString2Uint64(uint8_t *s, size_t len,uint64_t *d)
{
    uint64_t x = 0;
	size_t b_len, temp;
	for(b_len = 0;b_len < len; ++b_len)
	{
		temp = (int)s[b_len];
		if(temp > '9' || temp < '0')
            return 0;
		x *= 10;
		x += temp - '0';
	}
	*d = x;
    return 1;
}

/* No SIMD support, fall back to plain memcmp and a home grown lowercase one */

/* wrapper around memcmp to match the retvals of the SIMD implementations */
#define SCMemcmp(a,b,c) ({ \
    memcmp((a), (b), (c)) ? 1 : 0; \
})


typedef struct zEnumCharMap_ {
    char *enum_name;
    int enum_value;
} zEnumCharMap;
int zMapEnumNameToValue(const char *, zEnumCharMap *);
const char * zMapEnumValueToName(int, zEnumCharMap *);

#ifdef	__cplusplus
}
#endif

#endif
