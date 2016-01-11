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

#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
//noted begin
//g++ do not know #define __STDC_FORMAT_MACROS,so when using g++ need #define __STDC_FORMAT_MACROS before #include <inttypes.h>
//#ifdef	__cplusplus
//#define __STDC_FORMAT_MACROS
//#endif

#include <inttypes.h>
//noted end

#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#define SCReturnInt(x) return x
#define SCReturnPtr(x, type)            return x
#define SCEnter(...)
#define SCLogDebug(...) zLogDebug(__VA_ARGS__)
#define SCMalloc(a) malloc((a))

#define SCFree(a) ({ \
    free(a); \
})



#if CPPCHECK==1
#define likely
#define unlikely
#else
#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#endif
