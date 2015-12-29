
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
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


#endif
