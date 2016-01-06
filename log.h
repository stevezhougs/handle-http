#ifndef __ZLOG_H__
#define __ZLOG_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include "util.h"
#include <time.h>

typedef enum zlog_show{ ZWRITE, ZSHOW, ZWRITESHOW }zlog_show;

/**
 * \brief The various log levels
 */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
} LogLevel;


/* The maximum length of the log message */
#define SC_LOG_MAX_LOG_MSG_LEN 2048
#define zLog(x,...) do {                     \
                time_t t = time(0);         \
                char tt[32] = {0};           \
                strftime(tt, sizeof(tt), "%Y-%m-%d %X",localtime(&t) );\
                char _sc_log_msg[SC_LOG_MAX_LOG_MSG_LEN] = "";\
                char *temp = _sc_log_msg;\
                int n = snprintf(temp,SC_LOG_MAX_LOG_MSG_LEN,"[%lu] ",SCGetThreadIdLong());\
                temp  += n;\
                n = snprintf(temp,sizeof(tt),tt);\
                temp  += n;\
                n = snprintf(temp,SC_LOG_MAX_LOG_MSG_LEN - (temp - _sc_log_msg)," %s:%d (%s) -- ",__FILE__,__LINE__,__FUNCTION__);\
                temp  += n;\
                snprintf(temp,SC_LOG_MAX_LOG_MSG_LEN - (temp - _sc_log_msg),__VA_ARGS__);\
                zLogMsg(x,_sc_log_msg);\
                } while(0)

#ifdef ZPRINT
#define zPRINT(...) zLog(LOG_DEBUG,__VA_ARGS__)
#else
#define zPRINT(...)
#endif

#ifdef ZSHOWENTER
#define zEnter(...)  zLogDebug(__VA_ARGS__)
#else
#define zEnter(...)
#endif

#define zLogDebug(...) zLog(LOG_DEBUG,__VA_ARGS__)
#define zLogInfo(...) zLog(LOG_INFO,__VA_ARGS__)
#define zLogWarn(...) zLog(LOG_WARN,__VA_ARGS__)
#define zLogError(...) zLog(LOG_ERROR,__VA_ARGS__)
#define zLogFatal(...) zLog(LOG_FATAL,__VA_ARGS__)






//#define zlog(...)  zLogMsg("[%lu] %s:%d (%s) -- ",SCGetThreadIdLong(),zGetLocalTime(),__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__)
int zLogInit();
void zLogShutdown();
int zLogMsg(LogLevel log_level,char *msg);
inline FILE * zGetLogFp();

#ifdef	__cplusplus
}
#endif

#endif

