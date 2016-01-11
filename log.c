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

#include "log.h"
#include <stdarg.h>

#define zLogPath "detect-http.log"

static FILE *fp = NULL;
static zlog_show log_show = ZWRITE;


zEnumCharMap log_level_map[ ] = {
    { "<Debug>",        LOG_DEBUG},
    { "<Info >",        LOG_INFO },
    { "<Warn >",        LOG_WARN },
    { "<Error>",        LOG_ERROR },
    { "<Fatal>",        LOG_FATAL },
    { NULL,             -1 }
};


#if defined(_WIN32)
#define snprintf _snprintf
#endif

int zLogInit()
{
#ifdef ZSHOW_LOG
        log_show = ZSHOW;
		return 0;
#else
	#ifdef ZWRITESHOW_LOG
        log_show = ZWRITESHOW;
	#endif

	fp = fopen(zLogPath,"a+");
	if(NULL == fp)
		return -1;
	else
		return 0;
#endif
}
void zLogShutdown()
{
	if(fp != NULL)
		fclose(fp);
	fp = NULL;
}

static inline void zPrintToStream(FILE *fd, char *msg)
{
	if (fprintf(fd, "%s", msg) < 0)
		printf("fprintf error\n");
	fflush(fd);
	return;
}
int zLogMsg(LogLevel log_level,char *msg)
{
	char ch_output[MAX_LOG_MSG_LEN] = {0};
	const char *s = NULL;

	/* no of characters_written(cw) by snprintf */
    int cw = 0;

    s = zMapEnumValueToName(log_level, log_level_map);
    if (s != NULL)
        cw = snprintf(ch_output, MAX_LOG_MSG_LEN,"%s%s",s," ");
    else
        cw = snprintf(ch_output, MAX_LOG_MSG_LEN,"%s","<-----> ");
	if (cw < 0)
		return -1;

	char *temp = msg;
	int len = strlen(msg);
	if (len == LOG_MSG_LEN - 1)
		len = LOG_MSG_LEN - 2;

    temp[len] = '\n';
   	temp[len + 1] = '\0';

	cw = snprintf(ch_output + cw, MAX_LOG_MSG_LEN - cw,"%s",temp);
	if (cw < 0)
		return -1;
	
	switch(log_show)
	{
		case ZWRITE:
			zPrintToStream(fp,ch_output);
			break;
		case ZSHOW:
			zPrintToStream(stdout,ch_output);
			break;
		case ZWRITESHOW:
			zPrintToStream(stdout,ch_output);
			zPrintToStream(fp,ch_output);
			break;
		default:
            break;
	}
	return 0;
	/*

    char buf[MAX_LOG_MSG_LEN];
    va_list args;

    va_start(args, fmt);

    int r = vsnprintf(buf, MAX_LOG_MSG_LEN, fmt, args);

    va_end(args);

    if (r < 0) {
        snprintf(buf, MAX_LOG_MSG_LEN, "[vnsprintf returned error %d]", r);
    } else if (r >= MAX_LOG_MSG_LEN) {
        // Indicate overflow with a '+' at the end.
        buf[MAX_LOG_MSG_LEN -2] = '+';
        buf[MAX_LOG_MSG_LEN - 1] = '\0';
    }

	printf(buf);
	return 0;

	va_list args;
	va_start (args, fmt);

	                char t[32] = {0};           \
				ut_getLocaltime(t);\
                char _sc_log_msg[SC_LOG_MAX_LOG_MSG_LEN] = "";\
                char *temp = _sc_log_msg;\
                int n = snprintf(temp,sizeof(t),t);\
                temp  += n;\
                n = snprintf(temp,SC_LOG_MAX_LOG_MSG_LEN - (temp - _sc_log_msg)," %s:%d (%s) -- ",__FILE__,__LINE__,__FUNCTION__);\
                temp  += n;\
                n = snprintf(temp,SC_LOG_MAX_LOG_MSG_LEN - (temp - _sc_log_msg),__VA_ARGS__);\
				int len = strlen(_sc_log_msg);\
				if (len == SC_LOG_MAX_LOG_MSG_LEN - 1)\
					len = SC_LOG_MAX_LOG_MSG_LEN - 	2;\
				_sc_log_msg[len] = '\n';\
                _sc_log_msg[len + 1] = '\0';\
                printf(_sc_log_msg);\

	va_end (args);
*/
}

inline FILE * zGetLogFp()
{
	if(NULL == fp)
		fp = fopen(zLogPath,"a+");
    return fp;
}
