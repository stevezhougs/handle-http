#include "log.h"
#include <stdarg.h>

#define zLogPath "detect-http.log"
static FILE *fp = NULL;
static zlog_show log_show = ZWRITE;

#define MAX_LOG_MSG_LEN 2048

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
	//if(NULL == fp) 
		//return -1;
	char *temp = msg;
	int len = strlen(msg);

	if (len == SC_LOG_MAX_LOG_MSG_LEN - 1)
        	len = SC_LOG_MAX_LOG_MSG_LEN - 2;

    	temp[len] = '\n';
   	temp[len + 1] = '\0';
	switch(log_show)
	{
		case ZWRITE:
			zPrintToStream(fp,msg);
			break;
		case ZSHOW:
			zPrintToStream(stdout,msg);
			break;
		case ZWRITESHOW:
			zPrintToStream(stdout,msg);
			zPrintToStream(fp,msg);
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

