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
	void *htp_state;
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

