#include "common.h"
#include "log.h"
#include "handle-http-data.h"
#if 0
#define REQ_MSG "POST https://192.168.1.26/index.php?explorer/fileUpload&path=%2F HTTP/1.1\r\n"
		"Host: 192.168.1.26\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: 829\r\n"
		"Origin: https://192.168.1.26\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\r\n"
		"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Accept: */*\r\n"
		"Referer: https://192.168.1.26/index.php\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: zh-CN,zh;q=0.8\r\n"
		"Cookie: user_language=zh_CN; PHPSESSID=d7517ipbquo5hhojljol8esed7\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"id\"\r\n"
		"\r\n"
		"WU_FILE_1\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"name\"\r\n"
		"\r\n"
		"1.txt\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"type\"\r\n"
		"\r\n"
		"text/plain\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
		"\r\n"
		"Mon Dec 28 2015 10:25:14 GMT+0800 (中国标准时间)\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"size\"\r\n"
		"\r\n"
		"10\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"fullPath\"\r\n"
		"\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"1.txt\"\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"1234567890\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM--\r\n"
#endif
int main(int argc,char *argv[])
{
	//PRINT("Start!");
	
	
	if(-1 == zLogInit())	
	{
		printf("zLogInit failed!\n");
		exit(1);
	}

//--------------------------------------------------------------------------------------------------------- 

	uint8_t httpbuf_get[] =
        "GET https:";
	uint32_t http_len_get = sizeof(httpbuf_get) - 1;
	
	uint8_t httpbuf_get_1[] =
		"//192.168.1.26/index.php?explorer/pathList&path=%2F HTTP/1.1\r\n";
	uint32_t http_len_get_1 = sizeof(httpbuf_get_1) - 1;

	uint8_t httpbuf_get_2[] =
		"Host: 192.168.1.26\r\n"
		"Connection: keep-alive\r\n"
		"Accept: application/json, text/javascript, */*; q=0.01\r\n"
		"X-Requested-With: XMLHttpRequest\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\r\n"
		"Referer: https://192.168.1.26/index.php\r\n"
		"Accept-Encoding: gzip, deflate, sdch\r\n"
		"Accept-Language: zh-CN,zh;q=0.8\r\n"
		"Cookie: user_language=zh_CN; PHPSESSID=ntslsa1701ilbbs6d3d6eiurm2"
		"\r\n\r\n";
	uint32_t http_len_get_2 = sizeof(httpbuf_get_2) - 1;


		
//---------------------------------------------------------------------------------------------------------	
	zLogDebug("Start");
   	
    uint8_t http_buf_complete[] =
        "POST https://192.168.1.26/index.php?explorer/fileUpload&path=%2F HTTP/1.1\r\n"
		"Host: 192.168.1.26\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: 829\r\n"
		"Origin: https://192.168.1.26\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\r\n"
		"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Accept: */*\r\n"
		"Referer: https://192.168.1.26/index.php\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: zh-CN,zh;q=0.8\r\n"
		"Cookie: user_language=zh_CN; PHPSESSID=d7517ipbquo5hhojljol8esed7\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"id\"\r\n"
		"\r\n"
		"WU_FILE_1\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"name\"\r\n"
		"\r\n"
		"1.txt\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"type\"\r\n"
		"\r\n"
		"text/plain\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
		"\r\n"
		"Mon Dec 28 2015 10:25:14 GMT+0800 (中国标准时间)\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"size\"\r\n"
		"\r\n"
		"10\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"fullPath\"\r\n"
		"\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"1.txt\"\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"1234567890\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM--\r\n";
    uint32_t http_len_complete = sizeof(http_buf_complete) - 1;
	//-------------------------------------------------------------------------
	uint8_t http_req_buf1[] =
		"POST https://192.168.1.26/index.php?explorer/fileUpload&path=%2F HTTP/1.1\r\n"
		"Host: 192.168.1.26\r\n"
		"Connection: keep-alive\r\n"
		"Content-Length: 829\r\n"
		"Origin: https://192.168.1.26\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\r\n"
		"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Accept: */*\r\n"
		"Referer: https://192.168.1.26/index.php\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: zh-CN,zh;q=0.8\r\n"
		"Cookie: user_language=zh_CN; PHPSESSID=d7517ipbquo5hhojljol8esed7\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"id\"\r\n"
		"\r\n"
		"WU_FILE_1\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"name\"\r\n"
		"\r\n"
		"1.txt\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"type\"\r\n"
		"\r\n"
		"text/plain\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
		"\r\n"
		"Mon Dec 28 2015 10:25:14 GMT+0800 (中国标准时间)\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"size\"\r\n"
		"\r\n"
		"10\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"fullPath\"\r\n"
		"\r\n"
		"\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"1.txt\"\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n1";
		
	uint32_t http_req_len1 = sizeof(http_req_buf1) - 1;

	uint8_t *uc_http_req_buf1 = (uint8_t *)calloc(1,sizeof(http_req_buf1));
	if(NULL == uc_http_req_buf1)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf1,http_req_buf1,http_req_len1);
	uint32_t uc_http_req_len1 = http_req_len1;
	//zLogDebug((char*)uc_http_req_buf1);	
	zLogDebug("length is:%d",uc_http_req_len1);	
//-------------------------------------------------------------------------
	uint8_t http_req_buf1_1[] =
		"234567890\r\n"
		"------WebKitFormBoundaryq";

	uint32_t http_req_len1_1 = sizeof(http_req_buf1_1) - 1;

	uint8_t *uc_http_req_buf1_1 = (uint8_t *)calloc(1,sizeof(http_req_buf1_1));
	if(NULL == uc_http_req_buf1_1)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf1_1,http_req_buf1_1,http_req_len1_1);
	uint32_t uc_http_req_len1_1 = http_req_len1_1;
	//zLogDebug((char*)uc_http_req_buf1);	
	zLogDebug("length is:%d",uc_http_req_len1_1); 
//-------------------------------------------------------------------------
	uint8_t http_req_buf1_2[] =
		"PEJVlkco56jW0IM--\r\n";

	uint32_t http_req_len1_2 = sizeof(http_req_buf1_2) - 1;

	uint8_t *uc_http_req_buf1_2 = (uint8_t *)calloc(1,sizeof(http_req_buf1_2));
	if(NULL == uc_http_req_buf1_2)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf1_2,http_req_buf1_2,http_req_len1_2);
	uint32_t uc_http_req_len1_2 = http_req_len1_2;
	//zLogDebug((char*)uc_http_req_buf1);	
	zLogDebug("length is:%d",uc_http_req_len1_2); 	
//-------------------------------------------------------------------------
	uint8_t http_req_buf1_3[] =
		"23";

	uint32_t http_req_len1_3 = sizeof(http_req_buf1_3) - 1;

	uint8_t *uc_http_req_buf1_3 = (uint8_t *)calloc(1,sizeof(http_req_buf1_3));
	if(NULL == uc_http_req_buf1_3)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf1_3,http_req_buf1_3,http_req_len1_3);
	uint32_t uc_http_req_len1_3 = http_req_len1_3;
	//zLogDebug((char*)uc_http_req_buf1);	
	zLogDebug("length is:%d",uc_http_req_len1_3); 	
//-------------------------------------------------------------------------

	uint8_t http_req_buf2[] = "4567";
	uint32_t http_req_len2 = sizeof(http_req_buf2) - 1;


	uint8_t *uc_http_req_buf2 = (uint8_t *)calloc(1,sizeof(http_req_buf2));
	if(NULL == uc_http_req_buf2)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf2,http_req_buf2,http_req_len2);
	uint32_t uc_http_req_len2 = http_req_len2;
	//zLogDebug((char*)uc_http_req_buf2);
	zLogDebug("length is:%d",uc_http_req_len2);	
//-------------------------------------------------------------------------

	uint8_t http_req_buf3[] =
		"890\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM--\r\n";
	uint32_t http_req_len3 = sizeof(http_req_buf3) - 1;


	uint8_t *uc_http_req_buf3 = (uint8_t *)calloc(1,sizeof(http_req_buf3));
	if(NULL == uc_http_req_buf3)
	{
		zLogFatal("memory allocate failed");
		goto error;
	}	
	memcpy((void*)uc_http_req_buf3,http_req_buf3,http_req_len3);
	uint32_t uc_http_req_len3 = http_req_len3;
	//zLogDebug((char*)uc_http_req_buf2);
	zLogDebug("length is:%d",uc_http_req_len3); 
//-------------------------------------------------------------------------


	
    uint8_t http_res_buf1[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_res_len1 = sizeof(http_res_buf1) - 1;
	
	DTInitHTTP();

	stSocketInput ssInput;
	memset(&ssInput,0,sizeof(ssInput));
#if 0

	ssInput.buf = httpbuf_get;
	ssInput.buf_len = http_len_get;
	DTRequestData(&ssInput);
	zLogDebug("After the httpbuf_get,ssInput.htp_state is:%p",ssInput.htp_state);


	ssInput.buf = httpbuf_get_1;
	ssInput.buf_len = http_len_get_1;
	DTRequestData(&ssInput);
	zLogDebug("After the httpbuf_get_1,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = httpbuf_get_2;
	ssInput.buf_len = http_len_get_2;
	DTRequestData(&ssInput);
	zLogDebug("After the httpbuf_get_1,ssInput.htp_state is:%p",ssInput.htp_state);	
#endif


	ssInput.buf = http_buf_complete;
	ssInput.buf_len = http_len_complete;
	DTRequestData(&ssInput);
	zLogDebug("After the http_buf_complete,ssInput.htp_state is:%p",ssInput.htp_state);
#if 0

	ssInput.buf = uc_http_req_buf1;
	ssInput.buf_len = uc_http_req_len1;
	DTRequestData(&ssInput);
	zLogDebug("After the 1 req,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = uc_http_req_buf1_1;
	ssInput.buf_len = uc_http_req_len1_1;
	DTRequestData(&ssInput);
	zLogDebug("After the 1_1 req,ssInput.htp_state is:%p",ssInput.htp_state);
	
	ssInput.buf = uc_http_req_buf1_2;
	ssInput.buf_len = uc_http_req_len1_2;
	DTRequestData(&ssInput);
	zLogDebug("After the 1_2 req,ssInput.htp_state is:%p",ssInput.htp_state);
	
	ssInput.buf = uc_http_req_buf1_3;
	ssInput.buf_len = uc_http_req_len1_3;
	DTRequestData(&ssInput);
	zLogDebug("After the 1_3 req,ssInput.htp_state is:%p",ssInput.htp_state);


	ssInput.buf = uc_http_req_buf2;
	ssInput.buf_len = uc_http_req_len2;
	DTRequestData(&ssInput);
	zLogDebug("After the 2 req,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = uc_http_req_buf3;
	ssInput.buf_len = uc_http_req_len3;
	DTRequestData(&ssInput);
	zLogDebug("After the 3 req,ssInput.htp_state is:%p",ssInput.htp_state);

#endif

	ssInput.buf = http_res_buf1;
	ssInput.buf_len = http_res_len1;
	DTResponseData(&ssInput);
	zLogDebug("After the res,ssInput.htp_state is:%p",ssInput.htp_state);
	
	DTFreeHTTPState(&ssInput);
	
	zLogDebug("Exit");
	return 0;
error:
	return 1;
}
