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
	
#if 0	
	uint8_t httpbuf1[] =
        "GET /abc2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
#endif
	
	if(-1 == zLogInit())	
	{
		printf("zLogInit failed!\n");
		exit(1);
	}
	
	zLogDebug("Start");

/*    	
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: m.olymtech.net/\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
*/
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
		"\r\n"
		"1234567";
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

	uint8_t http_req_buf2[] =
		"890\r\n"
		"------WebKitFormBoundaryqPEJVlkco56jW0IM--\r\n";
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
	ssInput.buf = uc_http_req_buf1;
	ssInput.buf_len = uc_http_req_len1;
	DTRequestData(&ssInput);
	zLogDebug("After first req,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = uc_http_req_buf2;
	ssInput.buf_len = uc_http_req_len2;
	DTRequestData(&ssInput);
	zLogDebug("After second req,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = http_res_buf1;
	ssInput.buf_len = http_res_len1;
	DTResponseData(&ssInput);
	zLogDebug("After first res,ssInput.htp_state is:%p",ssInput.htp_state);
	
	DTFreeHTTPState(&ssInput);
	
	zLogDebug("Exit");
	return 0;
error:
	return 1;
}
