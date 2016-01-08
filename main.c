#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "log.h"
#include "handle-http-data.h"


void test_file();
void test_post();
void test_put();
void test_response_multipart();
void test_post_multipart();

int main(int argc,char *argv[])
{
	if(-1 == zLogInit())	
	{
		printf("zLogInit failed!\n");
		exit(1);
	}
	zLogDebug("Start");

	test_post_multipart();
	
	zLogDebug("Exit");
	zLogShutdown();	
	return 0;
}

#define FILE_1 "big1_Request.txt"
#define FILE_2 "big2_Request.txt"
#define FILE_OUTPUT "output.txt"

#define BUFFER_SIZE 200

FILE * g_pFileOutput = NULL;

void test_response_multipart()
{
    uint8_t httpbuf1[] =
        "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

	uint8_t http_res_buf1[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: multipart/x-mixed-replace; boundary=--4646a1160058e09bed25\r\n"
		"Server: Microsoft-HTTPAPI/2.0\r\n"
		"Date: Fri, 17 May 2013 08:20:42 GMT --4646a1160058e09bed25  Content-Type: text/plain\r\n"
		"Content-Length: 28\r\n"
		"\r\n"
		"Fortune doesn't favor fools. --4646a1160058e09bed25  Content-Type: text/plain\r\n"
		"Content-Length: 65\r\n"
		"\r\n"
		"Watch your mouth kid, or you'll find yourself respawning at home! --4646a1160058e09bed25\r\n";
	uint32_t http_res_len1 = sizeof(http_res_buf1) - 1;

	
 

}

void test_file()
{
	FILE * pFile;
	long lSize,lFilesize,lHaveRead = 0;
	char  buffer[BUFFER_SIZE + 1] = {0};
	size_t result;

	pFile = fopen ( FILE_1 , "rb" );
	if (pFile==NULL) {fputs ("File error\n",stderr); exit (1);}

	// obtain file size:
	fseek (pFile , 0 , SEEK_END);
	lFilesize = ftell (pFile);
	rewind (pFile);

	// allocate memory to contain the whole file:
	//buffer = (char*) malloc (sizeof(char)*lSize);
	//if (buffer == NULL) {fputs ("Memory error\n",stderr); exit (2);}


	

	/* the whole file is now loaded in the memory buffer. */
//----------------------------------------------------------------------------

	g_pFileOutput = fopen (FILE_OUTPUT, "a+");
	if(g_pFileOutput == NULL) {fputs ("File output.txt error\n",stderr); exit (4);}

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

	// copy the file into the buffer:
	lSize = lFilesize > BUFFER_SIZE ? BUFFER_SIZE : lFilesize ;
	for(;;)
	{
		result = fread (buffer,1,lSize,pFile);
		if (result != lSize) {fputs ("Reading error\n",stderr); exit (3);}		

		ssInput.buf = (uint8_t *)buffer;
		ssInput.buf_len = lSize;
		DTRequestData(&ssInput);
		lHaveRead += result;
		if(lHaveRead == lFilesize)
			break;
		else if(lHaveRead > lFilesize)
			{zLogDebug("Reading error"); exit (3);}
		fseek(pFile, lHaveRead, SEEK_SET);

		lSize = (lFilesize - lHaveRead) > BUFFER_SIZE ? BUFFER_SIZE : (lFilesize - lHaveRead) ;

		sleep(1);
	}


	zLogDebug("After the read file,ssInput.htp_state is:%p",ssInput.htp_state);


	ssInput.buf = http_res_buf1;
	ssInput.buf_len = http_res_len1;
	DTResponseData(&ssInput);
	zLogDebug("After the first res,ssInput.htp_state is:%p",ssInput.htp_state);
	
	DTFreeHTTPState(&ssInput);
		
//----------------------------------------------------------------------------

	// terminate
	fclose (pFile);
	fclose (g_pFileOutput);
	g_pFileOutput = NULL;
	//free (buffer);
}

void test_post()
{
    uint8_t http_req_buf1[] = "POST /filenam";
    uint32_t http_req_len1 = sizeof(http_req_buf1) - 1; /* minus the \0 */
	
    uint8_t http_req_buf2[] = 
					     "e HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Length: 11\r\n"
                         "\r\nFILECONTENT";
    uint32_t http_req_len2 = sizeof(http_req_buf2) - 1; /* minus the \0 */


	

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

	ssInput.buf = http_req_buf1;
	ssInput.buf_len = http_req_len1;
	DTRequestData(&ssInput);
	zLogDebug("After the http_req_buf1,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = http_req_buf2;
	ssInput.buf_len = http_req_len2;
	DTRequestData(&ssInput);
	zLogDebug("After the http_req_buf2,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = http_res_buf1;
	ssInput.buf_len = http_res_len1;
	DTResponseData(&ssInput);
	zLogDebug("After the first res,ssInput.htp_state is:%p",ssInput.htp_state);

	DTFreeHTTPState(&ssInput);

}
void test_put()
{
	uint8_t http_req_buf1[] = "PUT /filename HTTP/1.1\r\n"
							 "Host: www.server.lan\r\n"
							 "Content-Length: 11\r\n"
							 "\r\nFI";
	uint32_t http_req_len1 = sizeof(http_req_buf1) - 1; /* minus the \0 */
	
	uint8_t http_req_buf2[] = "LECONTENT";
	uint32_t http_req_len2 = sizeof(http_req_buf2) - 1; /* minus the \0 */


	

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

	ssInput.buf = http_req_buf1;
	ssInput.buf_len = http_req_len1;
	DTRequestData(&ssInput);
	zLogDebug("After the http_req_buf1,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = http_req_buf2;
	ssInput.buf_len = http_req_len2;
	DTRequestData(&ssInput);
	zLogDebug("After the http_req_buf2,ssInput.htp_state is:%p",ssInput.htp_state);

	ssInput.buf = http_res_buf1;
	ssInput.buf_len = http_res_len1;
	DTResponseData(&ssInput);
	zLogDebug("After the first res,ssInput.htp_state is:%p",ssInput.htp_state);

	DTFreeHTTPState(&ssInput);

}

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

void test_post_multipart()
{
	DTInitHTTP();
	
	stSocketInput ssInput;
	memset(&ssInput,0,sizeof(ssInput));
	                         
    uint8_t httpbuf1_1_2m[] = 
						 "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 387\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecont";
    uint32_t httplen1_1_2m = sizeof(httpbuf1_1_2m) - 1; /* minus the \0 */

	ssInput.buf = httpbuf1_1_2m;
	ssInput.buf_len = httplen1_1_2m;
	DTRequestData(&ssInput);
	zLogDebug("After the httpbuf1_1_2m,ssInput.htp_state is:%p",ssInput.htp_state);
	
    uint8_t httpbuf2_1_2m[] = 
						 "entA\r\n"
                         "-----------------------------277531038314945\r\n"
						 "Content-Disposition: form-data; name=\"uploadfile_1\"; filename=\"somepicture2.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "FILECONTENT\r\n"
       					 "-----------------------------277531038314945--\r\n";
	uint32_t httplen2_1_2m = sizeof(httpbuf2_1_2m) - 1; /* minus the \0 */

	ssInput.buf = httpbuf2_1_2m;
	ssInput.buf_len = httplen2_1_2m;
	DTRequestData(&ssInput);
	zLogDebug("After the httpbuf2_1_2m,ssInput.htp_state is:%p",ssInput.htp_state);
	//---------------------------------------------------------------------------------------------------------

	/** \test first multipart part contains file but doesn't end in first chunk */

		uint8_t httpbuf1_2_2m[] = "POST /upload.cgi HTTP/1.1\r\n"
		                 "Host: www.server.lan\r\n"
		                 "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
		                 "Content-Length: 544\r\n"
		                 "\r\n"
		                 "-----------------------------277531038314945\r\n"
		                 "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
		                 "Content-Type: image/jpeg\r\n"
		                 "\r\n"
		                 "filecontent\r\n"
		                 "-----------------------------27753103831494";
		uint32_t httplen1_2_2m = sizeof(httpbuf1_2_2m) - 1; /* minus the \0 */
		
		uint8_t httpbuf2_2_2m[] = "5\r\nContent-Disposition: form-data; name=\"uploadfile_1\"; filename=\"somepicture2.jpg\"\r\n"
		                 "Content-Type: image/jpeg\r\n"
		                 "\r\n"
		                 "FILECONTENT\r\n"
		"-----------------------------277531038314945--\r\n";
		uint32_t httplen2_2_2m = sizeof(httpbuf2_2_2m) - 1; /* minus the \0 */
	//--------------------------------------------------------------------------------------------------------- 
			
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
	
		uint8_t http_buf_complete_1[] =
			"POST https://192.168.1.26/index.php?explorer/fileUpload&path=%2F HTTP/1.1\r\n"
			"Host: 192.168.1.26\r\n"
			"Connection: keep-alive\r\n"
			"Content-Length: 829\r\n"
			"Origin: https://192.168.1.26\r\n"
			"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\r\n"
			"Content-Type: multipart/form-data; boundary=----AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Accept: */*\r\n"
			"Referer: https://192.168.1.26/index.php\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Accept-Language: zh-CN,zh;q=0.8\r\n"
			"Cookie: user_language=zh_CN; PHPSESSID=d7517ipbquo5hhojljol8esed7\r\n"
			"\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"id\"\r\n"
			"\r\n"
			"WU_FILE_1\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"name\"\r\n"
			"\r\n"
			"1.txt\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"type\"\r\n"
			"\r\n"
			"text/plain\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
			"\r\n"
			"Mon Dec 28 2015 10:25:14 GMT+0800 (中国标准时间)\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"size\"\r\n"
			"\r\n"
			"10\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"fullPath\"\r\n"
			"\r\n"
			"\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM\r\n"
			"Content-Disposition: form-data; name=\"file\"; filename=\"1.txt\"\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"0123456789\r\n"
			"------AebKitFormBoundaryqPEJVlkco56jW0IM--\r\n";
		uint32_t http_len_complete_1 = sizeof(http_buf_complete_1) - 1;
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
			"\r\n";
			
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
			"1234567890\r\n"
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
			"PEJVlkco56jW0IM--";
	
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
			"\r\n";
	
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
		


		//ssInput.buf = httpbuf2_1_2m;
		//ssInput.buf_len = httplen2_1_2m;
		//DTRequestData(&ssInput);
		//zLogDebug("After the httpbuf2_1_2m,ssInput.htp_state is:%p",ssInput.htp_state);

#if 0
	
		ssInput.buf = uc_http_req_buf1;
		ssInput.buf_len = uc_http_req_len1;
		DTRequestData(&ssInput);
		zLogDebug("After the httpbuf_get,ssInput.htp_state is:%p",ssInput.htp_state);
	
	
		ssInput.buf = uc_http_req_buf1_1;
		ssInput.buf_len = uc_http_req_len1_1;
		DTRequestData(&ssInput);
		zLogDebug("After the httpbuf_get_1,ssInput.htp_state is:%p",ssInput.htp_state);
	
		ssInput.buf = uc_http_req_buf1_2;
		ssInput.buf_len = uc_http_req_len1_2;
		DTRequestData(&ssInput);
		zLogDebug("After the httpbuf_get_1,ssInput.htp_state is:%p",ssInput.htp_state); 

		ssInput.buf = uc_http_req_buf1_3;
		ssInput.buf_len = uc_http_req_len1_3;
		DTRequestData(&ssInput);
		zLogDebug("After the httpbuf_get_1,ssInput.htp_state is:%p",ssInput.htp_state); 
#endif
	
#if 0
	
		ssInput.buf = http_buf_complete;
		ssInput.buf_len = http_len_complete;
		DTRequestData(&ssInput);
		zLogDebug("After the http_buf_complete,ssInput.htp_state is:%p",ssInput.htp_state);
	
		ssInput.buf = http_buf_complete_1;
		ssInput.buf_len = http_len_complete_1;
		DTRequestData(&ssInput);
		zLogDebug("After the http_buf_complete_1,ssInput.htp_state is:%p",ssInput.htp_state);
	
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
		zLogDebug("After the first res,ssInput.htp_state is:%p",ssInput.htp_state);
	
		//DTResponseData(&ssInput);
		//zLogDebug("After the second res,ssInput.htp_state is:%p",ssInput.htp_state);
		
		DTFreeHTTPState(&ssInput);
		return;
error:
		printf("error!\n");
		return;

}
