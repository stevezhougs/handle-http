#include "common.h"
#include "handle-http-data.h"
#include "detect-http.h"
#include "app-layer-htp-body.h"
#include "util.h"
#include "log.h"
#include "util-spm.h"

#include <math.h>

static htp_cfg_t *g_cfg = NULL;

static void HTPFree(void *ptr, size_t size)
{
    free(ptr);

   // HTPDecrMemuse((uint64_t)size);
}

/**
 *  \param name /Lowercase/ version of the variable name
 */
static int HTTPParseContentTypeHeader(uint8_t *name, size_t name_len,
        uint8_t *data, size_t len, uint8_t **retptr, size_t *retlen)
{
#ifdef ZPRINT
    zPRINT("DATA START: ");
    zPrintRawDataFp(stdout, data, len);
    zPRINT("DATA END: ");
#endif
    size_t x;
    int quote = 0;

    for (x = 0; x < len; x++) {
        if (!(isspace(data[x])))
            break;
    }

    if (x >= len) {
        return 0;
    }

    uint8_t *line = data+x;
    size_t line_len = len-x;
    size_t offset = 0;
#ifdef ZPRINT
    zPRINT("LINE START: ");
    zPrintRawDataFp(stdout, line, line_len);
    zPRINT("LINE END: ");
#endif
    for (x = 0 ; x < line_len; x++) {
        if (x > 0) {
            if (line[x - 1] != '\\' && line[x] == '\"') {
                quote++;
            }

            if (((line[x - 1] != '\\' && line[x] == ';') || ((x + 1) == line_len)) && (quote == 0 || quote % 2 == 0)) {
                uint8_t *token = line + offset;
                size_t token_len = x - offset;

                if ((x + 1) == line_len) {
                    token_len++;
                }

                offset = x + 1;

                while (offset < line_len && isspace(line[offset])) {
                    x++;
                    offset++;
                }
#ifdef ZPRINT
                zPRINT("TOKEN START: ");
                zPrintRawDataFp(stdout, token, token_len);
                zPRINT("TOKEN END: ");
#endif
                if (token_len > name_len) {
                    if (name == NULL || SCMemcmpLowercase(name, token, name_len) == 0) {
                        uint8_t *value = token + name_len;
                        size_t value_len = token_len - name_len;

                        if (value[0] == '\"') {
                            value++;
                            value_len--;
                        }
                        if (value[value_len-1] == '\"') {
                            value_len--;
                        }
#ifdef ZPRINT
                        zPRINT("VALUE START: ");
                        zPrintRawDataFp(stdout, value, value_len);
                        zPRINT("VALUE END: ");
#endif
                        *retptr = value;
                        *retlen = value_len;
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}


/**
 *  \brief setup multipart parsing: extract boundary and store it
 *
 *  \param d HTTP transaction
 *  \param htud transaction userdata
 *
 *  \retval 1 ok, multipart set up
 *  \retval 0 ok, not multipart though
 *  \retval -1 error: problem with the boundary
 *
 *  If the request contains a multipart message, this function will
 *  set the HTP_BOUNDARY_SET in the transaction.
 */
static int HtpRequestBodySetupMultipart(htp_tx_data_t *d, HtpTxUserData *htud)
{
    htp_header_t *h = (htp_header_t *)htp_table_get_c(d->tx->request_headers,
            "Content-Type");
    if (h != NULL && bstr_len(h->value) > 0) {
        uint8_t *boundary = NULL;
        size_t boundary_len = 0;

        int r = HTTPParseContentTypeHeader((uint8_t *)"boundary=", 9,
                (uint8_t *) bstr_ptr(h->value), bstr_len(h->value),
                &boundary, &boundary_len);
        if (r == 1) {
#ifdef ZPRINT
            zPRINT("BOUNDARY START: ");
            zPrintRawDataFp(stdout, boundary, boundary_len);
            zPRINT("BOUNDARY END: ");
#endif
            if (boundary_len < HTP_BOUNDARY_MAX) {
                htud->boundary = malloc(boundary_len);
                if (htud->boundary == NULL) {
					zLogError("Memory allocate failed");
                    return -1;
                }
                htud->boundary_len = (uint8_t)boundary_len;
                memcpy(htud->boundary, boundary, boundary_len);

				/*****************dt  begin**********************/
				htud->boundary_end= malloc(boundary_len + 2);
                if (htud->boundary_end == NULL) {
					SAFE_FREE(htud->boundary);
					zLogError("Memory allocate failed");
                    return -1;
                }
                htud->boundary_end_len = (uint8_t)boundary_len + 2;
                memcpy(htud->boundary_end, boundary, boundary_len);
				htud->boundary_end[htud->boundary_end_len - 2] = '-';
				htud->boundary_end[htud->boundary_end_len - 1] = '-';
				/*****************dt  end***********************/

                htud->tsflags |= HTP_BOUNDARY_SET;
            } else {
                zLogDebug("invalid boundary");
                return -1;
            }
            return 1;
        }
        //SCReturnInt(1);
    }
    return 0;
}


/** \brief setup things for put request
 *  \todo really needed? */
static int HtpRequestBodySetupPUT(htp_tx_data_t *d, HtpTxUserData *htud) {
//    if (d->tx->parsed_uri == NULL || d->tx->parsed_uri->path == NULL) {
//        return -1;
//    }

    /* filename is d->tx->parsed_uri->path */

    return 0;
}


/**
 *  \param name /Lowercase/ version of the variable name
 */
static int HTTPParseContentDispositionHeader(uint8_t *name, size_t name_len,
        uint8_t *data, size_t len, uint8_t **retptr, size_t *retlen)
{
#ifdef ZPRINT
    zLogDebug("DATA START:");
    zPrintRawDataFp(stdout, data, len);
    zLogDebug("DATA END:");
#endif
    size_t x;
    int quote = 0;

    for (x = 0; x < len; x++) {
        if (!(isspace(data[x])))
            break;
    }

    if (x >= len)
        return 0;

    uint8_t *line = data+x;
    size_t line_len = len-x;
    size_t offset = 0;
#ifdef ZPRINT
    zPRINT("LINE START:");
    zPrintRawDataFp(stdout, line, line_len);
    zPRINT("LINE END:");
#endif
    for (x = 0 ; x < line_len; x++) {
        if (x > 0) {
            if (line[x - 1] != '\\' && line[x] == '\"') {
                quote++;
            }

            if (((line[x - 1] != '\\' && line[x] == ';') || ((x + 1) == line_len)) && (quote == 0 || quote % 2 == 0)) {
                uint8_t *token = line + offset;
                size_t token_len = x - offset;

                if ((x + 1) == line_len) {
                    token_len++;
                }

                offset = x + 1;

                while (offset < line_len && isspace(line[offset])) {
                    x++;
                    offset++;
                }
#ifdef ZPRINT
                zPRINT("TOKEN START:");
                zPrintRawDataFp(stdout, token, token_len);
                zPRINT("TOKEN END:");
#endif
                if (token_len > name_len) {
                    if (name == NULL || SCMemcmpLowercase(name, token, name_len) == 0) {
                        uint8_t *value = token + name_len;
                        size_t value_len = token_len - name_len;

                        if (value[0] == '\"') {
                            value++;
                            value_len--;
                        }
                        if (value[value_len-1] == '\"') {
                            value_len--;
                        }
#ifdef ZPRINT
                        zPRINT("VALUE START:");
                        zPrintRawDataFp(stdout, value, value_len);
                        zPRINT("VALUE END:");
#endif
                        *retptr = value;
                        *retlen = value_len;
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}

#define C_D_HDR "content-disposition:"
#define C_D_HDR_LEN 20
#define C_T_HDR "content-type:"
#define C_T_HDR_LEN 13

static void HtpRequestBodyMultipartParseHeader(HtpState *hstate,
        HtpTxUserData *htud,
        uint8_t *header, uint32_t header_len,
        uint8_t **filename, uint16_t *filename_len,
        uint8_t **filetype, uint16_t *filetype_len)
{
    uint8_t *fn = NULL;
    size_t fn_len = 0;
    uint8_t *ft = NULL;
    size_t ft_len = 0;

#ifdef ZPRINT
    zLogDebug("HEADER START:");
    zPrintRawDataFp(stdout, header, header_len);
    zLogDebug("HEADER END:");
#endif

    while (header_len > 0) {
        uint8_t *next_line = Bs2bmSearch(header, header_len, (uint8_t *)"\r\n", 2);
        uint8_t *line = header;
        uint32_t line_len;

        if (next_line == NULL) {
            line_len = header_len;
        } else {
            line_len = next_line - header;
        }
        uint8_t *sc = (uint8_t *)memchr(line, ':', line_len);
        if (sc == NULL) {
			/*****************dt  begin**********************/
            //HTPSetEvent(hstate, htud,
                    //HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER);
            /*****************dt  end***********************/        
            /* if the : we found is the final char, it means we have
             * no value */
        } else if (line_len > 0 && sc == &line[line_len - 1]) {
			/*****************dt  begin**********************/
            //HTPSetEvent(hstate, htud,
                    //HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER);
            /*****************dt  end***********************/          
        } else {
#ifdef ZPRINT
            zPRINT("LINE START:");
            zPrintRawDataFp(stdout, line, line_len);
            zPRINT("LINE END:");
#endif
            if (line_len >= C_D_HDR_LEN &&
                    SCMemcmpLowercase(C_D_HDR, line, C_D_HDR_LEN) == 0) {
                uint8_t *value = line + C_D_HDR_LEN;
                uint32_t value_len = line_len - C_D_HDR_LEN;

                /* parse content-disposition */
                (void)HTTPParseContentDispositionHeader((uint8_t *)"filename=", 9,
                        value, value_len, &fn, &fn_len);
            } else if (line_len >= C_T_HDR_LEN &&
                    SCMemcmpLowercase(C_T_HDR, line, C_T_HDR_LEN) == 0) {
                SCLogDebug("content-type line");
                uint8_t *value = line + C_T_HDR_LEN;
                uint32_t value_len = line_len - C_T_HDR_LEN;

                (void)HTTPParseContentTypeHeader(NULL, 0,
                        value, value_len, &ft, &ft_len);
            }
        }

        if (next_line == NULL) {
            //SCLogDebug("no next_line");
            break;
        }
        header_len -= ((next_line + 2) - header);
        header = next_line + 2;
    } /* while (header_len > 0) */

    if (fn_len > USHRT_MAX)
        fn_len = USHRT_MAX;
    if (ft_len > USHRT_MAX)
        ft_len = USHRT_MAX;

    *filename = fn;
    *filename_len = fn_len;
    *filetype = ft;
    *filetype_len = ft_len;
}

/**
 *  \brief Create a single buffer from the HtpBodyChunks in our list
 *
 *  \param htud transaction user data
 *  \param chunks_buffers pointer to pass back the buffer to the caller
 *  \param chunks_buffer_len pointer to pass back the buffer length to the caller
 */
static void HtpRequestBodyReassemble(HtpTxUserData *htud,
        uint8_t **chunks_buffer, uint32_t *chunks_buffer_len)
{
	zEnter("Enter");
    uint8_t *buf = NULL;
    uint8_t *pbuf = NULL;
    uint32_t buf_len = 0;
    HtpBodyChunk *cur = htud->request_body.first;

    for ( ; cur != NULL; cur = cur->next) {
        //zLogDebug("chunk %p", cur);

        /* skip body chunks entirely before what we parsed already */
        if ((uint64_t )cur->stream_offset + cur->len <= htud->request_body.body_parsed) {
            //zLogDebug("skipping chunk");
            continue;
        }

        zLogDebug("cur->stream_offset %"PRIu64", cur->len %"PRIu32", body_parsed %"PRIu64,
            cur->stream_offset, cur->len, htud->request_body.body_parsed);

        if (cur->stream_offset < htud->request_body.body_parsed &&
                cur->stream_offset + cur->len >= htud->request_body.body_parsed) {
            zLogDebug("use part");

            uint32_t toff = htud->request_body.body_parsed - cur->stream_offset;
            uint32_t tlen = (cur->stream_offset + cur->len) - htud->request_body.body_parsed;
            uint8_t *pbuf = NULL;

            buf_len += tlen;
            //if ((pbuf = HTPRealloc(buf, buf_len - tlen, buf_len)) == NULL) {
            if ((pbuf = realloc(buf,buf_len)) == NULL) {
				zLogError("memory allocate failed!");
                //HTPFree(buf, buf_len - tlen);
                free(buf);
                buf = NULL;
                buf_len = 0;
                break;
            }
            buf = pbuf;
            memcpy(buf + buf_len - tlen, cur->data + toff, tlen);

        } else {
            zLogDebug("use entire chunk");

            buf_len += cur->len;
            //if ((pbuf = HTPRealloc(buf, buf_len - cur->len, buf_len)) == NULL) {
            if ((pbuf = realloc(buf, buf_len)) == NULL) {
                //HTPFree(buf, buf_len - cur->len);
                free(buf);
                buf = NULL;
                buf_len = 0;
                break;
            }
            buf = pbuf;
            memcpy(buf + buf_len - cur->len, cur->data, cur->len);
        }
    }

    *chunks_buffer = buf;
    *chunks_buffer_len = buf_len;
}

static int HTPCallbackRequestStart(htp_tx_t *tx)
{
	zEnter("Enter,htp_tx_t *tx:%p",tx);
	return HTP_OK;
}


static int HTPCallbackRequestLine(htp_tx_t *tx)
{
	zEnter("Enter,htp_tx_t *tx:%p",tx);
	return HTP_OK;
}

static int HTPCallbackRequestHeaderData(htp_tx_data_t *tx_data)
{
	zEnter("Enter,htp_tx_data_t *tx_data:%p",tx_data);
	
    if (tx_data->len == 0)
        return HTP_OK;

	//zLogDebug("-----------------test begin-----------------------");
	//zPrintRawDataFp(stdout,tx_data->data, tx_data->len);
	//zLogDebug("-----------------test end-------------------------");
	
	return HTP_OK;
}


/**
 *  \brief Setup boundary buffers
 */
static int HtpRequestBodySetupBoundary(HtpTxUserData *htud,
        uint8_t **expected_boundary, uint8_t *expected_boundary_len,
        uint8_t **expected_boundary_end, uint8_t *expected_boundary_end_len)
{
    uint8_t *eb = NULL;
    uint8_t *ebe = NULL;

    uint8_t eb_len = htud->boundary_len + 2;
    eb = (uint8_t *)malloc(eb_len);
    if (eb == NULL) {
        goto error;
    }
    memset(eb, '-', eb_len);
    memcpy(eb + 2, htud->boundary, htud->boundary_len);

    uint8_t ebe_len = htud->boundary_len + 4;
    ebe = (uint8_t *)malloc(ebe_len);
    if (ebe == NULL) {
        goto error;
    }
    memset(ebe, '-', ebe_len);
    memcpy(ebe + 2, htud->boundary, htud->boundary_len);

    *expected_boundary = eb;
    *expected_boundary_len = eb_len;
    *expected_boundary_end = ebe;
    *expected_boundary_end_len = ebe_len;

    SCReturnInt(0);

error:
    if (eb != NULL) {
        HTPFree(eb, eb_len);
    }
    if (ebe != NULL) {
        HTPFree(ebe, ebe_len);
    }
    SCReturnInt(-1);
}


static int HTPStateGetAlstateProgress(void *tx, uint8_t direction)
{
    if (direction & STREAM_TOSERVER)
        return ((htp_tx_t *)tx)->request_progress;
    else
        return ((htp_tx_t *)tx)->response_progress;
}

/*****************dt  begin**********************/

static int ExtractDataFromString(uint8_t *text, uint32_t textlen,uint8_t **find_begin)
{
	int found = 0;
	while(*find_begin <= text + textlen)
	{
		if((*find_begin)[0] == '\r')
		{
			found = 1;	
			break;
		}
		(*find_begin) += 1;
	}
	return found;
}



#define C_D_SIZE   "Content-Disposition: form-data; name=\"size\"\r\n\r\n"
#define C_D_CHUNKS "Content-Disposition: form-data; name=\"chunks\"\r\n\r\n"
#define C_D_CHUNK  "Content-Disposition: form-data; name=\"chunk\"\r\n\r\n"

static void ExtractInformation(uint64_t *val,uint8_t *chunks_buffer, uint32_t chunks_buffer_len,
										uint8_t *info, uint32_t info_len)
{
	uint8_t *buf_begin = NULL;
	uint16_t buf_len = 0;
	buf_begin = Bs2bmSearch(chunks_buffer, chunks_buffer_len,
			info, info_len);
	if(buf_begin != NULL)
	{
		buf_begin += info_len;
		uint8_t *buf_end = buf_begin;
		if(ExtractDataFromString(chunks_buffer,chunks_buffer_len,&buf_end))
		{
			buf_len = buf_end - buf_begin;
			int ret = ConvertString2Uint64(buf_begin,buf_len,val);
			BUG_ON(ret == 0);
			zLogDebug("val is %"PRIu64,*val);
		}
	}

}

/*****************dt  end***********************/

static int HtpRequestBodyHandleMultipart(HtpState *hstate, HtpTxUserData *htud,
                                  void *tx, uint8_t *chunks_buffer, uint32_t chunks_buffer_len,
                                  uint8_t **file_buffer, uint32_t *file_buffer_len)
{
    uint8_t *expected_boundary = NULL;
    uint8_t *expected_boundary_end = NULL;
    uint8_t expected_boundary_len = 0;
    uint8_t expected_boundary_end_len = 0;
    int tx_progress = 0;

#ifdef ZPRINT
    zLogDebug("CHUNK START");
    zPrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    zLogDebug("CHUNK END");
#endif

    if (HtpRequestBodySetupBoundary(htud, &expected_boundary, &expected_boundary_len,
                &expected_boundary_end, &expected_boundary_end_len) < 0) {
        goto end;
    }
	
//#ifdef ZPRINT
    zLogDebug("expected_boundary_end START");
	zLogDebug("expected_boundary_end_len is:%d",expected_boundary_end_len);
    zPrintRawDataFp(stdout, expected_boundary_end, expected_boundary_end_len);
    zLogDebug("expected_boundary_end END");
//#endif

    /* search for the header start, header end and form end */
    uint8_t *header_start = Bs2bmSearch(chunks_buffer, chunks_buffer_len,
            expected_boundary, expected_boundary_len);
    uint8_t *header_end = NULL;
    if (header_start != NULL) {
        header_end = Bs2bmSearch(header_start, chunks_buffer_len - (header_start - chunks_buffer),
                (uint8_t *)"\r\n\r\n", 4);
    }
    uint8_t *form_end = Bs2bmSearch(chunks_buffer, chunks_buffer_len,
            expected_boundary_end, expected_boundary_end_len);

    SCLogDebug("header_start %p, header_end %p, form_end %p", header_start,
            header_end, form_end);

    /* we currently only handle multipart for ts.  When we support it for tc,
     * we will need to supply right direction */

	/*****************dt  begin**********************/
    //tx_progress = AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, STREAM_TOSERVER);
    tx_progress = HTPStateGetAlstateProgress(tx, STREAM_TOSERVER);
	/*****************dt  end***********************/
	
    /* if we're in the file storage process, deal with that now */
    if (htud->tsflags & HTP_FILENAME_SET) {
        if (header_start != NULL || form_end != NULL || (tx_progress > HTP_REQUEST_BODY)) {
            SCLogDebug("reached the end of the file");

            uint8_t *filedata = chunks_buffer;
            uint32_t filedata_len = 0;
            uint8_t flags = 0;

            if (header_start < form_end || (header_start != NULL && form_end == NULL)) {
                filedata_len = header_start - filedata - 2; /* 0d 0a */
            } else if (form_end != NULL && form_end < header_start) {
                filedata_len = form_end - filedata;
            } else if (form_end != NULL && form_end == header_start) {
                filedata_len = form_end - filedata - 2; /* 0d 0a */
            } else if (tx_progress > HTP_RESPONSE_BODY) {
                filedata_len = chunks_buffer_len;
                flags = FILE_TRUNCATED;
            }
			/*****************dt  begin**********************/
			if (filedata_len > chunks_buffer_len) {
            	//HTPSetEvent(hstate, htud,
                        //HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);			
                goto end;
            }
			/*****************dt  end***********************/

			*file_buffer = filedata;
			*file_buffer_len = filedata_len;
//#ifdef ZPRINT
            zLogDebug("FILEDATA (final chunk) START:");
            zPrintRawDataFp(stdout, filedata, filedata_len);
            zLogDebug("FILEDATA (final chunk) END:");
//#endif
            /*****************dt  begin**********************/
            /*if (!(htud->tsflags & HTP_DONTSTORE)) {
                if (HTPFileClose(hstate, filedata, filedata_len, flags,
                            STREAM_TOSERVER) == -1)
                {
                    goto end;
                }
            }*/
			/*****************dt  end***********************/

            htud->tsflags &=~ HTP_FILENAME_SET;

            /* fall through */
        } else {
            SCLogDebug("not yet at the end of the file");

            if (chunks_buffer_len > expected_boundary_end_len) {
                uint8_t *filedata = chunks_buffer;
                uint32_t filedata_len = chunks_buffer_len - expected_boundary_len;
//#ifdef ZPRINT
                zLogDebug("FILEDATA (part) START:");
                zPrintRawDataFp(stdout, filedata, filedata_len);
                zLogDebug("FILEDATA (part) END:");
//#endif
			/*****************dt  begin**********************/
				*file_buffer = filedata;
				*file_buffer_len = filedata_len;

			#if 0
            if (!(htud->tsflags & HTP_DONTSTORE)) {
                    result = HTPFileStoreChunk(hstate, filedata,
                            filedata_len, STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        /* we know for sure we're not storing the file */
                        htud->tsflags |= HTP_DONTSTORE;
                    }
            	}
			#endif
			/*****************dt  end***********************/


                htud->request_body.body_parsed += filedata_len;
            } else {
                SCLogDebug("chunk too small to already process in part");
            }

            goto end;
        }
    }

	/*****************dt  begin**********************/
	//find out the filesize
	ExtractInformation(&htud->filesize,chunks_buffer, chunks_buffer_len,(uint8_t *)C_D_SIZE, strlen(C_D_SIZE));
	//find out the chunks
	ExtractInformation(&htud->chunks,chunks_buffer, chunks_buffer_len,(uint8_t *)C_D_CHUNKS, strlen(C_D_CHUNKS));
	//only there have chunks,and then there have chunk
	if(htud->chunks != 0)
		ExtractInformation(&htud->chunk,chunks_buffer, chunks_buffer_len,(uint8_t *)C_D_CHUNK, strlen(C_D_CHUNK));
	
	/*****************dt  end***********************/

    while (header_start != NULL && header_end != NULL &&
            header_end != form_end &&
            header_start < (chunks_buffer + chunks_buffer_len) &&
            header_end < (chunks_buffer + chunks_buffer_len) &&
            header_start < header_end)
    {
        uint8_t *filename = NULL;
        uint16_t filename_len = 0;
        uint8_t *filetype = NULL;
        uint16_t filetype_len = 0;

        uint32_t header_len = header_end - header_start;
        //SCLogDebug("header_len %u", header_len);
        uint8_t *header = header_start;

        /* skip empty records */
        if (expected_boundary_len == header_len) {
            goto next;
        } else if ((uint32_t)(expected_boundary_len + 2) <= header_len) {
            header_len -= (expected_boundary_len + 2);
            header = header_start + (expected_boundary_len + 2); // + for 0d 0a
        }

        HtpRequestBodyMultipartParseHeader(hstate, htud, header, header_len,
                &filename, &filename_len, &filetype, &filetype_len);

        if (filename != NULL) {
            uint8_t *filedata = NULL;
            uint32_t filedata_len = 0;

			memcpy((void *)htud->filename,filename,filename_len);
			
//#ifdef ZPRINT
			zLogDebug("filename start:");
			zPrintData((uint8_t *)htud->filename, strlen(htud->filename));
			zLogDebug("filename end:");
//#endif

            SCLogDebug("we have a filename");

            htud->tsflags |= HTP_FILENAME_SET;
            htud->tsflags &= ~HTP_DONTSTORE;

            SCLogDebug("header_end %p", header_end);
            SCLogDebug("form_end %p", form_end);

            /* everything until the final boundary is the file */
            if (form_end != NULL) {
                filedata = header_end + 4;
                if (form_end == filedata) {
					/*****************dt  begin**********************/
                    //HTPSetEvent(hstate, htud,
                            //HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA);
                    /*****************dt  end***********************/        
                    goto end;
                } else if (form_end < filedata) {
                	/*****************dt  begin**********************/
                    //HTPSetEvent(hstate, htud,
                            //HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
					/*****************dt  end***********************/		 
					goto end;
                }

                filedata_len = form_end - (header_end + 4 + 2);
                SCLogDebug("filedata_len %"PRIuMAX, (uintmax_t)filedata_len);

                /* or is it? */
                uint8_t *header_next = Bs2bmSearch(filedata, filedata_len,
                        expected_boundary, expected_boundary_len);
                if (header_next != NULL) {
                    filedata_len -= (form_end - header_next);
                }

                if (filedata_len > chunks_buffer_len) {
					/*****************dt  begin**********************/
					//HTPSetEvent(hstate, htud,
                            //HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
					/*****************dt  end***********************/		 
					goto end;
                }
                SCLogDebug("filedata_len %"PRIuMAX, (uintmax_t)filedata_len);
//#ifdef ZPRINT
                zLogDebug("FILEDATA START:");
                zPrintRawDataFp(stdout, filedata, filedata_len);
                zLogDebug("FILEDATA END:");
//#endif
				/*****************dt  begin**********************/
				//a complete req will come here 
				*file_buffer = filedata;
				*file_buffer_len = filedata_len;

				#if 0
                result = HTPFileOpen(hstate, filename, filename_len,
                            filedata, filedata_len, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                if (result == -1) {
                    goto end;
                } else if (result == -2) {
                    htud->tsflags |= HTP_DONTSTORE;
                } else {
                    if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                        goto end;
                    }
                }
				#endif
				/*****************dt  end***********************/
                htud->request_body.body_parsed += (header_end - chunks_buffer);
                htud->tsflags &= ~HTP_FILENAME_SET;
            } else {
                SCLogDebug("chunk doesn't contain form end");

                filedata = header_end + 4;
                filedata_len = chunks_buffer_len - (filedata - chunks_buffer);
                SCLogDebug("filedata_len %u (chunks_buffer_len %u)", filedata_len, chunks_buffer_len);

                if (filedata_len > chunks_buffer_len) {
					/*****************dt  begin**********************/
					//HTPSetEvent(hstate, htud,
                            //HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
					/*****************dt  begin**********************/
                    goto end;
                }
				/*****************dt  begin**********************/
				//confirm that:this code print the first file chunk
				zLogDebug("-----------------test begin-------------------------");
				zLogDebug("----------FIRST FILE DATA CHUNK----------------------");
				*file_buffer = filedata;
				*file_buffer_len = filedata_len;
				zPrintRawDataFp(stdout, filedata, filedata_len);	
				htud->is_file_data_come = HTP_FILEDATA_COME;
				zLogDebug("-----------------test end-------------------------");
				
				
				/*****************dt  begin**********************/
#ifdef ZPRINT
                zPRINT("FILEDATA START:");
                zPrintRawDataFp(stdout, filedata, filedata_len);
                zPRINT("FILEDATA END:");
#endif
                /* form doesn't end in this chunk, but part might. Lets
                 * see if have another coming up */
                uint8_t *header_next = Bs2bmSearch(filedata, filedata_len,
                        expected_boundary, expected_boundary_len);
                SCLogDebug("header_next %p", header_next);
                if (header_next == NULL) {
                    /* no, but we'll handle the file data when we see the
                     * form_end */

                    SCLogDebug("more file data to come");

                    uint32_t offset = (header_end + 4) - chunks_buffer;
                    SCLogDebug("offset %u", offset);
                    htud->request_body.body_parsed += offset;
					/*****************dt  begin**********************/
					#if 0
                    result = HTPFileOpen(hstate, filename, filename_len,
                            NULL, 0, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->tsflags |= HTP_DONTSTORE;
                    }
					#endif
					/*****************dt  begin**********************/
                } else if (header_next - filedata > 2) {
                    filedata_len = header_next - filedata - 2;
                    SCLogDebug("filedata_len %u", filedata_len);
					/*****************dt  begin**********************/
					#if 0
                    result = HTPFileOpen(hstate, filename, filename_len,
                            filedata, filedata_len, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->tsflags |= HTP_DONTSTORE;
                    } else {
                        if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                            goto end;
                        }
                    }
					#endif
					/*****************dt  begin**********************/

                    htud->tsflags &= ~HTP_FILENAME_SET;
                    htud->request_body.body_parsed += (header_end - chunks_buffer);
                }
            }
        }

next:
        SCLogDebug("header_start %p, header_end %p, form_end %p",
                header_start, header_end, form_end);

        /* Search next boundary entry after the start of body */
        uint32_t cursizeread = header_end - chunks_buffer;
        header_start = Bs2bmSearch(header_end + 4,
                chunks_buffer_len - (cursizeread + 4),
                expected_boundary, expected_boundary_len);
        if (header_start != NULL) {
            header_end = Bs2bmSearch(header_end + 4,
                    chunks_buffer_len - (cursizeread + 4),
                    (uint8_t *) "\r\n\r\n", 4);
        }
    }
end:
    if (expected_boundary != NULL) {
        HTPFree(expected_boundary, expected_boundary_len);
    }
    if (expected_boundary_end != NULL) {
        HTPFree(expected_boundary_end, expected_boundary_end_len);
    }

    SCLogDebug("htud->request_body.body_parsed %"PRIu64, htud->request_body.body_parsed);
    return 0;
}

/*****************dt  begin**********************/
#if 0
/*****************dt  end***********************/

/** \internal
 *  \brief Handle POST, no multipart body data
 */
 
static int HtpRequestBodyHandlePOST(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{


    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tsflags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        if (filename != NULL) {
            result = HTPFileOpen(hstate, filename, (uint32_t)filename_len, data, data_len,
                    hstate->transaction_cnt, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tsflags |= HTP_DONTSTORE;
            } else {
                htud->tsflags |= HTP_FILENAME_SET;
                htud->tsflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tsflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->tsflags |= HTP_DONTSTORE;
            }
        }
    }

    return 0;
end:
    return -1;
	
}

/** \internal
 *  \brief Handle PUT body data
 */
static int HtpRequestBodyHandlePUT(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{
    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tsflags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        if (filename != NULL) {
            result = HTPFileOpen(hstate, filename, (uint32_t)filename_len, data, data_len,
                    hstate->transaction_cnt, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tsflags |= HTP_DONTSTORE;
            } else {
                htud->tsflags |= HTP_FILENAME_SET;
                htud->tsflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tsflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->tsflags |= HTP_DONTSTORE;
            }
        }
    }

    return 0;
end:
    return -1;	
}
/*****************dt  begin**********************/
#endif
/*****************dt  end***********************/

#define C_T "Content-Type: "

static uint8_t * SearchFilePosition(HtpChunkBuffer *hcBuf,HtpTxUserData *tx_ud,
										uint8_t *file_buffer,uint32_t file_buffer_len)
{
		BUG_ON(hcBuf == NULL);
		BUG_ON(hcBuf->len == 0);
		BUG_ON(tx_ud == NULL);
		BUG_ON(file_buffer_len == 0);

	    uint8_t *data = hcBuf->data;
	    uint32_t len = hcBuf->len; 
		//first:find out the boundary position in hcBuf->data
		//because the hcBuf->data may have two request or more£¬we should care about that two request may send the same file
		uint8_t * boundary_position = Bs2bmSearch(data,len,
												tx_ud->boundary,tx_ud->boundary_len);

		if(boundary_position == NULL)
		{
			zLogError("can't find the boundary position in hcBuf->data");
			zLogError("boundary is :");
			zPrintRawDataFp(zGetLogFp(),tx_ud->boundary,tx_ud->boundary_len);
			zLogError("hcBuf->data is :");
			zPrintRawDataFp(zGetLogFp(),data, len);
			BUG_ON(boundary_position == NULL);
		}

		//second:find the "Content-Type: " position in chunks_buffer
		//just in case the found file data is outside of the raw file position
		uint8_t * content_type_position = Bs2bmSearch(boundary_position, len - (boundary_position - data),
												(uint8_t *)C_T, strlen(C_T));
		if(content_type_position == NULL)
		{
			zLogError("can't find the Content-Type position in  hcBuf->data");
			zPrintRawDataFp(zGetLogFp(),data, len);
			BUG_ON(content_type_position == NULL);
		}
		
		//third:find out "\r\n\r\n" after "Content-Type"
		uint8_t * content_type_position_end = Bs2bmSearch(content_type_position, len - (content_type_position - data),
                (uint8_t *)"\r\n\r\n", 4);

		if(content_type_position_end == NULL)
		{
			zLogError("can't find the \\r\\n\\r\\n after Content-Type  position in  hcBuf->data");
			zPrintRawDataFp(zGetLogFp(),data, len);
			BUG_ON(content_type_position_end == NULL);
		}
		
		//fourth:find the raw file position
		uint8_t * raw_file_data_position = Bs2bmSearch(content_type_position_end + 4, 
													len - (content_type_position_end - data) - 4,
												file_buffer, file_buffer_len);
		if(raw_file_data_position == NULL)
		{
			zLogError("can't find the raw_file_data_position  position in  hcBuf->data");
			zLogError("file_buffer is :");
			zPrintRawDataFp(zGetLogFp(),file_buffer, file_buffer_len);
			zLogError("hcBuf->data is :");
			zPrintRawDataFp(zGetLogFp(),data, len);
			BUG_ON(raw_file_data_position == NULL);
		}
		return raw_file_data_position;

}


/**
 *  * \brief Function callback to append chunks for Requests
 *   * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 *    * \retval int HTP_OK if all goes well
 *     */
static int HTPCallbackRequestBodyData(htp_tx_data_t *d)
{
	zEnter("Enter,htp_tx_data_t *d:%p",d);
    if (d->data == NULL || d->len == 0)
        return HTP_OK;
	//zPrintRawDataFp(stdout, (uint8_t *)d->data, d->len);

	HtpState *hstate = htp_connp_get_user_data(d->tx->connp);
    if (hstate == NULL) {
		zLogError("HTP_ERROR");
        return HTP_ERROR;
    }

	BUG_ON(hstate->hcBuffer == NULL);
	BUG_ON(hstate->hcBuffer->data == NULL);	
	
	HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (tx_ud == NULL) {
        tx_ud = malloc(sizeof(HtpTxUserData));
        if (tx_ud == NULL)
		{
			zLogError("Memory allocate failed");
        	return HTP_OK;
        }
        memset(tx_ud, 0, sizeof(HtpTxUserData));

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, tx_ud);
    }
/*****************dt  begin**********************/
	//tx_ud->buf = hstate->buf;
	//tx_ud->buf_len = hstate->buf_len;
/*****************dt  end***********************/	
    if (!tx_ud->response_body_init) {
        tx_ud->response_body_init = 1;
        tx_ud->operation = HTP_BODY_REQUEST;

        if (d->tx->request_method_number == HTP_M_POST) {
            zLogDebug("POST");
            int r = HtpRequestBodySetupMultipart(d, tx_ud);
            if (r == 1) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_MULTIPART;
            } else if (r == 0) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_POST;
                zLogError("not multipart");
            }
        } else if (d->tx->request_method_number == HTP_M_PUT) {
            if (HtpRequestBodySetupPUT(d, tx_ud) == 0) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_PUT;
				zLogError("not multipart");
            }
        }
    }

/* within limits, add the body chunk to the state. */

//--------------------------------------------------------------------------------
//--------------------right now,no limits ,added by zhou 20151229-----------------
//--------------------------------------------------------------------------------

    //if (hstate->cfg->->request_body_limit == 0 || tx_ud->request_body.content_len_so_far < hstate->cfg->request_body_limit)
    //{
        uint32_t len = (uint32_t)d->len;
		/*
        if (hstate->cfg->request_body_limit > 0 &&
                (tx_ud->request_body.content_len_so_far + len) > hstate->cfg->request_body_limit)
        {
            len = hstate->cfg->request_body_limit - tx_ud->request_body.content_len_so_far;
            BUG_ON(len > (uint32_t)d->len);
        }
        SCLogDebug("len %u", len);
		*/
        HtpBodyAppendChunk(tx_ud, &tx_ud->request_body, (uint8_t *)d->data, len);

//************************************************************************
//************untill here,change d->data,will change the 
//					original body data

//and after calling HtpBodyAppendChunk,if we have the value:tx_ud->filesize and tx_ud->file_chunk_offset
//we can extract file data from d->data 
		if( 0 != tx_ud->filesize &&
			tx_ud->filesize == tx_ud->file_chunk_offset)
		{
			zLogDebug("file already end");
		}
		
		if(	tx_ud->is_file_data_come == HTP_FILEDATA_COME &&
			tx_ud->filesize > tx_ud->file_chunk_offset)
		{
			if(tx_ud->file_chunk_offset + len < tx_ud->filesize)
			{
				//file data do not end
				zLogDebug("-----------------test begin-------------------------");
				zLogDebug("----------MIDDLE FILE DATA CHUNK----------------------");
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);
				zPrintRawDataFp(stdout,(uint8_t *)d->data, len);	

				//encrypt data here
				zLogDebug("@@@@@@@@@@@@@@@@@ encrypt data here @@@@@@@@@@@@@@@@@");
				uint8_t * td = (uint8_t *)d->data;
				int i;
				for(i = 0;i < len;++i)
				{
					td[i] = 'A';
				}
				
				tx_ud->file_chunk_offset += len;
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);		
				zLogDebug("-----------------test end-------------------------");
			}
			else
			{
				//file data end in this d->data
				zLogDebug("-----------------test begin-------------------------");
				zLogDebug("---------- LAST FILE DATA CHUNK----------------------");
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);
				zPrintRawDataFp(stdout,(uint8_t *)d->data, tx_ud->filesize - tx_ud->file_chunk_offset);	

				//encrypt data here
				zLogDebug("@@@@@@@@@@@@@@@@@ encrypt data here @@@@@@@@@@@@@@@@@");
				uint8_t * td = (uint8_t *)d->data;
				int i;
				for(i = 0;i < tx_ud->filesize - tx_ud->file_chunk_offset;++i)
				{
					td[i] = 'A';
				}
				
				tx_ud->file_chunk_offset = tx_ud->filesize;
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);
				zLogDebug("-----------------test end-------------------------");				
			}

			hstate->hcBuffer->is_ready_to_send = HTP_READY_TO_SEND;
		}

		

//************************************************************************
		
        uint8_t *chunks_buffer = NULL;
        uint32_t chunks_buffer_len = 0;

        if (tx_ud->request_body_type == HTP_BODY_REQUEST_MULTIPART) {
            /* multi-part body handling starts here */
            if (!(tx_ud->tsflags & HTP_BOUNDARY_SET)) {
                goto end;
            }

            HtpRequestBodyReassemble(tx_ud, &chunks_buffer, &chunks_buffer_len);
            if (chunks_buffer == NULL) {
				//*******************************************************
				//when chunks_buffer is NULL,we can sure this is file data?
				//so we can make sure this coming data is part of file?
				//*******************************************************
                goto end;
            }
#ifdef ZPRINT
            zLogDebug("REASSCHUNK START:");
            zPrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
            zLogDebug("REASSCHUNK END:");
#endif

			uint8_t *file_buffer = NULL;
	        uint32_t file_buffer_len = 0;
			
            HtpRequestBodyHandleMultipart(hstate, tx_ud, d->tx, chunks_buffer, chunks_buffer_len,&file_buffer,&file_buffer_len);

			/*****************dt  begin**********************/
			//how many conditions?
			zLogDebug("#################################test begin#################################");
			zLogDebug("file_buffer:%p,file_buffer_len:%d",file_buffer,file_buffer_len);
			zPrintRawDataFp(stdout,file_buffer, file_buffer_len);	
			if(0 != file_buffer_len)
			{
				uint8_t * file_position =  SearchFilePosition(hstate->hcBuffer,tx_ud,file_buffer, file_buffer_len);
				BUG_ON(file_position == NULL);
				zLogDebug("@@@@@@@@@@@@@@@@@ encrypt data here @@@@@@@@@@@@@@@@@");
				//raw_file_data_position += i + 4;
				int j;
				for(j = 0;j < file_buffer_len ;++j)
				{
					file_position[j] = 'A';
				}

				hstate->hcBuffer->is_ready_to_send = HTP_READY_TO_SEND;
				
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);
				tx_ud->file_chunk_offset += file_buffer_len;
				zLogDebug("filesize is %"PRIu64",file_chunk_offset is %"PRIu64,tx_ud->filesize,tx_ud->file_chunk_offset);
			}
			zLogDebug("#################################test end#################################");
			/*****************dt  end************************/


            if (chunks_buffer != NULL) {
                //HTPFree(chunks_buffer, chunks_buffer_len);
                free(chunks_buffer);
            }
        }
		 else if (tx_ud->request_body_type == HTP_BODY_REQUEST_POST) {
		 	zLogFatal("So far,we just use Multipart!");
            //HtpRequestBodyHandlePOST(hstate, tx_ud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
        } else if (tx_ud->request_body_type == HTP_BODY_REQUEST_PUT) {
			 zLogFatal("So far,we just use Multipart!");
            //HtpRequestBodyHandlePUT(hstate, tx_ud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
        }

    //}


//print HtpBody begin
#if 0
	HtpBody *body = &tx_ud->request_body;
	HtpBodyChunk *cur = NULL;
	HtpBodyChunk *prev = NULL;
	prev = body->first;
		
	while (prev != NULL)
	{
		cur = prev->next;
		if (prev->data != NULL)
			zPRINT(prev->data);
		prev = cur;
	}
#endif	
//print HtpBody end

end:
    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(&tx_ud->request_body);
	return HTP_OK;//or HTP_ERROR

}

/**
 *  *  \brief  callback for request to store the recent incoming request
 *              in to the recent_in_tx for the given htp state
 *               *  \param  connp   pointer to the current connection parser which has the htp
 *                *                  state in it as user data
 *                 */
static int HTPCallbackRequest(htp_tx_t *tx) 
{
	zEnter("Enter,htp_tx_t *tx:%p",tx);

	if (tx == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    HtpState *hstate = htp_connp_get_user_data(tx->connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_ERROR);
    }

	BUG_ON(hstate->hcBuffer == NULL);
	BUG_ON(hstate->hcBuffer->data == NULL);
	hstate->hcBuffer->is_ready_to_send = HTP_READY_TO_SEND;

    //SCLogDebug("transaction_cnt %"PRIu64", list_size %"PRIu64,hstate->transaction_cnt, HTPStateGetTxCnt(hstate));

    SCLogDebug("HTTP request completed");


    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        if (htud->tsflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            //(void)HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER);
            htud->tsflags &= ~HTP_FILENAME_SET;
        }
    }
	
	return HTP_OK;
}

static int HTPCallbackResponseLine(htp_tx_t *tx)
{
	zEnter("Enter,htp_tx_t *tx:%p",tx);
	return HTP_OK;
}

static int HTPCallbackResponseHeaderData(htp_tx_data_t *tx_data)
{
	zEnter("Enter,htp_tx_data_t *tx_data:%p",tx_data);
	return HTP_OK;
}


/**
 * \brief Function callback to append chunks for Responses
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HTP_OK if all goes well
 */
static int HTPCallbackResponseBodyData(htp_tx_data_t *d)
{
	zEnter("Enter,htp_tx_data_t *d:%p",d);
	return HTP_OK;
}

/**
 *  \brief  callback for response to remove the recent received requests
            from the recent_in_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackResponse(htp_tx_t *tx) 
{
	zEnter("Enter,htp_tx_t *tx:%p",tx);
	return HTP_OK;
}


static uint64_t HTPStateGetTxCnt(void *alstate)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->conn != NULL)
        return (uint64_t)htp_list_size(http_state->conn->transactions);
    else
        return 0ULL;
}

static void *HTPStateGetTx(void *alstate, uint64_t tx_id)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->conn != NULL)
        return htp_list_get(http_state->conn->transactions, tx_id);
    else
        return NULL;
}

static void HtpTxUserDataFree(HtpTxUserData *htud) {
    if (htud) {
        HtpBodyFree(&htud->request_body);
        HtpBodyFree(&htud->response_body);
        bstr_free(htud->request_uri_normalized);
        if (htud->request_headers_raw)
            HTPFree(htud->request_headers_raw, htud->request_headers_raw_len);
        if (htud->response_headers_raw)
            HTPFree(htud->response_headers_raw, htud->response_headers_raw_len);
        //AppLayerDecoderEventsFreeEvents(&htud->decoder_events);
        if (htud->boundary)
            HTPFree(htud->boundary, htud->boundary_len);
/*****************dt  begin**********************/
		if (htud->boundary_end)
			SAFE_FREE(htud->boundary_end);	
/*****************dt  end***********************/		
        HTPFree(htud, sizeof(HtpTxUserData));
    }
}




/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void)
{

    HtpState *s = malloc(sizeof(HtpState));
    if (s == NULL)
        goto error;

    memset(s, 0x00, sizeof(HtpState));

    return((void *)s);

error:
    if (s != NULL) {
        free(s);
    }

    return NULL;
}

int DTInitHTTP()
{
	if(NULL != g_cfg)
		return 0;

	g_cfg = htp_config_create();
	if(NULL == g_cfg)
	{
		zLogFatal("memory allocate failed!");
		return -1;
	}	
	
	htp_config_register_request_start(g_cfg, HTPCallbackRequestStart);
	htp_config_register_request_line(g_cfg, HTPCallbackRequestLine);
	htp_config_register_request_header_data(g_cfg, HTPCallbackRequestHeaderData);
	htp_config_register_request_trailer_data(g_cfg, HTPCallbackRequestHeaderData);
	htp_config_register_request_body_data(g_cfg, HTPCallbackRequestBodyData);
	htp_config_register_request_complete(g_cfg, HTPCallbackRequest);
	
	htp_config_register_response_line(g_cfg, HTPCallbackResponseLine);
    htp_config_register_response_header_data(g_cfg, HTPCallbackResponseHeaderData);
    htp_config_register_response_trailer_data(g_cfg, HTPCallbackResponseHeaderData);
	htp_config_register_response_body_data(g_cfg, HTPCallbackResponseBodyData);
	htp_config_register_response_complete(g_cfg, HTPCallbackResponse);

	
	/* don't convert + to space by default */
	htp_config_set_plusspace_decode(g_cfg, HTP_DECODER_URLENCODED, 0);	
	return 0;
}

int DTRequestData(stSocketInput *stsi)
{
	zEnter("Enter");
	BUG_ON(g_cfg == NULL);
	BUG_ON(stsi == NULL);

	if(NULL == stsi->buf || 0 == stsi->buf_len)
		return 0;
	//zPrintRawDataFp(stdout, stsi->buf, stsi->buf_len);
	//zLogDebug("%s",stsi->buf);
	
	int r = -1;

	HtpState *hstate = (HtpState *)stsi->htp_state;
	if(hstate == NULL)
	{
		hstate = (HtpState *)HTPStateAlloc();
		if(hstate == NULL)
		{
			zLogFatal("memory allocate failed!");
			return -1;
		}

		hstate->connp = htp_connp_create(g_cfg);
		if (hstate->connp == NULL)
		{
			SAFE_FREE(hstate);
			zLogFatal("memory allocate failed!");
			return -1;
		}

		hstate->conn = htp_connp_get_connection(hstate->connp);
        htp_connp_set_user_data(hstate->connp, (void *)hstate);
		
		stsi->htp_state = hstate;
	}
	//htp_conn_t * conn = htp_connp_get_connection(connp);
	BUG_ON(hstate == NULL);

	if(NULL == hstate->hcBuffer)
	{
		 HtpChunkBuffer *hcb = (HtpChunkBuffer *)malloc(sizeof(HtpChunkBuffer));
		 if(hcb == NULL)
		 {
		 	zLogFatal("memory allocate failed!");
			return -1;
		 }
		 memset(hcb, 0x00, sizeof(HtpChunkBuffer));
		 hcb->len = stsi->buf_len;
		 hcb->data = malloc(stsi->buf_len);
        if (hcb->data == NULL) {
			SAFE_FREE(hcb);
            zLogFatal("memory allocate failed!");
			return -1;
        }
        memcpy(hcb->data, stsi->buf, stsi->buf_len);
		hstate->hcBuffer = hcb;
	}
	else
	{
		uint8_t *buf = hstate->hcBuffer->data;
	    uint8_t *pbuf = NULL;
		uint32_t buf_len = hstate->hcBuffer->len;
        if ((pbuf = realloc(buf,buf_len + stsi->buf_len)) == NULL) 
		{
            zLogFatal("memory allocate failed!");
			return -1;
        }
        buf = pbuf;
        memcpy(buf + buf_len, stsi->buf, stsi->buf_len);
		hstate->hcBuffer->data = buf;
		hstate->hcBuffer->len += stsi->buf_len;
	}

	BUG_ON(hstate->hcBuffer->data == NULL);
	BUG_ON(hstate->hcBuffer->len == 0);

	
	htp_time_t ts = { zGetTimestamp(), 0 };

	zLogDebug("-----------------test begin-----------------------");
	zLogDebug("hstate->hcBuffer->data:%p,hstate->hcBuffer->len:%d",hstate->hcBuffer->data,hstate->hcBuffer->len);
	zPrintData(hstate->hcBuffer->data, hstate->hcBuffer->len);
	zLogDebug("-----------------test end-------------------------");

	//*************************************************
	//whether need a flag to sign that is it input data have bee send?
	//*************************************************	
    /* pass the new data to the htp parser */
    r = htp_connp_req_data(hstate->connp, &ts, hstate->hcBuffer->data + (hstate->hcBuffer->len - stsi->buf_len) , stsi->buf_len);

	if(hstate->hcBuffer->is_ready_to_send == HTP_READY_TO_SEND)
	{
		zLogDebug("@@@@@@@@@@@@@@@ send it now @@@@@@@@@@@@@@@");
		zLogDebug("hstate->hcBuffer->data:%p,hstate->hcBuffer->len:%d",hstate->hcBuffer->data,hstate->hcBuffer->len);
		zPrintData(hstate->hcBuffer->data, hstate->hcBuffer->len);
		
		hstate->hcBuffer->is_ready_to_send = 0;
		SAFE_FREE(hstate->hcBuffer->data);
		SAFE_FREE(hstate->hcBuffer);
	}
	else
		zLogDebug("@@@@@@@@@@@@@@@ is not ready to send @@@@@@@@@@@@@@@");
	

	zLogDebug("htp_connp_req_data return value:%d",r);
	return 0;
}

int DTResponseData(stSocketInput *stsi)
{
	zEnter("Enter");

	BUG_ON(stsi == NULL);
	int r = -1;

	HtpState *hstate = (HtpState *)stsi->htp_state;
	if(hstate == NULL)
	{
		zLogError("Have no connp");
		return -1;
	}
	
	htp_connp_t *connp = (htp_connp_t*)hstate->connp;
	if (connp == NULL)
	{
		zLogError("Have no connp");
		return -1;
	}
	htp_time_t ts = { zGetTimestamp(), 0 };
	r = htp_connp_res_data(connp, &ts, stsi->buf, stsi->buf_len);
	
	zLogDebug("htp_connp_res_data return value:%d",r);
	return 0;
}

int DTFreeHTTPState(void *stsi)
{
	zEnter("Enter");

	stSocketInput *st = stsi;
	if(NULL == st)
	{
		zLogDebug("stsi is NULL!");
		return 0;
	}

	HtpState *s = (HtpState *)st->htp_state;
    if (s == NULL) {
        return 0;
    }

	/* Unset the body inspection */
	s->flags &=~ HTP_FLAG_NEW_BODY_SET;
	
    if (s->connp != NULL)
	{
        zLogDebug("freeing HTP state");
		
        uint64_t tx_id;
        uint64_t total_txs = HTPStateGetTxCnt(s);
        // free the list of body chunks
        if (s->conn != NULL) 
		{
            for (tx_id = 0; tx_id < total_txs; tx_id++)
			{
                htp_tx_t *tx = HTPStateGetTx(s, tx_id);
                if (tx != NULL)
				{
                    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
                    if (htud != NULL)
					{
                        HtpTxUserDataFree(htud);
                        htp_tx_set_user_data(tx, NULL);
                    }
                }
            }
        }
        
        htp_connp_destroy_all(s->connp);
    }
	
	if(s->hcBuffer)
	{
		SAFE_FREE(s->hcBuffer->data);
		SAFE_FREE(s->hcBuffer);
	}
	
    FileContainerFree(s->files_ts);
    FileContainerFree(s->files_tc);
    free(s);
	st->htp_state = NULL;
	
	return 0;
}

