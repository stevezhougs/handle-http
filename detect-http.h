#ifndef __DETECT_HTTP_H__
#define __DETECT_HTTP_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <htp/htp.h>
#include "util-file.h"



#define STREAM_START            0x01
#define STREAM_EOF              0x02
#define STREAM_TOSERVER         0x04
#define STREAM_TOCLIENT         0x08
#define STREAM_GAP              0x10    /* data gap encountered */
#define STREAM_DEPTH            0x20    /* depth reached */


/** a boundary should be smaller in size */
#define HTP_BOUNDARY_MAX                            200U

#define HTP_FLAG_STATE_OPEN         0x0001    /**< Flag to indicate that HTTP
                                             connection is open */
#define HTP_FLAG_STATE_CLOSED_TS    0x0002    /**< Flag to indicate that HTTP
                                             connection is closed */
#define HTP_FLAG_STATE_CLOSED_TC    0x0004    /**< Flag to indicate that HTTP
                                             connection is closed */
#define HTP_FLAG_STATE_DATA         0x0008    /**< Flag to indicate that HTTP
                                             connection needs more data */
#define HTP_FLAG_STATE_ERROR        0x0010    /**< Flag to indicate that an error
                                             has been occured on HTTP
                                             connection */
#define HTP_FLAG_NEW_BODY_SET       0x0020    /**< Flag to indicate that HTTP
                                             has parsed a new body (for
                                             pcre) */
                                             

enum {
    HTP_BODY_NONE = 0,                  /**< Flag to indicate the current
                                             operation */
    HTP_BODY_REQUEST,                   /**< Flag to indicate that the
                                             current operation is a request */
    HTP_BODY_RESPONSE                   /**< Flag to indicate that the current
                                          * operation is a response */
};

enum {
    HTP_BODY_REQUEST_NONE = 0,
    HTP_BODY_REQUEST_MULTIPART, /* POST, MP */
    HTP_BODY_REQUEST_POST,      /* POST, no MP */
    HTP_BODY_REQUEST_PUT,
};

#define HTP_READY_TO_SEND       0x01    /**< ready to send this buffer */

/*****************dt  begin**********************/
/** Struct used to hold chunks of a whole request */
struct HtpChunkBuffer_ {
    uint8_t *data;              /**< Pointer to the data of the chunk */
    uint32_t len; 				/**< Length of the chunk */
	int is_ready_to_send;
};
typedef struct HtpChunkBuffer_ HtpChunkBuffer;
/*****************dt  end***********************/


/** Need a linked list in order to keep track of these */
typedef struct HTPCfgRec_ {
    htp_cfg_t           *cfg;
    struct HTPCfgRec_   *next;

    int                 uri_include_all; /**< use all info in uri (bool) */

    /** max size of the client body we inspect */
    uint32_t            request_body_limit;
    uint32_t            response_body_limit;

    uint32_t            request_inspect_min_size;
    uint32_t            request_inspect_window;

    uint32_t            response_inspect_min_size;
    uint32_t            response_inspect_window;
    int                 randomize;
    int                 randomize_range;
} HTPCfgRec;


/** Struct used to hold chunks of a body on a request */
struct HtpBodyChunk_ {
    uint8_t *data;              /**< Pointer to the data of the chunk */
    struct HtpBodyChunk_ *next; /**< Pointer to the next chunk */
    uint64_t stream_offset;
    uint32_t len;               /**< Length of the chunk */
} __attribute__((__packed__));
typedef struct HtpBodyChunk_ HtpBodyChunk;

/** Struct used to hold all the chunks of a body on a request */
typedef struct HtpBody_ {
    HtpBodyChunk *first; /**< Pointer to the first chunk */
    HtpBodyChunk *last;  /**< Pointer to the last chunk */

    /* Holds the length of the htp request body seen so far */
    uint64_t content_len_so_far;
    /* parser tracker */
    uint64_t body_parsed;
    /* inspection tracker */
    uint64_t body_inspected;
} HtpBody;

#define HTP_CONTENTTYPE_SET     0x01    /**< We have the content type */
#define HTP_BOUNDARY_SET        0x02    /**< We have a boundary string */
#define HTP_BOUNDARY_OPEN       0x04    /**< We have a boundary string */
#define HTP_FILENAME_SET        0x08   /**< filename is registered in the flow */
#define HTP_DONTSTORE           0x10    /**< not storing this file */

#define HTP_FILEDATA_COME       0x01    /**< file data is come */

/** Now the Body Chunks will be stored per transaction, at
  * the tx user data */
typedef struct HtpTxUserData_ {
    /* Body of the request (if any) */
    uint8_t request_body_init;
    uint8_t response_body_init;
    HtpBody request_body;
    HtpBody response_body;

    bstr *request_uri_normalized;

    uint8_t *request_headers_raw;
    uint8_t *response_headers_raw;
    uint32_t request_headers_raw_len;
    uint32_t response_headers_raw_len;

    //AppLayerDecoderEvents *decoder_events;          /**< per tx events */

    /** Holds the boundary identificator string if any (used on
     *  multipart/form-data only)
     */
    uint8_t *boundary;
    uint8_t boundary_len;
	
	/*****************dt  begin**********************/
	uint8_t *boundary_end;
    uint8_t boundary_end_len;

	char filename[NAME_MAX];

	uint64_t filesize;//the whole file size,not this chunk file size

	uint64_t file_chunk_offset;//this chunk file offset, default to be 0
			
	uint64_t chunks;//total chunks,if chunks == 0,it means no other chunks

	uint64_t chunk;//this chunk number

	int is_file_data_come;
	/*****************dt  end***********************/

    uint8_t tsflags;
    uint8_t tcflags;

    int16_t operation;

    uint8_t request_body_type;
    uint8_t response_body_type;

} HtpTxUserData;


typedef struct HtpState_ {

    /* Connection parser structure for each connection */
    htp_connp_t *connp;
    /* Connection structure for each connection */
    htp_conn_t *conn;
    //Flow *f;                /**< Needed to retrieve the original flow when usin HTPLib callbacks */
    uint64_t transaction_cnt;
    uint64_t store_tx_id;
    FileContainer *files_ts;
    FileContainer *files_tc;
    struct HTPCfgRec_ *cfg;
    uint16_t flags;
    //uint16_t events;
    uint16_t htp_messages_offset; /**< offset into conn->messages list */
	
	/*****************dt  begin**********************/
	HtpChunkBuffer *hcBuffer;
	/*****************dt  end***********************/

} HtpState;

#ifdef	__cplusplus
}
#endif

#endif
