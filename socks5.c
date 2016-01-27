/**
*
*thanks to isayme
*Email : isaymeorg@gmail.com
*Blog  : www.isayme.org 
*https://github.com/isayme/socks5
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <fcntl.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>

//#include "defs.h"
//#include "liblog.h"
#include "socks5.h"

/*****************dt  begin**********************/
#include "log.h"
#include "handle-http-data.h"
#include "util-hash.h"
//#include <glib.h>
/*
#include <stddef.h>
#define container_of(ptr, type, member) ({	    \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})
*/
/*****************dt  end**********************/

//#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

static socks5_cfg_t g_cfg = {0};
struct ev_loop *g_loop = NULL;
struct ev_io g_io_accept;

static void help();
static int32_t check_para(int argc, char **argv);
static void signal_func(int sig);
static void signal_init();

static int32_t socks5_srv_init(uint16_t port, int32_t backlog);
static int32_t socks5_srv_exit();

static int32_t socks5_sockset(int sockfd);

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void read_cb_client(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void read_cb_remote(struct ev_loop *loop, struct ev_io *watcher, int revents);

/*****************dt  begin**********************/
#if 0
struct my_io{
   ev_io *c_io;
   ev_io *s_io;
   uint64_t number;
   int count_free;
   stSocketInput *ssInput;
   struct my_io *_next;
};
struct my_io g_my_io;

uint64_t number_total = 0;
#endif

//HashTable
HashTable *g_ht_io = NULL;
struct st_io
{
   ev_io *c_io;//client
   ev_io *s_io;//server
   int count_free;//when count_free == 0,free this st_io
   stSocketInput *ssInput;
};

uint32_t IOHashTableHash(HashTable *ht, void *data, uint16_t datalen) 
{
	uint8_t *d;
	if(1 == datalen)
	{
		d = (uint8_t *)data;
	}	
	else
	{
		struct st_io *stio = (struct st_io *)data;
		d = (uint8_t *)stio->s_io;
	}

	uint32_t hash = (uint32_t)((uint64_t)d % ht->array_size);
	//hash %= ht->array_size;
	return hash;
}


char IOHashTableCompare(void *data1, uint16_t len1, void *data2, uint16_t len2) 
{
	zEnter("Enter");	
    if (len1 == 0 || len2 == 0)
        return 0;

    struct st_io *t_io = (struct st_io *)data1;
    ev_io *c_io = (ev_io *)data2;
	if(c_io == t_io->c_io || c_io == t_io->s_io)
	    return 1;

	return 0;
}

static void IOHashTableFree(void *p)
{
    zEnter("Enter");

	struct st_io *io = (struct st_io *)p;
	if(io == NULL)return;	
	DTFreeHTTPState(io->ssInput);
	SAFE_FREE(io->ssInput);
	SAFE_FREE(io);	
}

static struct st_io* get_new_io()
{
	struct st_io *t_io = (struct st_io*)calloc(1,sizeof(struct st_io));
	if(NULL == t_io)
	{
		zLogDebug("t_io memory allocate failed!");
		return NULL;
	}
	stSocketInput *ssInput = (stSocketInput *)calloc(1,sizeof(stSocketInput));
	if(NULL == ssInput)
	{
		zLogDebug("ssInput memory allocate failed!");
		SAFE_FREE(t_io);
		return NULL;
	}
	t_io->ssInput = ssInput;
	t_io->count_free = 2;
	return t_io;
}

static FILE* g_fp = NULL;

/*****************dt  end***********************/

int main(int argc, char **argv) {
    if (-1 == check_para(argc, argv)) {
        printf("check argument error.\n");
        return -1;
    }
	/*****************dt  begin**********************/
	if(0 == zLogInit())	
	{
		printf("zLogInit failed!\n");
		exit(1);
	}
	zLogDebug("Start");

	if (-1 == DTInitHTTP())
	{
		zLogDebug("DTInitHTTP failed!\n");
		zLogShutdown();
		exit(1);
	}	

	g_fp = fopen("request.log","a+");
	if(NULL == g_fp)
	{
		printf("open request.log failed\n");
		exit(1);
	}
	/*****************dt  end***********************/

    signal_init();

    zLogInfo("socks5 starting, port: %d\n", g_cfg.port);

	//HashTable
	g_ht_io = HashTableInit(65536, IOHashTableHash, IOHashTableCompare, IOHashTableFree);
	BUG_ON(g_ht_io == NULL);

#if 0
	memset(&g_my_io,0,sizeof(struct my_io));
	stSocketInput *ssInput = (stSocketInput *)malloc(sizeof(stSocketInput));
	if(NULL == ssInput)
	{
		zLogError("malloc error");
		return -1;
	}
	memset(ssInput,0,sizeof(stSocketInput));
	g_my_io.ssInput = ssInput;
#endif

    g_cfg.fd = socks5_srv_init(g_cfg.port, 10);
    if (-1 == g_cfg.fd) {
        zLogError("socks server init error");
        return -1;
    }

    g_cfg.state = SOCKS5_STATE_RUNNING;

    g_loop = ev_default_loop(0);

    ev_io_init(&g_io_accept, accept_cb, g_cfg.fd, EV_READ);
    ev_io_start(g_loop, &g_io_accept);

    ev_loop(g_loop, 0);

    zLogInfo("time to exit.\n");
    socks5_srv_exit();
    zLogInfo("exit socket server.\n");

	/*****************dt  begin**********************/
	zLogInfo("Exit");
	zLogShutdown();	
	/*****************dt  end***********************/	
    return 0;
}

static void help() {
    printf("Usage: socks5 [options]\n");
    printf("Options:\n");
    printf("    -p <port>       tcp listen port\n");
    printf("    -d <Y|y>        run as a daemon if 'Y' or 'y', otherwise not\n");

    printf("    -l <level>      debug log level,range [0, 5]\n");
    printf("    -h              print help information\n");
}

static int32_t check_para(int argc, char **argv) {
    int ch;
    int32_t bdaemon = 0;

    memset(&g_cfg, 0, sizeof(g_cfg));

    g_cfg.start_time = time(NULL);
    g_cfg.port = SOCKS5_PORT;
    g_cfg.state = SOCKS5_STATE_PREPARE;

    while ((ch = getopt(argc, argv, ":d:p:l:h")) != -1) {
        switch (ch) {
            case 'd':
                if (1 == strlen(optarg) && ('Y' == optarg[0] || 'y' == optarg[0])) {
                    printf("run as a daemon.\n");
                    bdaemon = 1;
                }
                break;
            case 'p':
                g_cfg.port = atoi(optarg);
                break;
            case 'l':
                if (0 > atoi(optarg) || 5 < atoi(optarg)) {
                    printf("debug level [%s] out of range [0 - 5].\n", optarg);
                    return -1;
                }
                //liblog_level(atoi(optarg));
                printf("log level [%d].\n", atoi(optarg));
                break;
            case 'h':
                help();
                exit(EXIT_SUCCESS);
                break;
            case '?':
                if (isprint(optopt)) {
                   printf("unknown option '-%c'.\n", optopt);
                } else {
                   printf("unknown option character '\\x%x'.\n", optopt);
                }
                break;
            case ':':
                if (isprint(optopt)) {
                   printf("missing argment for '-%c'.\n", optopt);
                } else {
                   printf("missing argment for '\\x%x'.\n", optopt);
                }
            default:
                break;
        }
    }

    if (bdaemon) {
        daemon(1, 1);
    }

    return 0;
}

static void signal_init() {
    int sig;

    // Ctrl + C
    sig = SIGINT;
    if (SIG_ERR == signal(sig, signal_func)) {
        zLogWarn("signal[%d] failed.",sig);
    }

    // kill/pkill -15
    sig = SIGTERM;
    if (SIG_ERR == signal(sig, signal_func)) {
        zLogWarn("signal[%d] failed.",sig);
    }
}

// signal callback
static void signal_func(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            ev_io_stop(g_loop, &g_io_accept);
            ev_break(g_loop, EVBREAK_ALL);
            //if (NULL != g_loop) ev_unloop(g_loop, EVUNLOOP_ALL);
            g_cfg.state = SOCKS5_STATE_STOP;
            zLogInfo("signal [%d], exit.", sig);
            exit(0);
            break;
        default:
            zLogInfo("signal [%d], not supported.", sig);
            break;
    }
}

static int32_t socks5_srv_init(uint16_t port, int32_t backlog) {
    struct sockaddr_in serv;
    int sockfd;
    int opt;
    int flags;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        zLogError("socket error!");
        return -1;
    }

    bzero((char *)&serv, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(port);

    if (-1 == (flags = fcntl(sockfd, F_GETFL, 0))) {
        flags = 0;
    }
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    opt = 1;
    if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (uint *)&opt, sizeof(opt))) {
        zLogError("setsockopt SO_REUSEADDR fail.");
        return -1;
    }

#ifdef SO_NOSIGPIPE
    if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt))) {
        zLogError("setsockopt SO_NOSIGPIPE fail.");
        return -1;
    }
#endif

    if (bind(sockfd, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        zLogError("bind error [%d]", errno);
        return -1;
    }

    if (listen(sockfd, backlog) < 0) {
        zLogError("listen error!");
        return -1;
    }

    return sockfd;
}

static int32_t socks5_srv_exit() {
    return close(g_cfg.fd);
}

static int32_t socks5_sockset(int sockfd) {
    struct timeval tmo = {0};
    int opt = 1;

    tmo.tv_sec = 5;
    tmo.tv_usec = 0;
    if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof(tmo)) \
        || -1 == setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tmo, sizeof(tmo))) {
         zLogError("setsockopt error.");
         return -1;
    }

#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (uint *)&opt, sizeof(opt))) {
        zLogError("setsockopt SO_REUSEADDR fail.");
        return -1;
    }

    return 0;
}

/*****************dt  begin**********************/

#define log_action	printf
void dump_addr(int level, void *pAddr, char *title)
{
	return;
	char buf[128]={0};
	char xb[128]={0};
	struct sockaddr_in *addr = (struct sockaddr_in *)pAddr;

	log_action( "begin dumping address %s\n", title);
	inet_ntop(addr->sin_family, &(addr->sin_addr), buf, 128);
	sprintf(xb, "IP address %s port %d", buf, ntohs(addr->sin_port));
	log_action( "%s\n", xb);
	log_action("end dumping %s\n", title);
}
/*****************dt  end***********************/


static int32_t socks5_auth(int sockfd) {
	//printf("socks5_auth enter\n");
    int remote = 0;
    char buff[BUFFER_SIZE];
    struct sockaddr_in addr;
    int addr_len;
    int ret;

    socks5_sockset(sockfd);

    // VERSION and METHODS
    if (-1 == recv(sockfd, buff, 2, 0)) GOTO_ERR;
    if (SOCKS5_VERSION != ((socks5_method_req_t *)buff)->ver) GOTO_ERR;
    ret = ((socks5_method_req_t *)buff)->nmethods;
    if (-1 == recv(sockfd, buff, ret, 0)) GOTO_ERR;

    // no auth
    memcpy(buff, "\x05\x00", 2);
    if (-1 == send(sockfd, buff, 2, 0)) GOTO_ERR;

    // REQUEST and REPLY
    if (-1 == recv(sockfd, buff, 4, 0)) GOTO_ERR;

    if (SOCKS5_VERSION != ((socks5_request_t *)buff)->ver
        || SOCKS5_CMD_CONNECT != ((socks5_request_t *)buff)->cmd) {
        zLogDebug("ver : %d\tcmd = %d.", \
            ((socks5_request_t *)buff)->ver, ((socks5_request_t *)buff)->cmd);

        ((socks5_response_t *)buff)->ver = SOCKS5_VERSION;
        ((socks5_response_t *)buff)->cmd = SOCKS5_RESPONSE_COMMAND_NOT_SUPPORTED;
        ((socks5_response_t *)buff)->rsv = 0;

        // cmd not supported
        send(sockfd, buff, 4, 0);
        goto _err;
    }

    if (SOSKC5_ADDRTYPE_IPV4 == ((socks5_request_t *)buff)->addrtype) {
        bzero((char *)&addr, sizeof(addr));
        addr.sin_family = AF_INET;

        if (-1 == recv(sockfd, buff, 4, 0)) GOTO_ERR;
        memcpy(&(addr.sin_addr.s_addr), buff, 4);
        if (-1 == recv(sockfd, buff, 2, 0)) GOTO_ERR;
        memcpy(&(addr.sin_port), buff, 2);

        zLogDebug("type : IP, %s:%d.\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
    } else if (SOSKC5_ADDRTYPE_DOMAIN == ((socks5_request_t *)buff)->addrtype) {
        struct hostent *hptr;

        bzero((char *)&addr, sizeof(addr));
        addr.sin_family = AF_INET;

        if (-1 == recv(sockfd, buff, 1, 0)) GOTO_ERR;
        ret = buff[0];
        buff[ret] = 0;
        if (-1 == recv(sockfd, buff, ret, 0)) GOTO_ERR;
        hptr = gethostbyname(buff);
        zLogDebug("type : domain [%s].", buff);

        if (NULL == hptr) GOTO_ERR;
        if (AF_INET != hptr->h_addrtype) GOTO_ERR;
        if (NULL == *(hptr->h_addr_list)) GOTO_ERR;
        memcpy(&(addr.sin_addr.s_addr), *(hptr->h_addr_list), 4);

        if (-1 == recv(sockfd, buff, 2, 0)) GOTO_ERR;
        memcpy(&(addr.sin_port), buff, 2);
    } else {
        ((socks5_response_t *)buff)->ver = SOCKS5_VERSION;
        ((socks5_response_t *)buff)->cmd = SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED;
        ((socks5_response_t *)buff)->rsv = 0;

        // cmd not supported
        send(sockfd, buff, 4, 0);
        GOTO_ERR;
    }

    if ((remote = socket(AF_INET, SOCK_STREAM, 0)) < 0) GOTO_ERR;
    socks5_sockset(remote);

	//dump_addr(1, &addr, "connecting to ");
    if (0 > connect(remote, (struct sockaddr *)&addr, sizeof(addr))) {
		dump_addr(1, &addr, "connecting faild");
			
        zLogDebug("connect error.");	
		perror("can't connect!");

        memcpy(buff, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10);
        send(sockfd, buff, 4, 0);

        goto _err;
    }
	//dump_addr(1, &addr, "connected ");
    addr_len = sizeof(addr);
    if (0 > getpeername(remote, (struct sockaddr *)&addr, (socklen_t *)&addr_len)) GOTO_ERR;
    // reply remote address info
    memcpy(buff, "\x05\x00\x00\x01", 4);
    memcpy(buff + 4, &(addr.sin_addr.s_addr), 4);
    memcpy(buff + 8, &(addr.sin_port), 2);
    send(sockfd, buff, 10, 0);

    zLogDebug("auth ok.\n");
	//printf("socks5_auth end\n");
    return remote;

_err:
    if (0 != remote) close(remote);
	//printf("socks5_auth end with err\n");
    return -1;
}


/*****************dt  begin**********************/
#if 0
static struct my_io * get_insert_position()
{
	if(g_my_io.c_io == NULL && g_my_io.s_io)
		return &g_my_io;

	struct my_io *temp = &g_my_io;
	while(temp->_next != NULL)
		temp = temp->_next;
	
	struct my_io *t_my_io = (struct my_io*)malloc(sizeof(struct my_io));
	if(NULL == t_my_io)
	{
		printf("t_my_io memory allocate failed!\n");
		return NULL;
	}
	memset(t_my_io,0,sizeof(struct my_io));
	stSocketInput *ssInput = (stSocketInput *)malloc(sizeof(stSocketInput));
	if(NULL == ssInput)
	{
		printf("ssInput memory allocate failed!\n");
		SAFE_FREE(t_my_io);
		return NULL;
	}
	memset(ssInput,0,sizeof(stSocketInput));
	t_my_io->ssInput = ssInput;
	temp->_next = t_my_io;
	t_my_io->count_free = 2;
	//printf("get_insert_position %p ok\n",t_my_io);
	return t_my_io;
}
static struct my_io * find_my_io(struct ev_io * fm)
{
	struct my_io *temp = &g_my_io;
	while(temp->c_io != fm && temp->s_io != fm)
	{
		temp = temp->_next;	
	}	
	//printf("find ev_io * fm %p ok\n",temp);
	return temp;
}

static int free_my_io(struct my_io * fm)
{
	if(fm == NULL) 
			return 1;
	struct my_io *temp = &g_my_io;
	struct my_io *f_temp = temp;
	while(temp->number != fm->number)
	{
		f_temp = temp;
		temp = f_temp->_next;	
	}	
	if(temp == NULL || temp == &g_my_io)
	{
		if(temp == &g_my_io)
		{
			temp->c_io = NULL;
			temp->s_io = NULL;
		}
		return 1;
	}
	f_temp->_next = temp->_next;
	SAFE_FREE(temp->ssInput);
	SAFE_FREE(temp);
	//printf("free ok\n");
	return 1;
}

uint64_t get_number_total()
{
	number_total = (number_total < 999999999) ? number_total : 0;
	return number_total++;
}
#endif
/*****************dt  end***********************/

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = 0;
    int remote_fd;

    if (EV_ERROR & revents) {
        zLogError("error event in accept.");
        return;
    }

    struct ev_io *w_client = (struct ev_io*)malloc(sizeof(struct ev_io));
    struct ev_io *w_serv = (struct ev_io*)malloc(sizeof(struct ev_io));
    if (NULL == w_client || NULL == w_serv) {
        zLogError("apply memory error.");

        if (w_client) free(w_client);
        if (w_serv) free(w_serv);
        return;
    }


    client_fd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        free(w_client);
        free(w_serv);
        return;
    }

    if (-1 == (remote_fd = socks5_auth(client_fd))) {
        zLogError("auth error.");
        close(client_fd);
        free(w_client);
        free(w_serv);
        return;
    }

    w_client->data = w_serv;
	w_serv->data = w_client;
	/*****************dt  begin**********************/
#if 0	
	struct my_io *insert_io = get_insert_position();
	if(NULL != insert_io){
		insert_io->c_io = w_client;
		insert_io->s_io = w_serv;
		insert_io->number = get_number_total();
	}
#endif

	struct st_io *new_io = 	get_new_io();
	if(NULL == new_io)
	{
        zLogError("memory allocate error.");
		close(remote_fd);
        close(client_fd);
        free(w_client);
        free(w_serv);
        return;
	}
	new_io->c_io = w_client;
	new_io->s_io = w_serv;		

	if(-1 == HashTableAdd(g_ht_io,new_io,sizeof(struct st_io)))
	{
        zLogError("HashTableAdd error.");
		close(remote_fd);
        close(client_fd);
        free(w_client);
        free(w_serv);
		IOHashTableFree(new_io);
        return;		
	}
	/*****************dt  end***********************/
    ev_io_init(new_io->c_io, read_cb_client, client_fd, EV_READ);
    ev_io_start(loop, new_io->c_io);

	//zLogDebug("new_io->c_io is %p,it is address is %p",new_io->c_io,&new_io->c_io);

    	
    ev_io_init(new_io->s_io, read_cb_remote, remote_fd, EV_READ);
    ev_io_start(loop, new_io->s_io);
	
	//zLogDebug("new_io->s_io is %p,it is address is %p",new_io->s_io,&new_io->s_io);


    return;
}

static int send_sock(int sock, uint8_t *buffer, uint32_t size)
{
	int index = 0, ret;
	while(size) {
		if((ret = send(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}


int GetRemoteAddr( int nSocket, char *p_addr,char *p_port )
{
    struct sockaddr_in addr;
    unsigned int nAddrLen = sizeof( addr );

    if ( getpeername( nSocket,(struct sockaddr * ) &addr,&nAddrLen ) < 0 )
    {
        return 0;
    }
    else
    {
        strcpy( p_addr,inet_ntoa(addr.sin_addr));
		sprintf(p_port, "%d", ntohs(addr.sin_port));	
	    return 1;
    }
}

static void read_cb_client(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	zEnter("Enter");
	//watcher is a value,not the address of struct st_io.c_io,so can't use container_of
	//zLogDebug("watcher is %p,it is address is %p",watcher,&watcher);
	//struct ev_io *ori_watcher = container_of(&watcher->data, struct ev_io, data);
	//zLogDebug("ori_watcher is %p,it is address is %p",ori_watcher,&ori_watcher);

	//zLogDebug("watcher->data is %p",watcher->data);

	struct st_io *t_io = HashTableLookup(g_ht_io, watcher->data, 1);
	BUG_ON(t_io == NULL);
	
	char addr[128] = "";
	char port[128] = "";
	GetRemoteAddr(watcher->fd ,addr,port);

    char buffer[BUFFER_SIZE];
    ssize_t read;

    if (EV_ERROR & revents) {
      zLogError("error event in read.");
      return;
    }

    read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);
    if (read < 0) {
        zLogError("read error [%d].", errno);

        if (104 == errno) {
            zLogDebug("close %s:%s.", addr, port);
            ev_io_stop(loop, watcher);
            ev_io_stop(loop, watcher->data);
            close(watcher->fd);
            close(((struct ev_io *)watcher->data)->fd);
            free(watcher->data);
            free(watcher);
			if(--t_io->count_free == 0)
				HashTableRemove(g_ht_io, t_io, sizeof(struct st_io));
			return;
        }
    } else if (0 == read) {
        zLogDebug("close %s:%s.", addr, port);
        ev_io_stop(loop, watcher);
        ev_io_stop(loop, watcher->data);
        close(watcher->fd);
        close(((struct ev_io *)watcher->data)->fd);
        free(watcher->data);
        free(watcher);
		if(--t_io->count_free == 0)
			HashTableRemove(g_ht_io, t_io, sizeof(struct st_io));

    } else {
    	t_io->ssInput->buf = (uint8_t *)buffer;
		t_io->ssInput->buf_len = (uint32_t)read;
		t_io->ssInput->fd = ((struct ev_io *)watcher->data)->fd;
		t_io->ssInput->send_sock = send_sock;
		
		fwrite (buffer , read, 1 , g_fp);
		
		DTRequestData(t_io->ssInput);
        //send(((struct ev_io *)watcher->data)->fd, buffer, read, 0);
    }

    return;

}
static void read_cb_remote(struct ev_loop *loop, struct ev_io *watcher, int revents) 
{
	zEnter("Enter");
	//watcher is a value,not the address of struct st_io.c_io,so can't use container_of
	//struct st_io *ori_io = container_of(&watcher, struct st_io, s_io);

	//zLogDebug("watcher is %p,it is address is %p",watcher,&watcher);
	//struct ev_io *ori_watcher = container_of(&watcher->data, struct ev_io, data);
	//zLogDebug("ori_watcher is %p,it is address is %p",ori_watcher,&ori_watcher);
	//zLogDebug("watcher is %p",watcher);

	struct st_io *t_io = HashTableLookup(g_ht_io, watcher, 1);

	BUG_ON(t_io == NULL);	

	char addr[128] = "";
	char port[128] = "";
	GetRemoteAddr(watcher->fd ,addr,port);
	//zLogDebug("ip is %s",buf);
	
	char buffer[BUFFER_SIZE];
    ssize_t read;

    if (EV_ERROR & revents) {
      zLogError("error event in read.");
      return;
    }

    read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);
    if (read < 0) {
        zLogError("read error [%d].", errno);

        if (104 == errno) {
            zLogDebug("close %s:%s.", addr, port);
            ev_io_stop(loop, watcher);
            ev_io_stop(loop, watcher->data);
            close(watcher->fd);
            close(((struct ev_io *)watcher->data)->fd);
            free(watcher->data);
            free(watcher);
			if(--t_io->count_free == 0)
				HashTableRemove(g_ht_io, t_io, sizeof(struct st_io));
            return;
        }
    } else if (0 == read) {
        zLogDebug("close %s:%s.", addr, port);
        ev_io_stop(loop, watcher);
        ev_io_stop(loop, watcher->data);
        close(watcher->fd);
        close(((struct ev_io *)watcher->data)->fd);
        free(watcher->data);
        free(watcher);
		if(--t_io->count_free == 0)
			HashTableRemove(g_ht_io, t_io, sizeof(struct st_io));

    } else {
    	t_io->ssInput->buf = (uint8_t *)buffer;
		t_io->ssInput->buf_len = (uint32_t)read;
		t_io->ssInput->fd = ((struct ev_io *)watcher->data)->fd;
		t_io->ssInput->send_sock = send_sock;
		DTResponseData(t_io->ssInput);
        //send(((struct ev_io *)watcher->data)->fd, buffer, read, 0);
    }

    return;
}
