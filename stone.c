/*
 * stone.c	simple repeater
 * Copyright(c)1995-2006 by Hiroaki Sengoku <sengoku@gcd.org>
 * Version 1.0	Jan 28, 1995
 * Version 1.1	Jun  7, 1995
 * Version 1.2	Aug 20, 1995
 * Version 1.3	Feb 16, 1996	relay UDP
 * Version 1.5	Nov 15, 1996	for Win32
 * Version 1.6	Jul  5, 1997	for SSL
 * Version 1.7	Aug 20, 1997	return packet of UDP
 * Version 1.8	Oct 18, 1997	pseudo parallel using SIGALRM
 * Version 2.0	Nov  3, 1997	http proxy & over http
 * Version 2.1	Nov 14, 1998	respawn & pop
 * Version 2.2	May 25, 2003	Posix Thread, XferBufMax, no ALRM, SSL verify
 * Version 2.3	Jan  1, 2006	LB, healthCheck, NonBlock, IPv6, sockaddr_un
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Emacs; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Usage: stone [-d] [-n] [-u <max>] [-f <n>] [-a <file>] [-L <file>] [-l]
 *              [-o <n>] [-g <n>] [-t <dir>] [-z <SSL>] [-D]
 *              [-C <file>] [-P <command>]
 *              <st> [-- <st>]...
 * <st> :=  <host>:<port> <sport> [<xhost>...]
 *        | proxy <sport> [<xhost>...]
 *        | <host>:<port#>/http <sport> <request> [<xhost>...]
 *        | <host>:<port#>/proxy <sport> <header> [<xhost>...]
 * <port>  := <port#>[/udp | /ssl | /apop]
 * <sport> := [<host>:]<port#>[/udp | /ssl | /http]
 * <xhost> := <host>[/<mask>]
 *
 *     Any packets received by <sport> are passed to <host>:<port>
 *     as long as these packets are sent from <xhost>...
 *     if <xhost> are not given, any hosts are welcome.
 *
 * Make:
 * gcc -o stone stone.c
 * or
 * cl -DWINDOWS stone.c /MT wsock32.lib
 * or
 * gcc -DWINDOWS -o stone.exe stone.c -lwsock32
 *
 * POP -> APOP conversion
 * gcc -DUSE_POP -o stone stone.c md5c.c
 * or
 * cl -DWINDOWS -DUSE_POP stone.c md5c.c /MT wsock32.lib
 * or
 * gcc -DWINDOWS -DUSE_POP -o stone.exe stone.c md5c.c -lwsock32
 *
 * md5c.c global.h md5.h are contained in RFC1321
 *
 * Using OpenSSL
 * gcc -DUSE_SSL -I/usr/local/ssl/include -o stone stone.c \
 *               -L/usr/local/ssl/lib -lssl -lcrypto
 * or
 * cl -DWINDOWS -DUSE_SSL stone.c /MT wsock32.lib ssleay32.lib libeay32.lib
 * or
 * gcc -DWINDOWS -DUSE_SSL -o stone.exe stone.c -lwsock32 -lssl32 -leay32
 *
 * -DUSE_POP	  use POP -> APOP conversion
 * -DUSE_SSL	  use OpenSSL
 * -DCPP	  preprocessor for reading config. file
 * -DIGN_SIGTERM  ignore SIGTERM signal
 * -DUNIX_DAEMON  fork into background and become a UNIX Daemon
 * -DNO_BCOPY	  without bcopy(3)
 * -DNO_SNPRINTF  without snprintf(3)
 * -DNO_SYSLOG	  without syslog(2)
 * -DNO_RINDEX	  without rindex(3)
 * -DNO_THREAD	  without thread
 * -DNO_PID_T	  without pid_t
 * -DNO_SOCKLEN_T without socklen_t
 * -DNO_ADDRINFO  without getaddrinfo
 * -DNO_FAMILY_T  without sa_family_t
 * -DADDRCACHE    cache address used in proxy
 * -DUSE_EPOLL	  use epoll(4) (Linux)
 * -DPTHREAD      use Posix Thread
 * -DPRCTL	  use prctl(2) - operations on a process
 * -DOS2	  OS/2 with EMX
 * -DWINDOWS	  Windows95/98/NT
 * -DNT_SERVICE	  WindowsNT/2000 native service
 */
#define VERSION	"2.3c"
static char *CVS_ID =
"@(#) $Id: stone.c,v 2.3 2006/09/17 00:53:35 hiroaki_sengoku Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <regex.h>
typedef void (*FuncPtr)(void*);

#ifdef WINDOWS
#define FD_SETSIZE	4096
#include <process.h>
#include <ws2tcpip.h>
#if !defined(EINPROGRESS) && defined(WSAEWOULDBLOCK)
#define EINPROGRESS     WSAEWOULDBLOCK
#endif
#if !defined(EMSGSIZE) && defined(WSAEMSGSIZE)
#define	EMSGSIZE	WSAEMSGSIZE
#endif
#if !defined(EADDRINUSE) && defined(WSAEADDRINUSE)
#define	EADDRINUSE	WSAEADDRINUSE
#endif
#if !defined(ECONNABORTED) && defined(WSAECONNABORTED)
#define	ECONNABORTED	WSAECONNABORTED
#endif
#if !defined(ECONNRESET) && defined(WSAECONNRESET)
#define	ECONNRESET	WSAECONNRESET
#endif
#if !defined(EISCONN) && defined(WSAEISCONN)
#define	EISCONN		WSAEISCONN
#endif
#include <time.h>
#ifdef NT_SERVICE
#include <windows.h>
#include "logmsg.h"
#endif
#define NO_SYSLOG
#define NO_FORK
#define NO_SETUID
#define NO_CHROOT
#define	NO_GETTIMEOFDAY
#define NO_FAMILY_T
#define	NO_UNIXDOMAIN
#define ValidSocket(sd)		((sd) != INVALID_SOCKET)
#define FD_SET_BUG
#undef EINTR
#define EINTR	WSAEINTR
#define NO_BCOPY
#define bzero(b,n)	memset(b,0,n)
#define	usleep(usec)	Sleep(usec)
#define ASYNC(func,arg)	{\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    waitMutex(AsyncMutex);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    if (_beginthread((FuncPtr)func,0,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d",errno);\
	func(arg);\
    }\
}
#else	/* ! WINDOWS */
#include <sys/param.h>
#ifdef OS2
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <process.h>
#include <os2.h>
#define NO_SYSLOG
#define	NO_UNIXDOMAIN
#define ASYNC(func,arg)	{\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    waitMutex(AsyncMutex);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    if (_beginthread((FuncPtr)func,NULL,32768,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d",errno);\
	func(arg);\
    }\
}
#else	/* ! WINDOWS & ! OS2 */
#ifdef PTHREAD
#include <pthread.h>
pthread_attr_t thread_attr;
typedef void *(*aync_start_routine) (void *);
#define ASYNC(func,arg)	{\
    pthread_t thread;\
    int err;\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC: %d",AsyncCount);\
    waitMutex(AsyncMutex);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    err=pthread_create(&thread,&thread_attr,(aync_start_routine)func,arg);\
    if (err) {\
	message(LOG_ERR,"pthread_create error err=%d",err);\
	func(arg);\
    } else if (Debug > 7) {\
	message(LOG_DEBUG,"pthread ID=%lu",thread);\
    }\
}
#else	/* ! PTHREAD */
#define ASYNC(func,arg)	{\
    waitMutex(AsyncMutex);\
    AsyncCount++;\
    freeMutex(AsyncMutex);\
    func(arg);\
}
#define NO_THREAD
#endif	/* ! PTHREAD */
#endif	/* ! WINDOWS & ! OS2 */
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#ifndef NO_SETUID
#include <grp.h>
#endif
#ifdef PRCTL
#include <sys/prctl.h>
#endif
#ifdef MEMLEAK_CHECK
#include <mcheck.h>
#endif
typedef int SOCKET;
#define INVALID_SOCKET		-1
#define ValidSocket(sd)		((sd) >= 0)
#define closesocket(sd)		close(sd)
#endif	/* ! WINDOWS */
#define InvalidSocket(sd)	(!ValidSocket(sd))
#ifdef USE_EPOLL
#include <sys/epoll.h>
#define EVSMAX	100
#else
#ifdef FD_SET_BUG
int FdSetBug = 0;
#define FdSet(fd,set)		do{if (!FdSetBug || !FD_ISSET((fd),(set))) \
					FD_SET((fd),(set));}while(0)
#else
#define FdSet(fd,set)		FD_SET((fd),(set))
#endif
#endif

#ifdef NO_THREAD
#define ASYNC_BEGIN		/* */
#define _ASYNC_END		/* */
#else
#define ASYNC_BEGIN	\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC_BEGIN: %d",AsyncCount)
#define _ASYNC_END	\
    if (Debug > 7) message(LOG_DEBUG,"ASYNC_END: %d",AsyncCount);\
    waitMutex(AsyncMutex);\
    AsyncCount--;\
    freeMutex(AsyncMutex)
#endif

#ifdef USE_SSL
#define ASYNC_END	\
    _ASYNC_END;\
    ERR_remove_state(0)
#else
#define ASYNC_END	_ASYNC_END
#endif

#ifdef NO_SYSLOG
#define LOG_CRIT	2	/* critical conditions */
#define LOG_ERR		3	/* error conditions */
#define LOG_WARNING	4	/* warning conditions */
#define LOG_NOTICE	5	/* normal but signification condition */
#define LOG_INFO	6	/* informational */
#define LOG_DEBUG	7	/* debug-level messages */
#else	/* SYSLOG */
#include <syslog.h>
#endif

#define BACKLOG_MAX	50
#define XPORT		6000
#define BUFMAX		2048
#define LONGSTRMAX	1024
#define STRMAX		127	/* > 38 */
#define CONN_TIMEOUT	60	/* 1 min */
#define	LB_MAX		100
#define	FREE_TIMEOUT	600	/* 10 min */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	255
#endif

#define TICK_SELECT	100000	/* 0.1 sec */
#define SPIN_MAX	10	/* 1 sec */
#define	NERRS_MAX	10	/* # of select errors */
#define	REF_UNIT	10	/* unit of pair->count */

#ifdef USE_SSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#ifdef CRYPTOAPI
int SSL_CTX_use_CryptoAPI_certificate(SSL_CTX *ssl_ctx, const char *cert_prop);
#endif

#define NMATCH_MAX	9	/* \1 ... \9 */
#define DEPTH_MAX	10

typedef struct {
    int verbose;
    int shutdown_mode;
    int depth;
    long serial;
    SSL_CTX *ctx;
    regex_t *re[DEPTH_MAX];
    unsigned char lbmod;
    unsigned char lbparm;
} StoneSSL;

typedef struct {
    int verbose;
    int shutdown_mode;
    int mode;
    int depth;
    int vflags;
    long off;
    long serial;
    SSL_METHOD *meth;
    int (*callback)(int, X509_STORE_CTX *);
    char *sid_ctx;
    char *keyFile;
    char *certFile;
    char *caFile;
    char *caPath;
    char *pfxFile;
    char *passwd;
#ifdef CRYPTOAPI
    char *certStore;
#endif
    char *cipherList;
    char *regexp[DEPTH_MAX];
    unsigned char lbmod;
    unsigned char lbparm;
} SSLOpts;

SSLOpts ServerOpts;
SSLOpts ClientOpts;
int PairIndex;
int MatchIndex;
int NewMatchCount = 0;
#ifdef WINDOWS
HANDLE *SSLMutex = NULL;
#else
#ifdef PTHREAD
pthread_mutex_t *SSLMutex = NULL;
#endif
#endif
int NSSLMutexs = 0;

#include <openssl/md5.h>
#define MD5Init		MD5_Init
#define MD5Update	MD5_Update
#define MD5Final	MD5_Final
#else
#ifdef USE_POP
#include "global.h"
#include "md5.h"
#endif
#endif
#ifdef CPP
char *CppCommand = CPP;
char *CppOptions = NULL;
#endif

#ifdef NO_ADDRINFO
#undef AF_INET6
#endif
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif

typedef struct _Chat {
    struct _Chat *next;
    char *send;
    int len;
    regex_t expect;
} Chat;

typedef struct {
    socklen_t len;
    struct sockaddr addr;
} SockAddr;
#define SockAddrBaseSize	(sizeof(SockAddr) - sizeof(struct sockaddr))

typedef struct _XHosts {
    struct _XHosts *next;
    short mbits;
    short mode;
    SockAddr xhost;	/* must be the last member */
} XHosts;
#define XHostsBaseSize		(sizeof(XHosts) - sizeof(struct sockaddr))
#define XHostsMode_Dump		0xF

typedef struct _XPorts {
    struct _XPorts *next;
    short from;		/* port range from */
    short end;		/* port range to, or equals to from */
} XPorts;

typedef struct _PortXHosts {
    struct _PortXHosts *next;
    XPorts *ports;
    XHosts *xhosts;
} PortXHosts;

typedef struct _Backup {
    struct _Backup *next;
    SockAddr *check;
    /* host:port for check (usually same as master) */
    SockAddr *master;
    SockAddr *backup;
    int proto;
    Chat *chat;		/* chat script for health check */
    short interval;	/* interval of health check */
    short bn;		/* 0: health, 1: backup */
    short used;		/* 0: not used, 1: assigned, 2: used */
    time_t last;	/* last health check */
} Backup;

typedef struct _LBSet {
    struct _LBSet *next;
    int proto;
    short ndsts;
    SockAddr *dsts[0];
} LBSet;

#define type_mask	0x000f
#define type_pair	0x0001
#define type_origin	0x0002
#define type_stone	0x0003
#define	type_pktbuf	0x0004

typedef struct _Stone {
    int common;
    SOCKET sd;			/* socket descriptor to listen */
    short port;
    short ndsts;		/* # of destinations */
    SockAddr **dsts;		/* destinations */
    SockAddr *from;
    int proto;
    Backup **backups;
    struct _Pair *pairs;
    char *p;
    int timeout;
    struct _Stone *next;
#ifdef USE_SSL
    StoneSSL *ssl_server;
    StoneSSL *ssl_client;
#endif
    int nhosts;			/* # of hosts */
    XHosts *xhosts;		/* hosts permitted to connect */
} Stone;

typedef struct _TimeLog {
    time_t clock;		/* time of beginning */
    int pri;			/* log priority */
    char str[0];		/* Log message */
} TimeLog;

typedef struct _ExBuf {	/* extensible buffer */
    struct _ExBuf *next;
    int start;		/* index of buf */
    int len;
    int bufmax;		/* buffer size */
    char buf[BUFMAX];
} ExBuf;

typedef struct _Pair {
    int common;
    struct _Pair *pair;
    struct _Pair *prev;
    struct _Pair *next;
    Stone *stone;	/* parent */
#ifdef USE_SSL
    SSL *ssl;		/* SSL handle */
    int ssl_flag;
#endif
    XHosts *xhost;
    time_t clock;
    int timeout;
    SOCKET sd;		/* socket descriptor */
    int proto;
    int count;		/* reference counter */
    char *p;
    TimeLog *log;
    int tx;		/* sent bytes */
    int rx;		/* received bytes */
    int loop;		/* loop count */
    int nbuf;
    ExBuf *t;	/* top */
    ExBuf *b;	/* bottom */
} Pair;

typedef struct _Conn {
    SockAddr *dst;	/* destination */
    Pair *pair;
    int lock;
    struct _Conn *next;
} Conn;

typedef struct _Origin {
    int common;
    SOCKET sd;		/* peer */
    Stone *stone;
    SockAddr *from;	/* from where */
    int lock;
    XHosts *xhost;
    time_t clock;
    struct _Origin *next;
} Origin;

typedef struct _PktBuf {	/* packet buffer */
    int common;
    struct _PktBuf *next;
    int type;
    Origin *origin;
    int len;
    int bufmax;		/* buffer size */
    char buf[BUFMAX];
} PktBuf;

typedef struct _Comm {
    char *str;
    int (*func)(Pair*, char*, int);
} Comm;

Stone *stones = NULL;
Stone *oldstones = NULL;
int ReuseAddr = 0;
PortXHosts *portXHosts = NULL;
XHosts *XHostsTrue = NULL;
Chat *healthChat = NULL;
Backup *backups = NULL;
LBSet *lbsets = NULL;
int MinInterval = 0;
time_t lastScanBackups = 0;
time_t lastEstablished = 0;
time_t lastReadWrite = 0;
Pair *PairTop = NULL;
Pair trash;
Pair *freePairs = NULL;
int nFreePairs = 0;
ExBuf *freeExBuf = NULL;
int nFreeExBuf = 0;
ExBuf *freeExBot = NULL;
int nFreeExBot = 0;
time_t freeExBotClock = 0;
Conn conns;
Origin *OriginTop = NULL;
int OriginMax = 100;
PktBuf *freePktBuf = NULL;
int nFreePktBuf = 0;
#ifdef USE_EPOLL
int ePollFd;
#else
fd_set rin, win, ein;
#endif
int PairTimeOut = 10 * 60;	/* 10 min */
int AsyncCount = 0;
int MutexConflict = 0;

const int state_mask =		    0x00ff;
const int proto_command =	    0x0f00;	/* command (dest. only) */
						/* only for Stone */
const int proto_ident =		    0x1000;	  /* need ident */
const int proto_nobackup =	    0x2000;	  /* no backup */
const int proto_udp_s =		    0x4000;	  /* UDP source */
const int proto_udp_d =		    0x8000;	  /*     destination */
const int proto_v6_s =		   0x10000;	  /* IPv6 source */
const int proto_v6_d =		   0x20000;	  /*      destination */
const int proto_ip_only_s =	   0x40000;	  /* IPv6 only source */
const int proto_ip_only_d =	   0x80000;	  /*           destination */
const int proto_unix_s =	  0x100000;       /* unix socket source */
const int proto_unix_d =	  0x200000;	  /*             destination */
const int proto_block_s =	  0x400000;	  /* blocking I/O source */
const int proto_block_d =	  0x800000;	  /*              destination*/
const int proto_ssl_s =		 0x1000000;	  /* SSL source */
const int proto_ssl_d =		 0x2000000;	  /*     destination */
						/* only for Pair */
const int proto_dirty =		    0x1000;	  /* ev must be updated */
/*const int proto_ =		    0x2000;	  */
const int proto_noconnect =	    0x4000;	  /* no connection needed */
const int proto_connect =	    0x8000;	  /* connection established */
const int proto_first_r =	   0x10000;	  /* first read packet */
const int proto_first_w =	   0x20000;	  /* first written packet */
const int proto_select_r =	   0x40000;	  /* select to read */
const int proto_select_w =	   0x80000;	  /* select to write */
const int proto_shutdown =	  0x100000;	  /* sent shutdown */
const int proto_close =	  	  0x200000;	  /* request to close */
const int proto_eof =		  0x400000;	  /* EOF was received */
const int proto_error =		  0x800000;	  /* error reported */
const int proto_thread =	 0x1000000;	  /* on thread */
const int proto_conninprog =	 0x2000000;	  /* connect in progress */
const int proto_ohttp_s =	 0x4000000;	/* over http source */
const int proto_ohttp_d =	 0x8000000;	/*           destination */
const int proto_base_s =	0x10000000;	/* base64 source */
const int proto_base_d =	0x20000000;	/*        destination */
#define command_ihead		    0x0100	/* insert header */
#define command_iheads		    0x0200	/* insert header repeatedly */
#define command_pop		    0x0300	/* POP -> APOP conversion */
#define command_health		    0x0400	/* is stone healthy ? */
#define command_identd		    0x0500	/* identd of stone */
#define command_proxy		    0x0600	/* http proxy */
#define command_source		    0x0f00	/* source flag */

#define proto_ssl	(proto_ssl_s|proto_ssl_d)
#define proto_v6	(proto_v6_s|proto_v6_d)
#define proto_udp	(proto_udp_s|proto_udp_d)
#define proto_ip_only	(proto_ip_only_s|proto_ip_only_d)
#define proto_unix	(proto_unix_s|proto_unix_d)
#define proto_block	(proto_block_s|proto_block_d)
#define proto_ohttp	(proto_ohttp_s|proto_ohttp_d)
#define proto_base	(proto_base_s|proto_base_d)
#define proto_stone_s	(proto_udp_s|proto_command|\
			 proto_ohttp_s|proto_base_s|\
			 proto_v6_s|proto_ip_only_s|\
			 proto_ssl_s|proto_ident)
#define proto_stone_d	(proto_udp_d|proto_command|\
			 proto_ohttp_d|proto_base_d|\
			 proto_v6_d|proto_ip_only_d|\
			 proto_ssl_d|proto_nobackup)
#define proto_pair_s	(proto_ohttp_s|proto_base_s)
#define proto_pair_d	(proto_ohttp_d|proto_base_d|proto_command)

#ifdef USE_SSL
const int sf_mask    =  0x0000f;
const int sf_depth   =	0x000f0;	/* depth of cert chain */
const int sf_depth_bit = 4;
const int sf_sb_on_r =  0x00100;	/* SSL_shutdown blocked on read */
const int sf_sb_on_w =  0x00200;	/* SSL_shutdown blocked on write */
const int sf_wb_on_r =	0x00400;	/* SSL_write blocked on read */
const int sf_rb_on_w =	0x00800;	/* SSL_read  blocked on write */
const int sf_cb_on_r =  0x01000;	/* SSL_connect blocked on read */
const int sf_cb_on_w =  0x02000;	/* SSL_connect blocked on write */
const int sf_ab_on_r =  0x04000;	/* SSL_accept blocked on read */
const int sf_ab_on_w =  0x08000;	/* SSL_accept blocked on write */
#endif

int BacklogMax = BACKLOG_MAX;
int XferBufMax = 1000;	/* TCP packet buffer initial size (must < 1024 ?) */
#define PKT_LEN_INI		2048	/* initial size */
int pkt_len_max = PKT_LEN_INI;	/* size of UDP packet buffer */
int AddrFlag = 0;
#ifndef NO_SYSLOG
int Syslog = 0;
char SyslogName[STRMAX+1];
#endif
FILE *LogFp = NULL;
char *LogFileName = NULL;
FILE *AccFp = NULL;
char *AccFileName = NULL;
char *ConfigFile = NULL;
char *PidFile = NULL;
SockAddr *ConnectFrom = NULL;

int DryRun = 0;
int ConfigArgc = 0;
int OldConfigArgc = 0;
char **ConfigArgv = NULL;
char **OldConfigArgv = NULL;
#ifdef UNIX_DAEMON
int DaemonMode = 0;
#endif
#ifndef NO_CHROOT
char *RootDir = NULL;
#endif
#ifndef NO_SETUID
uid_t SetUID = 0;
gid_t SetGID = 0;
#endif
char *CoreDumpDir = NULL;
#ifdef NO_PID_T
typedef int pid_t;
#endif
pid_t MyPid;
#ifndef NO_FORK
int NForks = 0;
pid_t *Pid;
#endif
int Debug = 0;		/* debugging level */

#ifdef ADDRCACHE
#define	CACHE_TIMEOUT	180	/* 3 min */
int AddrCacheSize = 0;
#endif
#ifdef PTHREAD
pthread_mutex_t FastMutex = PTHREAD_MUTEX_INITIALIZER;
char FastMutexs[11];
#define PairMutex	0
#define ConnMutex	1
#define OrigMutex	2
#define AsyncMutex	3
#ifndef USE_EPOLL
#define FdRinMutex	4
#define FdWinMutex	5
#define FdEinMutex	6
#endif
#define ExBufMutex	7
#define FPairMutex	8
#define	PkBufMutex	9
#ifdef ADDRCACHE
#define	HashMutex	10
#endif
#endif
#ifdef WINDOWS
HANDLE PairMutex, ConnMutex, OrigMutex, AsyncMutex;
HANDLE FdRinMutex, FdWinMutex, FdEinMutex;
HANDLE ExBufMutex, FPairMutex, PkBufMutex;
#ifdef ADDRCACHE
HANDLE HashMutex;
#endif
#endif
#ifdef OS2
HMTX PairMutex, ConnMutex, OrigMutex, AsyncMutex;
HMTX FdRinMutex, FdWinMutex, FdEinMutex;
HMTX ExBufMutex, FPairMutex, PkBufMutex;
#ifdef ADDRCACHE
HMTX HashMutex;
#endif
#endif

#ifdef NT_SERVICE
SERVICE_STATUS NTServiceStatus;
SERVICE_STATUS_HANDLE NTServiceStatusHandle;
#define NTServiceDisplayPrefix	"Stone "
char *NTServiceDisplayName = NULL;
char *NTServiceName = NULL;
HANDLE NTServiceLog = NULL;
HANDLE NTServiceThreadHandle = NULL;
#endif

#ifdef NO_VSNPRINTF
int vsnprintf(char *str, size_t len, char *fmt, va_list ap) {
    int ret;
    ret = vsprintf(str, fmt, ap);
    if (strlen(str) >= len) {
	fprintf(stderr, "Buffer overrun\n");
	exit(1);
    }
    return ret;
}
#endif

#ifdef NO_SNPRINTF
int snprintf(char *str, size_t len, char *fmt, ...) {
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(str, len, fmt, ap);
    va_end(ap);
    return ret;
}
#endif

#ifdef NO_BCOPY
void bcopy(void *b1, void *b2, int len) {
    if (b1 < b2 && (char*)b2 < (char*)b1 + len) {	/* overlapping */
	char *p, *q;
	q = (char*)b2 + len - 1;
	for (p=(char*)b1+len-1; (char*)b1 <= p; p--, q--) *q = *p;
    } else {
	memcpy(b2, b1, len);
    }
}
#endif

#ifdef NO_RINDEX
char *rindex(char *p, int ch) {
    char *save = NULL;
    do {
	if (*p == ch) save = p;
    } while (*p++);
    return save;
}
#endif

char *strntime(char *str, int len, time_t *clock, long micro) {
    char *p, *q;
    int i;
    p = ctime(clock);
    if (p) {
	q = p + strlen(p);
	while (*p++ != ' ')	;
	while (*--q != ' ')	;
	i = 0;
	len--;
	while (p <= q && i < len) str[i++] = *p++;
	if (micro >= 0) {
	    i--;
	    snprintf(str+i, len-i, ".%06ld ", micro);
	} else {
	    str[i] = '\0';
	}
    } else {
	snprintf(str, len, "%lu ", *clock);
    }
    return str;
}

#ifdef NO_GETTIMEOFDAY
int gettimeofday(struct timeval *tv, void *tz) {
    static u_long start = 0;
    u_long tick = GetTickCount();
    time_t now;
    time(&now);
    if (start == 0) start = now - tick / 1000;
    if (tz) return -1;
    if (tv) {
	tv->tv_usec = (tick % 1000) * 1000;
	tv->tv_sec = start + (tick / 1000);
	if (now < tv->tv_sec - 1 || tv->tv_sec + 1 < now) {
	    start = 0;
	    tv->tv_usec = -1;	/* diff is too large */
	}
	return 0;
    }
    return -1;
}
#endif

#if defined (__STDC__) && __STDC__
void message(int pri, char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3))); 
#endif

void message(int pri, char *fmt, ...) {
    char str[LONGSTRMAX+1];
    int pos = 0;
    unsigned long thid = 0;
    va_list ap;
#ifndef NO_SYSLOG
    if (!Syslog)
#endif
    {
	struct timeval tv;
	if (gettimeofday(&tv, NULL) >= 0) {
	    strntime(str+pos, LONGSTRMAX-pos, &tv.tv_sec, tv.tv_usec);
	}
	str[LONGSTRMAX] = '\0';
	pos = strlen(str);
    }
#ifdef WINDOWS
    thid = (unsigned long)GetCurrentThreadId();
#else
#ifdef PTHREAD
    thid = (unsigned long)pthread_self();
#endif
#endif
    if (thid) {
	snprintf(str+pos, LONGSTRMAX-pos, "%lu ", thid);
	pos += strlen(str+pos);
    }
    va_start(ap, fmt);
    vsnprintf(str+pos, LONGSTRMAX-pos, fmt, ap);
    va_end(ap);
    str[LONGSTRMAX] = '\0';
#ifndef NO_SYSLOG
    if (Syslog) {
	if (Syslog == 1
	    || pri != LOG_DEBUG) syslog(pri, "%s", str);
	if (Syslog > 1) fprintf(stdout, "%s\n", str);	/* daemontools */
    } else
#else
#ifdef NT_SERVICE
    if (NTServiceLog) {
	LPCTSTR msgs[] = {str, NULL};
	int type = EVENTLOG_INFORMATION_TYPE;
	if (pri <= LOG_ERR) type = EVENTLOG_ERROR_TYPE;
	else if (pri <= LOG_NOTICE) type = EVENTLOG_WARNING_TYPE;
	ReportEvent(NTServiceLog, type, 0, EVLOG, NULL, 1, 0, msgs, NULL);
    } else
#endif
#endif
	if (LogFp) fprintf(LogFp, "%s\n", str);
}

void message_time(Pair *pair, int pri, char *fmt, ...) {
    va_list ap;
    char str[LONGSTRMAX+1];
    TimeLog *log;
    log = pair->log;
    if (log) {
	pair->log = NULL;
	free(log);
    }
    va_start(ap, fmt);
    vsnprintf(str, LONGSTRMAX, fmt, ap);
    va_end(ap);
    str[LONGSTRMAX] = '\0';
    log = (TimeLog*)malloc(sizeof(TimeLog)+strlen(str)+1);
    if (log) {
	time(&log->clock);
	log->pri = pri;
	strcpy(log->str, str);
	pair->log = log;
    }
}

int priority(Pair *pair) {
    int pri = LOG_ERR;
    if (pair) {
	if (pair->proto & proto_error) pri = LOG_DEBUG;
	else pair->proto |= proto_error;
    }
    return pri;
}

void packet_dump(char *head, char *buf, int len, XHosts *xhost) {
    char line[LONGSTRMAX+1];
    int mode = (xhost->mode & XHostsMode_Dump);
    int i, j, k, l;
    int nb = 8;
    k = 0;
    for (i=0; i < len; i += j) {
	if (mode <= 2) {
	    nb = 16;
	    l = 0;
	    line[l++] = ' ';
	    for (j=0; k <= j/10 && i+j < len && l < LONGSTRMAX-10; j++) {
		if (' ' <= buf[i+j] && buf[i+j] <= '~')
		    line[l++] = buf[i+j];
		else {
		    sprintf(&line[l], "<%02x>", buf[i+j]);
		    l += strlen(&line[l]);
		    if (buf[i+j] == '\n') {
			k = 0;
			j++;
			break;
		    }
		    if (buf[i+j] != '\t' && buf[i+j] != '\r'
			&& buf[i+j] != '\033')
			k++;
		}
	    }
	}
	if (k > j/10 || nb < 16) {
	    j = l = 0;
	    for (j=0; j < nb && i+j < len; j++) {
		if (mode == 1 && (' ' <= buf[i+j] && buf[i+j] <= '~'))
		    sprintf(&line[l], " '%c", buf[i+j]);
		else {
		    sprintf(&line[l], " %02x", (unsigned char)buf[i+j]);
		    if (buf[i+j] == '\n') k = 0; else k++;
		}
		l += strlen(&line[l]);
	    }
	    if (nb < 16) {
		while (l < (nb * 3) + 2) line[l++] = ' ';
		for (j=0; j < nb && i+j < len; j++) {
		    if (' ' <= buf[i+j] && buf[i+j] <= '~')
			line[l++] = buf[i+j];
		    else
			line[l++] = '.';
		}
	    }
	}
	line[l] = '\0';
	message(LOG_DEBUG, "%s%s", head, line);
    }
}

char *addr2ip(struct in_addr *addr, char *str, int len) {
    union {
	u_long	l;
	unsigned char	c[4];
    } u;
    if (len >= 1) {
	u.l = addr->s_addr;
	snprintf(str, len-1, "%d.%d.%d.%d", u.c[0], u.c[1], u.c[2], u.c[3]);
	str[len-1] = '\0';
    }
    return str;
}

#ifdef AF_INET6
char *addr2ip6(struct in6_addr *addr, char *str, int len) {
    u_short *s;
    if (len >= 1) {
	s = (u_short*)addr;
	snprintf(str, len-1, "%x:%x:%x:%x:%x:%x:%x:%x",
		 ntohs(s[0]), ntohs(s[1]), ntohs(s[2]), ntohs(s[3]),
		 ntohs(s[4]), ntohs(s[5]), ntohs(s[6]), ntohs(s[7]));
	str[len-1] = '\0';
    }
    return str;
}
#endif

char *addr2numeric(struct sockaddr *sa, char *str, int len) {
    if (sa->sa_family == AF_INET) {
	addr2ip(&((struct sockaddr_in*)sa)->sin_addr, str, len);
#ifdef AF_INET6
    } else if (sa->sa_family == AF_INET6) {
	addr2ip6(&((struct sockaddr_in6*)sa)->sin6_addr, str, len);
#endif
    } else {
	snprintf(str, len, "%s", "???");
    }
    return str;
}

char *ext2str(int ext, char *str, int len) {
    char sep = '/';
    int i = 0;
    if (!str || len <= 1) return "";
    if (ext & proto_udp) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "udp", len-i);
	i += 3;
    }
    if (ext & proto_ohttp) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "http", len-i);
	i += 4;
    }
    if (ext & proto_ssl) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "ssl", len-i);
	i += 3;
    }
    if (ext & proto_v6) {
	if (i < len) str[i++] = sep;
	sep = ',';
	if (ext & proto_ip_only) {
	    strncpy(str+i, "v6only", len-i);
	    i += 6;
	} else {
	    strncpy(str+i, "v6", len-i);
	    i += 2;
	}
    } else if (ext & proto_ip_only) {
	sep = ',';
	strncpy(str+i, "v4only", len-i);
	i += 6;
    }
    if (ext & proto_base) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "base", len-i);
	i += 4;
    }
    if (ext & proto_block) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "block", len-i);
	i += 5;
    }
    if (ext & proto_ident) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "ident", len-i);
	i += 5;
    }
    if (ext & proto_nobackup) {
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "nobackup", len-i);
	i += 8;
    }
    switch(ext & proto_command) {
    case command_ihead:
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "proxy", len-i);
	i += 5;
	break;
    case command_iheads:
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "mproxy", len-i);
	i += 6;
	break;
    case command_pop:
	if (i < len) str[i++] = sep;
	sep = ',';
	strncpy(str+i, "apop", len-i);
	i += 4;
	break;
    }
    return str;
}

int islocalhost(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
	if (ntohl(((struct sockaddr_in*)sa)->sin_addr.s_addr) == 0x7F000001L)
	    return 1;	/* localhost */
	if (ntohl(((struct sockaddr_in*)sa)->sin_addr.s_addr) == 0L)
	    return -1;	/* null */
    }
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
	int i;
	struct in6_addr *addrp = &((struct sockaddr_in6*)sa)->sin6_addr;
	for (i=0; i < 12; i+=4)
	    if (*(u_long*)&addrp->s6_addr[i] != 0) return 0;
	if (*(u_long*)&addrp->s6_addr[i] == ntohl(1)) return 1;	/* localhost */
	if (*(u_long*)&addrp->s6_addr[i] == 0) return -1;	/* null */
    }
#endif
    return 0;
}

#ifdef NO_ADDRINFO
#define NTRY_MAX	10
#define NI_NUMERICHOST	1

char *addr2str(struct sockaddr *sa, socklen_t salen,
	       char *str, int len, int flags) {
    struct hostent *ent;
    struct in_addr *addr;
    int ntry = NTRY_MAX;
    if (!str || len <= 1) return "";
    str[len-1] = '\0';
    if (sa->sa_family != AF_INET) {
	message(LOG_ERR, "Unknown family=%d", sa->sa_family);
	strncpy(str, "?.?.?.?", len-1);
	return str;
    }
    addr = &((struct sockaddr_in*)sa)->sin_addr;
    addr2ip(addr, str, len);
    if (!AddrFlag || flags) {
	do {
	    ent = gethostbyaddr((char*)&addr->s_addr,
				sizeof(addr->s_addr), AF_INET);
	    if (ent) {
		strncpy(str, ent->h_name, len-1);
		return str;
	    }
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
	message(LOG_ERR, "Unknown address: %s err=%d", str, h_errno);
    }
    return str;
}

char *addrport2str(struct sockaddr *sa, socklen_t salen,
		   int proto, char *str, int len, int flags) {
    struct servent *ent;
    int port;
    int i = 0;
    if (!str || len <= 1) return "";
    str[len-1] = '\0';
    if (sa->sa_family == AF_INET) {
	addr2str(sa, salen, str, len, 0);
	i = strlen(str);
	if (i < len-2) {
	    str[i++] = ':';
	    str[i] = '\0';
	}
    } else {
	message(LOG_ERR, "Unknown address family=%d len=%d",
		sa->sa_family, salen);
    }
    port = ((struct sockaddr_in*)sa)->sin_port;
    if (!AddrFlag) {
	ent = getservbyport(port, ((proto & proto_udp) ? "udp" : "tcp"));
	if (ent) strncpy(str+i, ent->s_name, len-i-5);
    }
    if (str[i] == '\0')
	snprintf(str+i, len-i-5, "%d", ntohs((unsigned short)port));
    i = strlen(str);
    ext2str(proto, str+i, len-i);
    return str;
}
#else
char *addr2str(struct sockaddr *sa, socklen_t salen,
	       char *str, int len, int flags) {
    int err;
    if (AddrFlag) flags |= NI_NUMERICHOST;
    err = getnameinfo(sa, salen, str, len, NULL, 0, flags);
    if (err) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	addr2numeric(sa, str, len);
	if (len >= 1) str[len-1] = '\0';
	message(LOG_ERR, "Unknown address: %s err=%d errno=%d",
		str, err, errno);
    }
    return str;
}

char *addrport2str(struct sockaddr *sa, socklen_t salen,
		   int proto, char *str, int len, int flags) {
    char serv[STRMAX+1];
    int err;
    int i;
    if (!str || len <= 1) return "";
    str[len-1] = '\0';
    serv[0] = '\0';
    if (AddrFlag) flags |= (NI_NUMERICHOST | NI_NUMERICSERV);
    else if (proto & proto_udp) flags |= NI_DGRAM;
    if (!(flags & NI_NUMERICHOST) && islocalhost(sa)) flags |= NI_NUMERICHOST;
    if (Debug > 10) {
	addr2numeric(sa, serv, STRMAX);
	serv[STRMAX] = '\0';
	message(LOG_DEBUG, "getnameinfo: %s family=%d len=%d flags=%d",
		serv, sa->sa_family, salen, flags);
    }
#ifndef NO_UNIXDOMAIN
    if (sa->sa_family == AF_UNIX) {
	int j;
	j = salen - (((struct sockaddr_un*)sa)->sun_path - (char*)sa);
	strncpy(serv, ((struct sockaddr_un*)sa)->sun_path, j);
	serv[j] = '\0';
	snprintf(str, len, "%s", "unix");
	err = 0;
    } else
#endif
	err = getnameinfo(sa, salen, str, len, serv, STRMAX, flags);
#ifdef WSANO_DATA
    if (err == WSANO_DATA && !(flags & NI_NUMERICSERV)) {
	/*
	  WinSock32 returns WSANO_DATA if serv can't be lookup although
	  the hostname itself is resolvable.  So we must call again
	  without looking up serv
	*/
	if (Debug > 10)
	    message(LOG_DEBUG, "getnameinfo: WSANO_DATA flags=%d", flags);
	flags |= NI_NUMERICSERV;
	err = getnameinfo(sa, salen, str, len, serv, STRMAX, flags);
    }
#endif
    if (err) {
	if (sa->sa_family == AF_INET) {
	    addr2ip(&((struct sockaddr_in*)sa)->sin_addr, str, len);
	    i = strlen(str);
	    snprintf(str+i, len-i-5, ":%d",
		     ntohs(((struct sockaddr_in*)sa)->sin_port));
#ifdef AF_INET6
	} else if (sa->sa_family == AF_INET6) {
	    addr2ip6(&((struct sockaddr_in6*)sa)->sin6_addr, str, len);
	    i = strlen(str);
	    snprintf(str+i, len-i-5, ":%d",
		     ntohs(((struct sockaddr_in6*)sa)->sin6_port));
#endif
	} else {
	    snprintf(str, len, "%s:?", "???");
	}
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "Unknown node:serv %s len=%d err=%d errno=%d",
		str, salen, err, errno);
    } else {
	i = strlen(str);
	snprintf(str+i, len-i, ":%s", serv);
    }
    i = strlen(str);
    ext2str(proto, str+i, len-i);
    return str;
}
#endif

int isdigitstr(char *str) {
    while (*str && !isspace(*str)) {
	if (!isdigit(*str)) return 0;
	str++;
    }
    return 1;
}

int isdigitaddr(char *name) {
    int ndigits = 0;
    int isdot = 1;
    while(*name) {
	if (*name == '.') {
	    if (isdot) return 0;	/* `.' appears twice */
	    isdot = 1;
	} else if (isdigit(*name)) {
	    if (isdot) ndigits++;
	    isdot = 0;
	} else {
	    return 0;	/* not digit nor dot */
	}
	name++;
    }
    return ndigits;
}

/* set port into struct sockaddr */
void saPort(struct sockaddr *sa, u_short port) {
    if (sa->sa_family == AF_INET) {
	((struct sockaddr_in*)sa)->sin_port = htons(port);
	return;
    }
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
	((struct sockaddr_in6*)sa)->sin6_port = htons(port);
	return;
    }
#endif
    message(LOG_ERR, "saPort: unknown family=%d", sa->sa_family);
}

/* get port from struct sockaddr */
int getport(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
	return ntohs(((struct sockaddr_in*)sa)->sin_port);
#ifdef AF_INET6
    } else if (sa->sa_family == AF_INET6) {
	return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
#endif
    }
    return -1;
}

int hostPortExt(char *str, char *host, char *port) {
    int port_pos = 0;
    int ext_pos = 0;
    int i;
    for (i=0; i < STRMAX && str[i]; i++) {
	host[i] = str[i];
	port[i-port_pos] = str[i];
	if (str[i] == ':') port_pos = i+1;
	if (str[i] == '/') ext_pos = i+1;
    }
    if (!port_pos) return -1;	/* illegal format */
    host[port_pos-1] = '\0';
    if (ext_pos) port[ext_pos - port_pos - 1] = '\0';
    else port[i - port_pos] = '\0';
    return ext_pos;
}

#ifdef NO_ADDRINFO
int str2port(char *str, char *proto) {	/* host byte order */
    struct servent *ent;
    ent = getservbyname(str, proto);
    if (ent) {
	return ntohs(ent->s_port);
    } else if (isdigitstr(str)) {
	return atoi(str);
    } else {
	return -1;
    }
}

int host2sa(char *name, char *serv, struct sockaddr *sa, socklen_t *salenp,
	    int *socktypep, int *protocolp, int flags) {
    struct hostent *hp;
    int ntry = NTRY_MAX;
    int port = -1;
    struct sockaddr_in *sinp = (struct sockaddr_in*)sa;
    struct in_addr *addrp = &sinp->sin_addr;
    if (*salenp < sizeof(struct sockaddr_in)) {
	message(LOG_ERR, "host2sa: too small salen=%d", *salenp);
	return 0;	/* too small */
    }
    *salenp = sizeof(struct sockaddr_in);
    if (!name) {
	bzero(sa, *salenp);
	sa->sa_family = AF_INET;
	goto hostok;
    }
    if (isdigitaddr(name)) {
	if ((addrp->s_addr=inet_addr(name)) != -1) {
	    sa->sa_family = AF_INET;
	    goto hostok;
	}
    } else {
	do {
	    hp = gethostbyname(name);
	    if (hp) {
		bcopy(hp->h_addr, (char *)addrp, hp->h_length);
		sa->sa_family = hp->h_addrtype;
	    hostok:
		if (serv) {
		    if (protocolp && *protocolp == IPPROTO_UDP) {
			port = str2port(serv, "udp");
		    } else {
			port = str2port(serv, "tcp");
		    }
		    if (port < 0) {
			message(LOG_ERR, "Unknown service: %s", serv);
			return 0;
		    }
		    saPort(sa, port);
		}
		return 1;
	    }
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
    }
    message(LOG_ERR, "Unknown host: %s err=%d", name, h_errno);
    return 0;
}
#else
int host2sa(char *name, char *serv, struct sockaddr *sa, socklen_t *salenp,
	    int *socktypep, int *protocolp, int flags) {
    struct addrinfo *ai = NULL;
    struct addrinfo hint;
    int err;
    hint.ai_flags = flags;
    hint.ai_family = sa->sa_family;
    if (socktypep) hint.ai_socktype = *socktypep;
    else hint.ai_socktype = SOCK_STREAM;
    if (protocolp) hint.ai_protocol = *protocolp;
    else hint.ai_protocol = 0;
    hint.ai_addrlen = 0;
    hint.ai_addr = NULL;
    hint.ai_canonname = NULL;
    hint.ai_next = NULL;
    if (Debug > 10) {
	message(LOG_DEBUG, "getaddrinfo: %s:%s family=%d socktype=%d flags=%d",
		(name ? name : ""), (serv ? serv : ""),
		sa->sa_family, hint.ai_socktype, flags);
    }
    err = getaddrinfo(name, serv, &hint, &ai);
    if (err != 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "getaddrinfo for %s:%s failed err=%d errno=%d",
		(name ? name : ""), (serv ? serv : ""), err, errno);
    fail:
	if (ai) freeaddrinfo(ai);
	return 0;
    }
    if (ai->ai_addrlen > *salenp) {
	message(LOG_ERR,
		"getaddrinfo for %s:%s returns unexpected addr size=%d",
		(name ? name : ""), (serv ? serv : ""), ai->ai_addrlen);
	goto fail;
    }
    *salenp = ai->ai_addrlen;
    if (socktypep) *socktypep = ai->ai_socktype;
    if (protocolp) *protocolp = ai->ai_protocol;
    bcopy(ai->ai_addr, sa, *salenp);
    freeaddrinfo(ai);
    return 1;
}
#endif

int hostPort2sa(char *str, struct sockaddr *sa, socklen_t *salenp, int flags) {
    char host[STRMAX+1];
    char port[STRMAX+1];
    int pos = hostPortExt(str, host, port);
    if (pos < 0) return 0;
#ifdef AF_INET6
    if (pos && !strcmp(str+pos, "v6")) sa->sa_family = AF_INET6;
#endif
    return host2sa(host, port, sa, salenp, NULL, NULL, flags);
}

SockAddr *saDup(struct sockaddr *sa, socklen_t salen) {
    SockAddr *ret = malloc(SockAddrBaseSize + salen);
    if (ret) {
	bcopy(sa, &ret->addr, salen);
	ret->len = salen;
    }
    return ret;
}

int saComp(struct sockaddr *a, struct sockaddr *b) {
    if (a->sa_family != b->sa_family) {
	if (Debug > 10) {
	    message(LOG_DEBUG, "saComp: sa_family differ: %d, %d",
		    a->sa_family, b->sa_family);
	}
	return 0;
    }
    if (a->sa_family == AF_INET) {
	struct in_addr *an, *bn;
	short ap, bp;
	an = &((struct sockaddr_in*)a)->sin_addr;
	bn = &((struct sockaddr_in*)b)->sin_addr;
	ap = ((struct sockaddr_in*)a)->sin_port;
	bp = ((struct sockaddr_in*)b)->sin_port;
	if (Debug > 10) {
	    message(LOG_DEBUG, "saComp: %lx:%d, %lx:%d",
		    (long unsigned)ntohl(an->s_addr), ntohs(ap),
		    (long unsigned)ntohl(bn->s_addr), ntohs(bp));
	}
	return (an->s_addr == bn->s_addr) && (ap == bp);
    }
#ifdef AF_INET6
    if (a->sa_family == AF_INET6) {
	struct in6_addr *an, *bn;
	short ap, bp;
	int i;
	an = &((struct sockaddr_in6*)a)->sin6_addr;
	bn = &((struct sockaddr_in6*)b)->sin6_addr;
	ap = ((struct sockaddr_in6*)a)->sin6_port;
	bp = ((struct sockaddr_in6*)b)->sin6_port;
	if (ap != bp) return 0;
	for (i=0; i < 16; i+=4)
	    if (*(u_long*)&an->s6_addr[i]
		!= *(u_long*)&bn->s6_addr[i]) return 0;
	return 1;
    }
#endif
    message(LOG_ERR, "saComp: unknown family=%d", a->sa_family);
    return 0;
}

/* *addrp is permitted to connect to *stonep ? */
XHosts *checkXhost(XHosts *xhosts, struct sockaddr *sa, socklen_t salen) {
    int match = 1;
    if (!xhosts) return XHostsTrue; /* any hosts can access */
    for (; xhosts != NULL; xhosts = xhosts->next) {
	if (xhosts->mbits < 0) {
	    match = !match;
	    continue;
	}
	if (sa->sa_family == AF_INET
	    && xhosts->xhost.addr.sa_family == AF_INET) {
	    if (xhosts->mbits > 0) {
		u_long addr = ntohl(((struct sockaddr_in*)sa)
				    ->sin_addr.s_addr);
		u_long xadr = ntohl(((struct sockaddr_in*)&xhosts->xhost.addr)
				    ->sin_addr.s_addr);
		u_long bits = ((u_long)~0 << (32 - xhosts->mbits));
		if ((addr & bits) != (xadr & bits)) continue;
	    }
	    if (match) return xhosts;
	    return NULL;
#ifdef AF_INET6
	} else if (sa->sa_family == AF_INET6
		   && xhosts->xhost.addr.sa_family == AF_INET6) {
	    struct in6_addr *adrp = &((struct sockaddr_in6*)sa)->sin6_addr;
	    struct in6_addr *xadp = &((struct sockaddr_in6*)
				      &xhosts->xhost.addr)->sin6_addr;
	    int j, k;
	    for (j=0, k=xhosts->mbits; k > 0; j+=4, k -= 32) {
		u_long addr, xadr, mask;
		addr = ntohl(*(u_long*)&adrp->s6_addr[j]);
		xadr = ntohl(*(u_long*)&xadp->s6_addr[j]);
		if (k >= 32) mask = (u_long)~0;
		else mask = ((u_long)~0 << (32-k));	/* premise: k > 0 */
		if (Debug > 12)
		    message(LOG_DEBUG, "compare addr=%lx x=%lx m=%lx",
			    addr, xadr, mask);
		if ((addr & mask) != (xadr & mask)) break;
	    }
	    if (k <= 0) {
		if (match) return xhosts;
		return NULL;
	    }
	} else if (sa->sa_family == AF_INET6
		   && xhosts->xhost.addr.sa_family == AF_INET) {
	    struct in6_addr *adrp = &((struct sockaddr_in6*)sa)->sin6_addr;
	    if (*(u_long*)&adrp->s6_addr[0] != 0
		|| *(u_long*)&adrp->s6_addr[4] != 0
		|| ntohl(*(u_long*)&adrp->s6_addr[8]) != 0xFFFF) continue;
	    if (xhosts->mbits > 0) {
		u_long addr = ntohl(*(u_long*)&adrp->s6_addr[12]);
		u_long xadr = ntohl(((struct sockaddr_in*)&xhosts->xhost.addr)
				    ->sin_addr.s_addr);
		u_long bits = ((u_long)~0 << (32 - xhosts->mbits));
		if ((addr & bits) != (xadr & bits)) continue;
	    }
	    if (match) return xhosts;
	    return NULL;
#endif
	}
    }
    if (!match) return XHostsTrue;
    return NULL;
}

#ifdef WINDOWS
void waitMutex(HANDLE h) {
    DWORD ret;
    if (h) {
	ret = WaitForSingleObject(h, 5000);	/* 5 sec */
	if (ret == WAIT_FAILED) {
	    message(LOG_ERR, "Fail to wait mutex err=%d, existing",
		    (int)GetLastError());
	    exit(1);
	} else if (ret == WAIT_TIMEOUT) {
	    message(LOG_ERR, "timeout to wait mutex, existing");
	    exit(1);
	}
    }
}

void freeMutex(HANDLE h) {
    if (h) {
	if (!ReleaseMutex(h)) {
	    message(LOG_ERR, "Fail to release mutex err=%d",
		    (int)GetLastError());
	}
    }
}
#else	/* ! WINDOWS */
#ifdef OS2
void waitMutex(HMTX h) {
    APIRET ret;
    if (h) {
	ret = DosRequestMutexSem(h, 500);	/* 0.5 sec */
	if (ret == ERROR_TIMEOUT) {
	    message(LOG_WARNING, "timeout to wait mutex");
	} else if (ret) {
	    message(LOG_ERR, "Fail to request mutex err=%d", ret);
	}
    }
}

void freeMutex(HMTX h) {
    APIRET ret;
    if (h) {
	ret = DosReleaseMutexSem(h);
	if (ret) {
	    message(LOG_ERR, "Fail to release mutex err=%d", ret);
	}
    }
}
#else	/* ! OS2 & ! WINDOWS */
#ifdef PTHREAD
void waitMutex(int h) {
    int err;
    for (;;) {
	err = pthread_mutex_lock(&FastMutex);
	if (err) {
	    message(LOG_ERR, "Mutex %d err=%d", h, err);
	}
	if (FastMutexs[h] == 0) {
	    int i = ++FastMutexs[h];
	    pthread_mutex_unlock(&FastMutex);
	    if (Debug > 20) message(LOG_DEBUG, "Lock Mutex %d = %d", h, i);
	    break;
	}
	pthread_mutex_unlock(&FastMutex);
	if (Debug > 10) message(LOG_DEBUG, "Mutex conflict %d = %d",
				h, FastMutexs[h]);
	MutexConflict++;
	usleep(100);
    }
}

void freeMutex(int h) {
    int err = pthread_mutex_lock(&FastMutex);
    if (err) {
	message(LOG_ERR, "Mutex %d err=%d", h, err);
    }
    if (FastMutexs[h] > 0) {
	if (FastMutexs[h] > 1)
	    message(LOG_ERR, "Mutex %d Locked Recursively (%d)",
		    h, FastMutexs[h]);
	FastMutexs[h]--;
	if (Debug > 20) message(LOG_DEBUG, "Unlock Mutex %d = %d",
				h, FastMutexs[h]);
    }
    pthread_mutex_unlock(&FastMutex);
}
#else	/* ! OS2 & ! WINDOWS & PTHREAD */
#define waitMutex(sem)	/* */
#define freeMutex(sem)	/* */
#endif
#endif
#endif

/* backup */

int healthCheck(struct sockaddr *sa, socklen_t salen,
		int proto, int timeout, Chat *chat) {
    SOCKET sd;
    int ret;
    char addrport[STRMAX+1];
#ifdef WINDOWS
    u_long param;
#endif
    time_t start, now;
#ifdef USE_EPOLL
    int epfd = epoll_create(BACKLOG_MAX);
    struct epoll_event ev;
    struct epoll_event evs[1];
    if (epfd < 0) {
	message(LOG_ERR, "health check: can't create epoll err=%d", errno);
	return 1;	/* I can't tell the master is healthy or not */
    }
    ev.events = (EPOLLOUT | EPOLLONESHOT);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev) < 0) {
	message(LOG_ERR, "health check: epoll_ctl ADD err=%d", errno);
	close(epfd);
	return 1;	/* I can't tell the master is healthy or not */
    }
#endif
    time(&start);
    sd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (InvalidSocket(sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "health check: can't create socket err=%d",
		errno);
#ifdef USE_EPOLL
	close(epfd);
#endif
	return 1;	/* I can't tell the master is healthy or not */
    }
    addrport2str(sa, salen, (proto & proto_pair_d), addrport, STRMAX, 0);
    addrport[STRMAX] = '\0';
    if (!(proto & proto_block_d)) {
#ifdef WINDOWS
	param = 1;
	ioctlsocket(sd, FIONBIO, &param);
#else
	fcntl(sd, F_SETFL, O_NONBLOCK);
#endif
    }
    ret = connect(sd, sa, salen);
    if (ret < 0) {
#ifdef WINDOWS
        errno = WSAGetLastError();
#endif
	if (errno == EINPROGRESS) {
#ifndef USE_EPOLL
	    fd_set wout;
	    struct timeval tv;
#endif
	    int optval;
	    socklen_t optlen = sizeof(optval);
	    do {
		time(&now);
		if (now - start >= timeout) goto timeout;
#ifndef USE_EPOLL
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&wout);
		FdSet(sd, &wout);
#endif
	    } while (
#ifdef USE_EPOLL
		epoll_wait(epfd, evs, 1, 1000) == 0
#else
		select(FD_SETSIZE, NULL, &wout, NULL, &tv) == 0
#endif
		);
	    getsockopt(sd, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
	    if (optval) {
		message(LOG_ERR, "health check: connect %s getsockopt err=%d",
			addrport, optval);
		goto fail;
	    }
	} else {
	    message(LOG_ERR, "health check: connect %s err=%d",
		    addrport, errno);
	    goto fail;
	}
    }
    time(&now);
    if (now - start >= timeout) goto timeout;
    while (chat) {
	char buf[BUFMAX];
	int len;
	int err;
	ret = send(sd, chat->send, chat->len, 0);
	if (ret < 0 || ret != chat->len) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "health check: send %s err=%d",
		    addrport, errno);
	    goto fail;
	}
	len = 0;
	do {
#ifdef USE_EPOLL
	    ev.events = (EPOLLIN | EPOLLONESHOT);
	    epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	    fd_set rout;
	    struct timeval tv;
#endif
	    do {
		time(&now);
		if (now - start >= timeout) goto timeout;
#ifndef USE_EPOLL
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rout);
		FdSet(sd, &rout);
#endif
	    } while (
#ifdef USE_EPOLL
		epoll_wait(epfd, evs, 1, 1000) == 0
#else
		select(FD_SETSIZE, &rout, NULL, NULL, &tv) == 0
#endif
		);
	    ret = recv(sd, buf+len, BUFMAX-1-len, 0);
	    if (ret < 0) {
#ifdef WINDOWS
		errno = WSAGetLastError();
#endif
		message(LOG_ERR, "health check: recv from %s err=%d",
			addrport, errno);
		goto fail;
	    }
	    len += ret;
	    buf[len] = '\0';
	    err = regexec(&chat->expect, buf, 0, NULL, 0);
	    if (Debug > 8)
		message(LOG_DEBUG, "health check: %s regexec=%d",
			addrport, err);
	    if (len > BUFMAX/2) {
		bcopy(buf+(len-BUFMAX/2), buf, BUFMAX/2);
		len = BUFMAX/2;
	    }
	} while (ret > 0 && err == REG_NOMATCH);
#ifndef REG_NOERROR
#ifdef REG_OK
#define	REG_NOERROR	REG_OK
#else
#define	REG_NOERROR	0
#endif
#endif
	if (err != REG_NOERROR) goto fail;
	chat = chat->next;
    }
    shutdown(sd, 2);
#ifdef USE_EPOLL
    close(epfd);
#endif
    closesocket(sd);
    return 1;	/* healthy ! */
 timeout:
    if (Debug > 8)
	message(LOG_DEBUG, "health check: %s timeout", addrport);
 fail:
    shutdown(sd, 2);
#ifdef USE_EPOLL
    close(epfd);
#endif
    closesocket(sd);
    return 0;	/* fail */
}

void asyncHealthCheck(Backup *b) {
    time_t now;
    char addrport[STRMAX+1];
    ASYNC_BEGIN;
    time(&now);
    b->last = now + 60 * 60;	/* suppress further check */
    addrport2str(&b->check->addr, b->check->len,
		 (b->proto & proto_pair_d), addrport, STRMAX, 0);
    addrport[STRMAX] = '\0';
    if (Debug > 8)
	message(LOG_DEBUG, "asyncHealthCheck %s", addrport);
    if (healthCheck(&b->check->addr, b->check->len,
		    b->proto, b->interval, b->chat)) {	/* healthy ? */
	if (Debug > 3 || (b->bn && Debug > 1))
	    message(LOG_DEBUG, "health check %s success", addrport);
	if (b->bn) b->bn = 0;
    } else {	/* unhealthy */
	if (Debug > 3 || (b->bn == 0 && Debug > 0))
	    message(LOG_DEBUG, "health check %s fail", addrport);
	if (b->bn == 0) b->bn++;
    }
    b->last = now;
    ASYNC_END;
}

void scanBackups(void) {
    Backup *b;
    time_t now;
    time(&now);
    for (b=backups; b != NULL; b=b->next) {
	if (b->used < 2) continue;		/* not used */
	if (b->interval <= 0 || now - b->last < b->interval) continue;
	ASYNC(asyncHealthCheck, b);
    }
}

Backup *findBackup(struct sockaddr *sa) {
    Backup *b;
    for (b=backups; b != NULL; b=b->next) {
	if (saComp(sa, &b->master->addr)) {	/* found */
	    if (Debug > 1) {
		char mhostport[STRMAX+1];
		char bhostport[STRMAX+1];
		addrport2str(&b->master->addr, b->master->len,
			     (b->proto & proto_pair_d), mhostport, STRMAX, 0);
		mhostport[STRMAX] = '\0';
		addrport2str(&b->backup->addr, b->backup->len,
			     (b->proto & proto_pair_d), bhostport, STRMAX, 0);
		bhostport[STRMAX] = '\0';
		message(LOG_DEBUG, "master %s backup %s interval %d",
			mhostport, bhostport, b->interval);
	    }
	    return b;
	}
    }
    return NULL;
}

int gcd(int a, int b) {
    int m;
    if (a > b) {
	m = a % b;
	if (m == 0) return b;
	return gcd(m, b);
    } else {
	m = b % a;
	if (m == 0) return a;
	return gcd(m, a);
    }
}

int mkBackup(int argc, int argi, char *argv[]) {
    char master_host[STRMAX+1];
    char master_port[STRMAX+1];
    char *master_ext = NULL;
    char backup_host[STRMAX+1];
    char backup_port[STRMAX+1];
    int pos;
    char *check_host = NULL;
    char *check_port = NULL;
    char *check_ext = NULL;
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t salen;
    Backup *b = malloc(sizeof(Backup));
    argi++;
    for ( ; argi < argc; argi++) {
	if (!strncmp(argv[argi], "host=", 5)) {
	    check_host = argv[argi]+5;
	} else if (!strncmp(argv[argi], "port=", 5)) {
	    check_port = argv[argi]+5;
	} else if (!strncmp(argv[argi], "ext=", 4)) {
	    check_ext = argv[argi]+4;
	} else {
	    break;
	}
    }
    if (argi+2 >= argc) {
	message(LOG_ERR, "Irregular backup option");
	exit(1);
    }
    if (b) {
	b->last = 0;
	b->bn = 0;	/* healthy */
	b->used = 0;
	b->interval = atoi(argv[argi]);
    } else {
    memerr:
	message(LOG_CRIT, "Out of memory, no backup for %s", argv[argi+1]);
	return argi+2;
    }
    if (b->interval > 0) {
	if (MinInterval > 0) {
	    MinInterval = gcd(MinInterval, b->interval);
	} else {
	    MinInterval = b->interval;
	}
    } else {
	b->bn = 1;	/* force unhealthy */
    }
    b->proto = 0;
    pos = hostPortExt(argv[argi+1], master_host, master_port);
    if (pos < 0) {
	message(LOG_ERR, "Illegal master: %s", argv[argi+1]);
	free(b);
	return argi+2;
    } else if (pos > 0) {
	master_ext = argv[argi+1] + pos;
    }
    salen = sizeof(ss);
    sa->sa_family = AF_UNSPEC;
#ifdef AF_INET6
    if (master_ext && !strcmp(master_ext, "v6")) sa->sa_family = AF_INET6;
#endif
    if (host2sa(master_host, master_port, sa, &salen, NULL, NULL, 0)) {
	b->master = saDup(sa, salen);
	if (!b->master) {
	    free(b);
	    goto memerr;
	}
	b->check = b->master;
    } else {
	free(b);
	return argi+2;
    }
    pos = hostPortExt(argv[argi+2], backup_host, backup_port);
    if (pos < 0) {
	message(LOG_ERR, "Illegal backup: %s", argv[argi+2]);
	free(b);
	return argi+2;
    }
    salen = sizeof(ss);
    sa->sa_family = AF_UNSPEC;
#ifdef AF_INET6
    if (pos && !strcmp(argv[argi+2]+pos, "v6")) sa->sa_family = AF_INET6;
#endif
    if (host2sa(backup_host, backup_port, sa, &salen, NULL, NULL, 0)) {
	b->backup = saDup(sa, salen);
	if (!b->backup) {
	    free(b->master);
	    free(b);
	    goto memerr;
	}
    } else {
	free(b->master);
	free(b);
	return argi+2;
    }
    if (check_host || check_port || check_ext) {
	if (!check_host) check_host = master_host;
	if (!check_port) check_port = master_port;
	if (!check_ext)  check_ext  = master_ext;
	salen = sizeof(ss);
	sa->sa_family = AF_UNSPEC;
#ifdef AF_INET6
	if (check_ext && !strcmp(check_ext, "v6")) sa->sa_family = AF_INET6;
#endif
	if (host2sa(check_host, check_port, sa, &salen, NULL, NULL, 0)) {
	    b->check = saDup(sa, salen);
	    if (!b->check) {
		free(b->backup);
		free(b->master);
		free(b);
		goto memerr;
	    }
	}
    }
    b->chat = healthChat;
    b->next = backups;
    backups = b;
    return argi+2;
}

int str2num(char **pp, int rad) {
    char *p;
    int num;
    int i;
    p = *pp;
    num = 0;
    for (i=0; i < 3; i++) {	/* 3 digit at most */
	char c = p[i];
	if ('0' <= c && c <= '9') {
	    num = num * rad + c;
	} else {
	    c = toupper(c);
	    if (rad > 10 && ('A' <= c && c <= ('A' + rad - 11))) {
		num = num * rad + (c - 'A' + 10);
	    } else {
		break;
	    }
	}
    }
    *pp = p;
    return num;
}

char *str2bin(char *p, int *lenp) {
    char buf[BUFMAX];
    char c;
    int i = 0;
    while ((c=*p++) && i < BUFMAX-5) {
	if (c == '\\') {
	    c = *p++;
	    switch(c) {
	    case 'n':  c = '\n';  break;
	    case 'r':  c = '\r';  break;
	    case 't':  c = '\t';  break;
	    case '0':  c = str2num(&p,  8);  break;
	    case 'x':  c = str2num(&p, 16);  break;
	    case '\0':
		c = '\\';
		p--;
	    }
	}
	buf[i++] = c;
    }
    p = malloc(i);
    if (!p) {
	message(LOG_CRIT, "Out of memory, can't make str");
	exit(1);
    }
    bcopy(buf, p, i);
    *lenp = i;
    return p;
}

int mkChat(int argc, int i, char *argv[]) {
    Chat *top, *bot;
    top = bot = NULL;
    i++;
    for ( ; i+1 < argc; i+=2) {
	Chat *cur;
	int err;
	if (argv[i][0] == '-' && argv[i][1] == '-') {
	    healthChat = top;
	    return i;
	}
	cur = malloc(sizeof(Chat));
	if (!cur) {
	memerr:
	    message(LOG_CRIT, "Out of memory, can't make Chat");
	    exit(1);
	}
	cur->send = str2bin(argv[i], &cur->len);
	if (!cur->send) {
	    free(cur);
	    goto memerr;
	}
	err = regcomp(&cur->expect, argv[i+1], REG_EXTENDED);
	if (err) {
	    message(LOG_ERR, "RegEx compiling error: \"%s\" err=%d",
		    argv[i+1], err);
	    exit(1);
	}
	cur->next = NULL;
	if (!top) top = cur;
	if (bot) bot->next = cur;
	bot = cur;
    }
    message(LOG_ERR, "chat script ends unexpectedly");
    exit(1);
    return i;
}

LBSet *findLBSet(struct sockaddr *sa) {
    LBSet *s;
    for (s=lbsets; s != NULL; s=s->next) {
	if (saComp(&s->dsts[0]->addr, sa)) {	/* found */
	    if (Debug > 1) {
		char buf[LONGSTRMAX+1];
		int len;
		int i;
		buf[LONGSTRMAX] = '\0';
		strcpy(buf, "LB set:");
		len = strlen(buf);
		for (i=0; i < s->ndsts && len < LONGSTRMAX-2; i++) {
		    buf[len++] = ' ';
		    addrport2str(&s->dsts[i]->addr, s->dsts[i]->len,
				 (s->proto & proto_pair_d),
				 buf+len, LONGSTRMAX-1-len, 0);
		    len += strlen(buf+len);
		}
		message(LOG_DEBUG, "%s", buf);
	    }
	    return s;
	}
    }
    return NULL;
}

int lbsopts(int argc, int i, char *argv[]) {
    SockAddr *dsts[LB_MAX];
    int ndsts = 0;
    LBSet *lbs;
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t salen;
    int proto = 0;
    i++;
    for ( ; i < argc; i++) {
	if (argv[i][0] == '-' && argv[i][1] == '-') break;
	if (ndsts >= LB_MAX) {
	    message(LOG_ERR, "Too many load balancing hosts");
	    exit(1);
	}
	salen = sizeof(ss);
	sa->sa_family = AF_UNSPEC;
	if (!hostPort2sa(argv[i], sa, &salen, 0)) {
	    message(LOG_ERR, "Illegal load balancing host: %s", argv[i]);
	    exit(1);
	}
	dsts[ndsts] = saDup(sa, salen);
	if (!dsts[ndsts]) goto memerr;
	ndsts++;
    }
    lbs = malloc(sizeof(LBSet) + sizeof(SockAddr*) * ndsts);
    if (lbs) {
	int j;
	lbs->next = lbsets;
	lbs->proto = proto;
	lbs->ndsts = ndsts;
	for (j=0; j < ndsts; j++) lbs->dsts[j] = dsts[j];
	lbsets = lbs;
    } else {
    memerr:
	message(LOG_CRIT, "Out of memory, can't make LB set");
	exit(1);
    }
    return i;
}

char *stone2str(Stone *stonep, char *str, int strlen) {
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    int salen = sizeof(ss);
    int proto;
    char src[STRMAX+1];
    if (getsockname(stonep->sd, sa, &salen) < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "stone %d: Can't get socket's name err=%d",
		stonep->sd, errno);
	str[0] = '\0';
	return NULL;
    }
    addrport2str(sa, salen, (stonep->proto & proto_stone_s), src, STRMAX, 0);
    src[STRMAX] = '\0';
    proto = stonep->proto;
    if ((proto & proto_command) == command_proxy) {
	snprintf(str, strlen, "stone %d: proxy <- %s", stonep->sd, src);
    } else if ((proto & proto_command) == command_health) {
	snprintf(str, strlen, "stone %d: health <- %s", stonep->sd, src);
    } else if ((proto & proto_command) == command_identd) {
	snprintf(str, strlen, "stone %d: identd <- %s", stonep->sd, src);
    } else {
	char dst[STRMAX+1];
	addrport2str(&stonep->dsts[0]->addr, stonep->dsts[0]->len,
		     (stonep->proto & proto_stone_d), dst, STRMAX, 0);
	dst[STRMAX] = '\0';
	snprintf(str, strlen, "stone %d: %s <- %s", stonep->sd, dst, src);
    }
    str[strlen] = '\0';
    return str;
}


/* relay UDP */

void message_origin(int pri, Origin *origin) {
    struct sockaddr_storage ss;
    struct sockaddr *name = (struct sockaddr*)&ss;
    socklen_t namelen = sizeof(ss);
    SOCKET sd;
    Stone *stone;
    int i;
    char str[LONGSTRMAX+1];
    str[LONGSTRMAX] = '\0';
    strntime(str, LONGSTRMAX, &origin->clock, -1);
    i = strlen(str);
    if (ValidSocket(origin->sd)) {
	if (getsockname(origin->sd, name, &namelen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "%d UDP %d: Can't get socket's name err=%d",
			origin->stone->sd, origin->sd, errno);
	} else {
	    addrport2str(name, namelen, proto_udp, str+i, LONGSTRMAX-i, 0),
	    i = strlen(str);
	    if (i < LONGSTRMAX-2) str[i++] = ' ';
	}
    }
    if (i > LONGSTRMAX) i = LONGSTRMAX;
    str[i] = '\0';
    stone = origin->stone;
    if (stone) sd = stone->sd;
    else sd = INVALID_SOCKET;
    addrport2str(&origin->from->addr, origin->from->len, proto_udp,
		 str+i, STRMAX-i, 0);
    str[STRMAX] = '\0';
    message(pri, "%d UDP%3d:%3d %s", origin->stone->sd, origin->sd, sd, str);
}

void ungetPktBuf(PktBuf *pb) {
    if (pb->bufmax < pkt_len_max) {
	free(pb);	/* never reuse short buffer */
	return;
    }
    waitMutex(PkBufMutex);
    pb->next = freePktBuf;
    freePktBuf = pb;
    nFreePktBuf++;
    freeMutex(PkBufMutex);
}

PktBuf *getPktBuf(void) {
    PktBuf *ret = NULL;
    waitMutex(PkBufMutex);
    if (freePktBuf) {
	ret = freePktBuf;
	freePktBuf = ret->next;
	nFreePktBuf--;
    }
    freeMutex(PkBufMutex);
    if (ret && ret->bufmax < pkt_len_max) {
	free(ret);	/* discard short buffer */
	ret = NULL;
    }
    if (!ret) {
	int size = pkt_len_max;
	do {
	    ret = malloc(sizeof(PktBuf) + size - BUFMAX);
	} while (!ret && pkt_len_max > BUFMAX && (pkt_len_max /= 2));
	if (!ret) {
	    message(LOG_CRIT, "Out of memory, no ExBuf");
	    return ret;
	}
	ret->common = type_pktbuf;
	ret->bufmax = size;
    }
    ret->next = NULL;
    ret->origin = NULL;
    ret->len = 0;
    return ret;
}

void freeOrigin(Origin *origin) {
    if (origin->from) free(origin->from);
    free(origin);
}

Origin *getOrigins(struct sockaddr *from, socklen_t fromlen, Stone *stone) {
    Origin *origin;
    Origin *origins = (Origin*)stone->p;
    SOCKET sd;
#ifdef USE_EPOLL
    struct epoll_event ev;
#endif
    for (origin=origins->next; origin != NULL && origin->from;
	 origin=origin->next) {
	if (InvalidSocket(origin->sd)) continue;
	if (saComp(&origin->from->addr, from)) {
	    origin->lock = 1;	/* lock origin */
	    return origin;
	}
    }
    /* can't find origin, so create */
    sd = socket(from->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (InvalidSocket(sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "%d UDP: can't create datagram socket err=%d",
		stone->sd, errno);
	return NULL;
    }
    if (Debug > 3) {
	char addrport[STRMAX+1];
	message(LOG_DEBUG, "%d UDP %d: New origin %s",
		stone->sd, sd,
		addrport2str(from, fromlen, proto_udp, addrport, STRMAX, 0));
    }
    if (!(stone->proto & proto_block_d)) {
#ifdef WINDOWS
	u_long param;
	param = 1;
	ioctlsocket(sd, FIONBIO, &param);
#else
	fcntl(sd, F_SETFL, O_NONBLOCK);
#endif
    }
    origin = malloc(sizeof(Origin));
    if (!origin) {
    memerr:
	message(LOG_CRIT, "%d UDP %d: Out of memory, closing socket",
		stone->sd, sd);
	return NULL;
    }
    origin->common = type_origin;
    origin->sd = sd;
    origin->stone = stone;
    origin->from = saDup(from, fromlen);
    if (!origin->from) {
	free(origin);
	goto memerr;
    }
    origin->lock = 0;
    origin->xhost = NULL;
#ifdef USE_EPOLL
    ev.events = EPOLLIN;
    ev.data.ptr = origin;
    if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, sd, &ev) < 0) {
	message(LOG_ERR, "%d UDP %d: epoll_ctl ADD err=%d",
		stone->sd, sd, errno);
	freeOrigin(origin);
	return NULL;
    }
#else
    waitMutex(FdRinMutex);
    FdSet(origin->sd, &rin);
    freeMutex(FdRinMutex);
#endif
    waitMutex(OrigMutex);
    origin->next = origins->next;	/* insert origin */
    origins->next = origin;
    freeMutex(OrigMutex);
    return origin;
}

PktBuf *recvUDP(Stone *stone) {
    struct sockaddr_storage ss;
    struct sockaddr *from = (struct sockaddr*)&ss;
    socklen_t fromlen = sizeof(ss);
    Origin *origin;
    SOCKET sd;
    int flags = 0;
    char *dirstr;
    PktBuf *pb = getPktBuf();
    pb->type = (stone->common & type_mask);
    if (pb->type == type_origin) {
	origin = (Origin*)stone;
	sd = origin->sd;
	stone = origin->stone;
	dirstr = "<";
#ifdef MSG_DONTWAIT
	if (!(stone->proto & proto_block_d)) flags = MSG_DONTWAIT;
#endif
    } else {
	origin = NULL;
	sd = stone->sd;
	dirstr = ">";
#ifdef MSG_DONTWAIT
	if (!(stone->proto & proto_block_s)) flags = MSG_DONTWAIT;
#endif
    }
#ifdef MSG_TRUNC
    flags |= MSG_TRUNC;
#endif
    pb->len = recvfrom(sd, pb->buf, pb->bufmax, flags, from, &fromlen);
    if (pb->len < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EMSGSIZE) {
	    if (Debug > 4)
		message(LOG_DEBUG, "%d UDP%s%d: recvfrom received larger msg",
			stone->sd, dirstr, sd);
	    pb->len = pb->bufmax + 1;
	} else {
	    message(LOG_ERR, "%d UDP%s%d: recvfrom failed err=%d",
		    stone->sd, dirstr, sd, errno);
	end:
	    ungetPktBuf(pb);
	    return NULL;
	}
    }
    if (pb->type == type_stone) {	/* outward */
	XHosts *xhost = checkXhost(stone->xhosts, from, fromlen);
	if (!xhost) {
	    if (Debug > 4) {
		char addrport[STRMAX+1];
		addrport2str(from, fromlen, proto_udp, addrport, STRMAX, 0);
		addrport[STRMAX] = '\0';
		message(LOG_DEBUG, "%d UDP%s%d: recvfrom denied %s",
			stone->sd, dirstr, sd, addrport);
	    }
	    goto end;
	}
	origin = getOrigins(from, fromlen, stone);
	if (!origin) goto end;
	origin->xhost = xhost;
	time(&origin->clock);
    }
    pb->origin = origin;
    if (pb->len > pb->bufmax || Debug > 4) {
	char addrport[STRMAX+1];
	addrport2str(from, fromlen, proto_udp, addrport, STRMAX, 0);
	addrport[STRMAX] = '\0';
	if (Debug > 4)
	    message(LOG_DEBUG, "%d UDP%s%d: %d bytes received from %s",
		    stone->sd, dirstr, origin->sd, pb->len, addrport);
	if (pb->len > pb->bufmax) {
	    message(LOG_NOTICE, "%d UDP%s%d: recvfrom failed: larger packet "
		    "(%d bytes) arrived from %s",
		    stone->sd, dirstr, origin->sd, pb->len, addrport);
	    while (pkt_len_max < pb->len) pkt_len_max <<= 1;
	    ungetPktBuf(pb);
	    return NULL;	/* drop */
	}
    }
    return pb;
}

int sendUDP(PktBuf *pb) {
    Origin *origin = pb->origin;
    Stone *stone = origin->stone;
    SOCKET sd;
    int flags = 0;
    struct sockaddr *sa;
    socklen_t salen;
    char *dirstr;
    if (pb->type == type_stone) {
	sd = origin->sd;
	sa = &stone->dsts[0]->addr;
	salen = stone->dsts[0]->len;
	dirstr = ">";
#ifdef MSG_DONTWAIT
	if (!(stone->proto & proto_block_d)) flags = MSG_DONTWAIT;
#endif
    } else {
	sd = stone->sd;
	sa = &origin->from->addr;
	salen = origin->from->len;
	dirstr = "<";
#ifdef MSG_DONTWAIT
	if (!(stone->proto & proto_block_s)) flags = MSG_DONTWAIT;
#endif
    }
    if (sendto(sd, pb->buf, pb->len, flags, sa, salen) != pb->len) {
	char addrport[STRMAX+1];
	addrport2str(sa, salen, proto_udp, addrport, STRMAX, 0);
	addrport[STRMAX] = '\0';
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR, "%d UDP%s%d: sendto failed err=%d: to %s",
		stone->sd, dirstr, origin->sd, errno, addrport);
	return -1;
    }
    if (Debug > 4) {
	char addrport[STRMAX+1];
	addrport2str(sa, salen, proto_udp, addrport, STRMAX, 0);
	addrport[STRMAX] = '\0';
	message(LOG_DEBUG, "%d UDP%s%d: %d bytes sent to %s",
		stone->sd, dirstr, origin->sd, pb->len, addrport);
    }
    if ((origin->xhost->mode & XHostsMode_Dump) > 0) {
	char head[STRMAX+1];
	snprintf(head, STRMAX, "%d UDP%s%d:", stone->sd, dirstr, origin->sd);
	head[STRMAX] = '\0';
	packet_dump(head, pb->buf, pb->len, origin->xhost);
    }
    return pb->len;
}

void docloseUDP(Origin *origin) {
#ifdef USE_EPOLL
    SOCKET sd = origin->sd;
#endif
    if (Debug > 2) message(LOG_DEBUG, "%d UDP %d: close",
			   origin->stone->sd, origin->sd);
    origin->lock = -1;	/* request to close */
#ifdef USE_EPOLL
    origin->sd = INVALID_SOCKET;
    closesocket(sd);
#else
    waitMutex(FdRinMutex);
    FD_CLR(origin->sd, &rin);
    freeMutex(FdRinMutex);
#endif
}

int scanUDP(
#ifndef USE_EPOLL
    fd_set *rop, fd_set *eop,
#endif
    Origin *origins
    ) {
    Origin *origin, *prev;
    int n = 0;
    int all;
    time_t now;
    time(&now);
    if (origins) {
	all = 0;
    } else {
	origins = OriginTop;
	all = 1;
    }
    prev = origins;
    for (origin=origins->next; origin != NULL && (all || origin->from != NULL);
	 prev=origin, origin=origin->next) {
	if (all && origin->from == NULL) {
	    origins = origin;
	    continue;
	}
	if (InvalidSocket(origin->sd) || origin->lock > 0) {
	    Origin *old = origin;
	    waitMutex(OrigMutex);
	    if (prev->next == origin) {
		origin = prev;
		origin->next = old->next;	/* remove `old' from list */
		if (InvalidSocket(old->sd)) {
		    freeOrigin(old);
		} else {
		    old->lock = 0;
		    old->next = origins->next;	/* insert old on top */
		    origins->next = old;
		}
	    }
	    freeMutex(OrigMutex);
	    goto next;
	}
#ifndef USE_EPOLL
	if (origin->lock < 0) {
	    int isset;
	    waitMutex(FdRinMutex);
	    isset = FD_ISSET(origin->sd, &rin);
	    if (isset) FD_CLR(origin->sd, &rin);
	    freeMutex(FdRinMutex);
	    if (!isset) {
		closesocket(origin->sd);
		origin->sd = INVALID_SOCKET;
	    }
	    goto next;
	}
	if (FD_ISSET(origin->sd, rop) && FD_ISSET(origin->sd, &rin)) {
	    PktBuf *pb = recvUDP((Stone*)origin);
	    if (pb) {
		sendUDP(pb);
		ungetPktBuf(pb);
	    }
	    goto next;
	}
#endif
	if (++n >= OriginMax || now - origin->clock > CONN_TIMEOUT)
	    docloseUDP(origin);
      next:
	;
    }
    return 1;
}

/* relay TCP */

void message_pair(int pri, Pair *pair) {
    struct sockaddr_storage ss;
    struct sockaddr *name = (struct sockaddr*)&ss;
    socklen_t namelen = sizeof(ss);
    SOCKET sd, psd;
    Pair *p;
    int i;
    char str[LONGSTRMAX+1];
    str[LONGSTRMAX] = '\0';
    strntime(str, LONGSTRMAX, &pair->clock, -1);
    i = strlen(str);
    sd = pair->sd;
    if (ValidSocket(sd)) {
	if (getsockname(sd, name, &namelen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "%d TCP %d: Can't get socket's name err=%d",
			pair->stone->sd, sd, errno);
	} else {
	    addrport2str(name, namelen, 0, str+i, LONGSTRMAX-i, 0);
	    i = strlen(str);
	    if (i < LONGSTRMAX-2) str[i++] = ' ';
	}
	namelen = sizeof(ss);
	if (getpeername(sd, name, &namelen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG, "%d TCP %d: Can't get peer's name err=%d",
			pair->stone->sd, sd, errno);
	} else {
	    addrport2str(name, namelen, 0, str+i, LONGSTRMAX-i, 0);
	    i += strlen(str+i);
	}
    }
    if (i > LONGSTRMAX) i = LONGSTRMAX;
    str[i] = '\0';
    p = pair->pair;
    if (p) psd = p->sd;
    else psd = INVALID_SOCKET;
    if (p && p->p) {
	message(pri, "%d TCP%3d:%3d %08x %d %s %s tx:%d rx:%d lp:%d",
		pair->stone->sd, sd, psd, pair->proto, pair->count, str, p->p,
		pair->tx, pair->rx, pair->loop);
    } else {
	message(pri, "%d TCP%3d:%3d %08x %d %s tx:%d rx:%d lp:%d",
		pair->stone->sd, sd, psd, pair->proto, pair->count, str,
		pair->tx, pair->rx, pair->loop);
    }
}

void ungetExBuf(ExBuf *ex) {
    ExBuf *freeptr = NULL;
    time_t now;
    time(&now);
    waitMutex(ExBufMutex);
    if (ex->start < 0) {
	freeMutex(ExBufMutex);
	message(LOG_ERR, "ungetExBuf duplication. can't happen, ignore");
	return;
    }
    if (now - freeExBotClock > FREE_TIMEOUT) {
	if (nFreeExBot > 2) {
	    freeptr = freeExBot->next;
	    freeExBot->next = NULL;
	    nFreeExBuf -= (nFreeExBot - 1);
	} else {
	    freeExBot = freeExBuf;
	    nFreeExBot = nFreeExBuf;
	}
	freeExBotClock = now;
    }
    ex->start = -1;
    ex->len = 0;
    ex->next = freeExBuf;
    freeExBuf = ex;
    nFreeExBuf++;
    freeMutex(ExBufMutex);
    if (freeptr) {
	if (Debug > 3) message(LOG_DEBUG, "freeExBot %d nfex=%d",
			       nFreeExBot, nFreeExBuf);
	freeExBot = NULL;
	nFreeExBot = 0;
	while (freeptr) {
	    ExBuf *p = freeptr;
	    freeptr = freeptr->next;
	    free(p);
	}
    }
}

ExBuf *getExBuf(void) {
    ExBuf *ret = NULL;
    time_t now;
    time(&now);
    waitMutex(ExBufMutex);
    if (freeExBuf) {
	ret = freeExBuf;
	freeExBuf = ret->next;
	nFreeExBuf--;
	if (nFreeExBuf < nFreeExBot) {
	    nFreeExBot = nFreeExBuf;
	    freeExBot = freeExBuf;
	    freeExBotClock = now;
	}
    }
    freeMutex(ExBufMutex);
    if (!ret) {
	int size = XferBufMax;
	do {
	    ret = malloc(sizeof(ExBuf) + size - BUFMAX);
	} while (!ret && XferBufMax > BUFMAX && (XferBufMax /= 2));
	if (!ret) {
	    message(LOG_CRIT, "Out of memory, no ExBuf");
	    return ret;
	}
	ret->bufmax = size;
    }
    ret->next = NULL;
    ret->start = 0;
    ret->len = 0;
    return ret;
}

#ifdef USE_SSL
static void printSSLinfo(int pri, SSL *ssl) {
    X509 *peer;
    char *p = (char *)SSL_get_cipher(ssl);
    if (p == NULL) p = "<NULL>";
    message(pri, "[SSL cipher=%s]", p);
    peer = SSL_get_peer_certificate(ssl);
    if (peer) {
	char buf[LONGSTRMAX+1];
	ASN1_INTEGER *n = X509_get_serialNumber(peer);
	if (n) message(pri, "[SSL serial=%lx]", ASN1_INTEGER_get(n));
	buf[LONGSTRMAX] = '\0';
	if (X509_NAME_oneline(X509_get_subject_name(peer), buf, LONGSTRMAX))
	    message(pri, "[SSL subject=%s]", buf);
	if (X509_NAME_oneline(X509_get_issuer_name(peer), buf, LONGSTRMAX))
	    message(pri, "[SSL issuer=%s]", buf);
	X509_free(peer);
    }
}

int doSSL_accept(Pair *pair) {
    int err, ret;
    SOCKET sd;
    SSL *ssl;
    if (!pair) return -1;
    sd = pair->sd;
    if (InvalidSocket(sd)) return -1;
    ssl = pair->ssl;
    if (!ssl) {
	ssl = SSL_new(pair->stone->ssl_server->ctx);
	if (!ssl) {
	    message(LOG_ERR, "%d TCP %d: SSL_new failed", pair->stone->sd, sd);
	    return -1;
	}
	SSL_set_ex_data(ssl, PairIndex, pair);
	SSL_set_fd(ssl, sd);
	pair->ssl = ssl;
    }
    pair->ssl_flag &= ~(sf_ab_on_r | sf_ab_on_w);
    pair->proto |= proto_dirty;
    ret = SSL_accept(ssl);
    if (Debug > 7)
	message(LOG_DEBUG, "%d TCP %d: SSL_accept ret=%d, state=%x, "
		"finished=%x, in_init=%x/%x", pair->stone->sd,
		sd, ret, SSL_state(ssl), SSL_is_init_finished(ssl),
		SSL_in_init(ssl), SSL_in_accept_init(ssl));
    if (ret > 0) {	/* success */
	if (SSL_in_accept_init(ssl)) {
	    if (pair->stone->ssl_server->verbose) {
		message(LOG_NOTICE, "%d TCP %d: SSL_accept unexpected EOF",
			pair->stone->sd, sd);
		message_pair(LOG_NOTICE, pair);
	    }
	    return -1;	/* unexpected EOF */
	}
	/* src & pair is connected */
	pair->proto |= (proto_connect | proto_dirty);
	if (Debug > 3) {
	    SSL_CTX *ctx = pair->stone->ssl_server->ctx;
	    message(LOG_DEBUG, "%d TCP %d: SSL_accept succeeded "
		    "sess=%ld accept=%ld hits=%ld", pair->stone->sd, sd,
		    SSL_CTX_sess_number(ctx), SSL_CTX_sess_accept(ctx),
		    SSL_CTX_sess_hits(ctx));
	}
	if (pair->stone->ssl_server->verbose) printSSLinfo(LOG_DEBUG, ssl);
	return ret;
    }
    err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
	pair->ssl_flag |= sf_ab_on_r;
	ret = 0;
    } else if (err == SSL_ERROR_WANT_WRITE) {
	pair->ssl_flag |= sf_ab_on_w;
	ret = 0;
    } else if (err == SSL_ERROR_SYSCALL) {
	unsigned long e = ERR_get_error();
	if (e == 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR || errno == EAGAIN) {
		pair->ssl_flag |= (sf_ab_on_r | sf_ab_on_r);
		if (Debug > 8)
		    message(LOG_DEBUG, "%d TCP %d: SSL_accept "
			    "interrupted sf=%x",
			    pair->stone->sd, sd, pair->ssl_flag);
		return 0;
	    }
	    if (errno == 0) {
		if (Debug > 0)
		    message(LOG_DEBUG, "%d TCP %d: SSL_accept "
			    "shutdowned by peer sf=%x errno=%d",
			    pair->stone->sd, sd,
			    pair->ssl_flag, errno);
		return ret;
	    }
	    message(priority(pair), "%d TCP %d: SSL_accept "
		    "I/O error sf=%x errno=%d", pair->stone->sd, sd,
		    pair->ssl_flag, errno);
	} else {
	    message(priority(pair), "%d TCP %d: SSL_accept sf=%x %s",
		    pair->stone->sd, sd, pair->ssl_flag, ERR_error_string(e, NULL));
	}
	return ret;
    } else if (err == SSL_ERROR_SSL) {
	unsigned long e = ERR_get_error();
	message(priority(pair), "%d TCP %d: SSL_accept lib %s",
		pair->stone->sd, sd, ERR_error_string(e, NULL));
	return ret;
    }
    if (Debug > 4)
	message(LOG_DEBUG, "%d TCP %d: SSL_accept interrupted sf=%x err=%d",
		pair->stone->sd, sd, pair->ssl_flag, err);
    return ret;
}

int doSSL_connect(Pair *pair) {
    int ret;
    int err;
    SOCKET sd;
    SSL *ssl;
    if (!pair) return -1;
    sd = pair->sd;
    if (InvalidSocket(sd)) return -1;
    ssl = pair->ssl;
    if (!ssl) {
	ssl = SSL_new(pair->stone->ssl_client->ctx);
	if (!ssl) {
	    message(LOG_ERR, "%d TCP %d: SSL_new failed", pair->stone->sd, sd);
	    return -1;
	}
	SSL_set_ex_data(ssl, PairIndex, pair);
	SSL_set_fd(ssl, sd);
	pair->ssl = ssl;
    }
    pair->ssl_flag &= ~(sf_cb_on_r | sf_cb_on_w);
    pair->proto |= proto_dirty;
    ret = SSL_connect(ssl);
    if (ret > 0) {	/* success */
	Pair *p = pair->pair;
	/* pair & dst is connected */
	pair->proto |= (proto_connect | proto_dirty);
	if (p) p->proto |= proto_dirty;	/* src */
	if (Debug > 3) {
	    SSL_CTX *ctx = pair->stone->ssl_client->ctx;
	    message(LOG_DEBUG, "%d TCP %d: SSL_connect succeeded "
		    "sess=%ld connect=%ld hits=%ld", pair->stone->sd, sd,
		    SSL_CTX_sess_number(ctx), SSL_CTX_sess_connect(ctx),
		    SSL_CTX_sess_hits(ctx));
	    message_pair(LOG_DEBUG, pair);
	}
	if (pair->stone->ssl_client->verbose) printSSLinfo(LOG_DEBUG, ssl);
	return ret;
    }
    err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
	pair->ssl_flag |= sf_cb_on_r;
	ret = 0;
    } else if (err == SSL_ERROR_WANT_WRITE) {
	pair->ssl_flag |= sf_cb_on_w;
	ret = 0;
    } else if (err == SSL_ERROR_SYSCALL) {
	unsigned long e = ERR_get_error();
	if (e == 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == 0) {
		return 1;	/* success ? */
	    } else if (errno == EINTR || errno == EAGAIN) {
		pair->ssl_flag |= (sf_cb_on_r | sf_cb_on_r);
		if (Debug > 8)
		    message(LOG_DEBUG, "%d TCP %d: SSL_connect "
			    "interrupted sf=%x",
			    pair->stone->sd, sd, pair->ssl_flag);
		return 0;
	    }
	    message(priority(pair), "%d TCP %d: SSL_connect "
		    "I/O error sf=%x errno=%d", pair->stone->sd, sd,
		    pair->ssl_flag, errno);
	} else {
	    message(priority(pair), "%d TCP %d: SSL_connect sf=%x %s",
		    pair->stone->sd, sd, pair->ssl_flag, ERR_error_string(e, NULL));
	}
	return ret;
    }
    if (Debug > 4)
	message(LOG_DEBUG, "%d TCP %d: SSL_connect interrupted sf=%x err=%d",
		pair->stone->sd, sd, pair->ssl_flag, err);
    return ret;
}

int doSSL_shutdown(Pair *pair, int how) {
    int ret;
    int err;
    int i;
    SOCKET sd;
    SSL *ssl;
    StoneSSL *ss;
    if (!pair) return -1;
    sd = pair->sd;
    if (InvalidSocket(sd)) return -1;
    ssl = pair->ssl;
    if (!ssl) return -1;
    if (how >= 0) pair->ssl_flag = (how & sf_mask);
    else pair->ssl_flag = sf_mask;
    if ((pair->proto & proto_command) == command_source) {
	ss = pair->stone->ssl_server;
    } else {
	ss = pair->stone->ssl_client;
    }
    if (ss->shutdown_mode) {
	int state = SSL_get_shutdown(ssl);
	SSL_set_shutdown(ssl, (state | ss->shutdown_mode));
    }
    for (i=0; i < 4; i++) {
	ret = SSL_shutdown(ssl);
	if (ret != 0) break;
    }
    if (ret == 0 && ss->shutdown_mode == 0) {
	if (Debug > 4)
	    message(LOG_DEBUG, "%d TCP %d: SSL_shutdown ret=%d sf=%x, "
		    "so don't wait peer's notify",
		    pair->stone->sd, sd, ret, pair->ssl_flag);
	SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
	ret = SSL_shutdown(ssl);
    }
    if (ret < 0) {
	err = SSL_get_error(ssl, ret);
	if (Debug > 4)
	    message(LOG_DEBUG, "%d TCP %d: SSL_shutdown ret=%d err=%d sf=%x",
		    pair->stone->sd, sd, ret, err, pair->ssl_flag);
	if (err == SSL_ERROR_WANT_READ) {
	    pair->ssl_flag |= sf_sb_on_r;
	} else if (err == SSL_ERROR_WANT_WRITE) {
	    pair->ssl_flag |= sf_sb_on_w;
	} else if (err == SSL_ERROR_SYSCALL) {
	    unsigned long e = ERR_get_error();
	    if (e == 0) {
#ifdef WINDOWS
		errno = WSAGetLastError();
#endif
		if (errno == 0) {
		    ret = 1;	/* success ? */
		} else if (errno == EINTR || errno == EAGAIN) {
		    pair->ssl_flag |= (sf_sb_on_r | sf_sb_on_r);
		    if (Debug > 8)
			message(LOG_DEBUG, "%d TCP %d: SSL_shutdown "
				"interrupted sf=%x", pair->stone->sd, sd,
				pair->ssl_flag);
		} else {
		    message(priority(pair), "%d TCP %d: SSL_shutdown "
			    "I/O error sf=%x errno=%d", pair->stone->sd, sd,
			    pair->ssl_flag, errno);
		}
	    } else {
		message(priority(pair), "%d TCP %d: SSL_shutdown sf=%x %s",
			pair->stone->sd, sd,
			pair->ssl_flag, ERR_error_string(e, NULL));
	    }
	} else {
	    if (Debug > 4)
		message(LOG_DEBUG,
			"%d TCP %d: SSL_shutdown interrupted sf=%x err=%d",
			pair->stone->sd, sd, pair->ssl_flag, err);
	}
    } else if (ret == 0) {
	if (Debug > 4)
	    message(priority(pair), "%d TCP %d: SSL_shutdown error "
		    "ret=%d sf=%x, reset connection",
		    pair->stone->sd, sd, ret, pair->ssl_flag);
	shutdown(sd, 2);
	ret = 0;
    }
    if (ret > 0) {	/* success */
	if (Debug > 4)
	    message(LOG_DEBUG, "%d TCP %d: SSL_shutdown sf=%x",
		    pair->stone->sd, sd, pair->ssl_flag);
	if ((pair->ssl_flag & sf_mask) != sf_mask)
	    shutdown(sd, (pair->ssl_flag & sf_mask));
    }
    return ret;
}
#endif	/* USE_SSL */

int doshutdown(Pair *pair, int how) {
#ifdef USE_SSL
    SSL *ssl;
#endif
    if (!pair) return -1;
#ifdef USE_SSL
    ssl = pair->ssl;
    if (ssl) return doSSL_shutdown(pair, how);
    else {
#endif
	if (Debug > 4)
	    message(LOG_DEBUG, "%d TCP %d: shutdown how=%d",
		    pair->stone->sd, pair->sd, how);
	return shutdown(pair->sd, how);
#ifdef USE_SSL
    }
#endif
}

Pair *newPair(void) {
    Pair *pair = NULL;
    waitMutex(FPairMutex);
    if (freePairs) {
	pair = freePairs;
	freePairs = pair->next;
	nFreePairs--;
    }
    freeMutex(FPairMutex);
    if (!pair) pair = malloc(sizeof(Pair));
    if (pair) {
	pair->common = type_pair;
	pair->t = getExBuf();
	if (!pair->t) {
	    free(pair);
	    return NULL;
	}
	pair->nbuf = 1;
	pair->sd = INVALID_SOCKET;
	pair->stone = NULL;
	pair->proto = 0;
	pair->xhost = NULL;
	pair->timeout = PairTimeOut;
	pair->count = 0;
	pair->b = pair->t;
	pair->p = NULL;
	pair->log = NULL;
	pair->tx = 0;
	pair->rx = 0;
	pair->loop = 0;
	time(&pair->clock);
	pair->pair = NULL;
	pair->next = NULL;
	pair->prev = NULL;
#ifdef USE_SSL
	pair->ssl = NULL;
	pair->ssl_flag = 0;
#endif
    }
    return pair;
}

void freePair(Pair *pair) {
    SOCKET sd;
    char *p;
    TimeLog *log;
#ifdef USE_SSL
    SSL *ssl;
#endif
    ExBuf *ex;
    if (!pair) return;
    sd = pair->sd;
    pair->sd = INVALID_SOCKET;
    if (Debug > 8) message(LOG_DEBUG, "%d TCP %d: freePair",
			   pair->stone->sd, sd);
    p = pair->p;
    if (p) {
	pair->p = NULL;
	free(p);
    }
    log = pair->log;
    if (log) {
	pair->log = NULL;
	free(log);
    }
#ifdef USE_SSL
    ssl = pair->ssl;
    if (ssl) {
	SSL_CTX *ctx = NULL;
	int state;
	pair->ssl = NULL;
	state = SSL_get_shutdown(ssl);
	if (!(state & SSL_RECEIVED_SHUTDOWN) && Debug > 2) {
	    message(LOG_DEBUG, "%d TCP %d: SSL close notify was not received",
		    pair->stone->sd, sd);
	}
	if (!(state & SSL_SENT_SHUTDOWN) && Debug > 2) {
	    message(LOG_DEBUG, "%d TCP %d: SSL close notify was not sent",
		    pair->stone->sd, sd);
	    SSL_set_shutdown(ssl, (state | SSL_SENT_SHUTDOWN));
	}
	SSL_free(ssl);
	if (pair->stone->proto & proto_ssl_s) {
	    ctx = pair->stone->ssl_server->ctx;
	}
	if (ctx) SSL_CTX_flush_sessions(ctx, pair->clock);
    }
#endif
    pair->b = NULL;
    ex = pair->t;
    pair->t = NULL;
    while (ex) {
	ExBuf *f = ex;
	ex = f->next;
	f->next = NULL;
	pair->nbuf--;
	if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: freePair "
			       "unget ExBuf nbuf=%d nfex=%d",
			       pair->stone->sd, sd, pair->nbuf, nFreeExBuf);
	ungetExBuf(f);
    }
    if (ValidSocket(sd)) {
#ifdef USE_EPOLL
	if (Debug > 6)
	    message(LOG_DEBUG, "%d TCP %d: freePair "
		    "epoll_ctl %d DEL %x",
		    pair->stone->sd, sd, ePollFd, (int)pair);
	epoll_ctl(ePollFd, EPOLL_CTL_DEL, sd, NULL);
#endif
	closesocket(sd);
    }
    waitMutex(FPairMutex);
    if (pair->clock == 0) {
	freeMutex(FPairMutex);
	message(LOG_ERR, "freePair duplication. can't happen, ignore");
	return;
    }
    pair->clock = 0;
    pair->next = freePairs;
    freePairs = pair;
    nFreePairs++;
    freeMutex(FPairMutex);
}

void insertPairs(Pair *p1) {
    Pair *p2 = p1->pair;
    Stone *stone = p1->stone;
    p1->next = p2;	/* link pair each other */
    p2->prev = p1;
    waitMutex(PairMutex);
    p2->next = stone->pairs->next;	/* insert pair */
    if (stone->pairs->next != NULL) stone->pairs->next->prev = p2;
    p1->prev = stone->pairs;
    stone->pairs->next = p1;
    freeMutex(PairMutex);
    if (Debug > 4) {
	message(LOG_DEBUG, "%d TCP %d: pair %d inserted",
		stone->sd, p1->sd, p2->sd);
	message_pair(LOG_DEBUG, p1);
    }
}

void message_time_log(Pair *pair) {
    TimeLog *log = pair->log;
    if (log && log->clock) {
	struct tm *t = localtime(&log->clock);
	time_t now;
	time(&now);
	message(log->pri, "%02d:%02d:%02d %d %s",
		t->tm_hour, t->tm_min, t->tm_sec,
		(int)(now - log->clock), log->str);
	log->clock = 0;
    }
}

/* after connect(2) successfully completed */
void connected(Pair *pair) {
    Pair *p = pair->pair;
    if (Debug > 2)
	message(LOG_DEBUG, "%d TCP %d: established to %d %08x %08x",
		pair->stone->sd, p->sd, pair->sd, p->proto, pair->proto);
    time(&lastEstablished);
    /* now successfully connected */
#ifdef USE_SSL
    if (pair->stone->proto & proto_ssl_d) {
	if (doSSL_connect(pair) < 0) {
	    /* SSL_connect fails, shutdown pairs */
	    if (!(p->proto & proto_shutdown))
		if (doshutdown(p, 2) >= 0)
		    p->proto |= (proto_shutdown | proto_dirty);
	    p->proto |= (proto_close | proto_dirty);
	    pair->proto |= (proto_close | proto_dirty);
	    return;
	}
    } else
#endif	/* pair & dst is connected */
    {
	pair->proto |= (proto_connect | proto_dirty);
	p->proto |= proto_dirty;	/* src */
    }
    /*
      SSL connection may not be established yet,
      but we can prepare for read/write
    */
    if (pair->t->len > 0) {
	if (Debug > 8)
	    message(LOG_DEBUG, "%d TCP %d: waiting %d bytes to write",
		    pair->stone->sd, pair->sd, pair->t->len);
	if (!(pair->proto & proto_shutdown))
	    pair->proto |= (proto_select_w | proto_dirty);
    } else if (!(pair->proto & proto_ohttp_d)) {
	if (Debug > 8)
	    message(LOG_DEBUG, "%d TCP %d: request to read 1st",
		    pair->stone->sd, p->sd);
	if (!(p->proto & proto_eof))
	    p->proto |= (proto_select_r | proto_dirty);
    }
    if (!(p->proto & proto_ohttp_s)) {
	if (p->t->len > 0) {
	    if (Debug > 8)
		message(LOG_DEBUG, "%d TCP %d: waiting %d bytes to write",
			pair->stone->sd, p->sd, p->t->len);
	    if (!(p->proto & proto_shutdown))
		p->proto |= (proto_select_w | proto_dirty);
	} else {
	    if (Debug > 8)
		message(LOG_DEBUG, "%d TCP %d: request to read",
			pair->stone->sd, pair->sd);
	    if (!(pair->proto & proto_eof))
		pair->proto |= (proto_select_r | proto_dirty);
	}
    }
}

void message_conn(int pri, Conn *conn) {
    SOCKET sd = INVALID_SOCKET;
    Pair *p1, *p2;
    int proto = 0;
    int i = 0;
    char str[LONGSTRMAX+1];
    str[LONGSTRMAX] = '\0';
    p1 = conn->pair;
    if (p1) {
	p2 = p1->pair;
	strntime(str, LONGSTRMAX, &p1->clock, -1);
	i = strlen(str);
	proto = p1->proto;
	if (p2) sd = p2->sd;
    }
    addrport2str(&conn->dst->addr, conn->dst->len, (proto & proto_pair_d),
		 str+i, LONGSTRMAX-i, 0);
    i = strlen(str);
    if (i > LONGSTRMAX) i = LONGSTRMAX;
    str[i] = '\0';
    message(pri, "Conn %d: %08x %s", sd, proto, str);
}

int doconnect(Pair *p1, struct sockaddr *sa, socklen_t salen) {
    struct sockaddr_storage ss;
    struct sockaddr *dst = (struct sockaddr*)&ss;	/* destination */
    socklen_t dstlen = sizeof(ss);
    int ret;
    Pair *p2;
#ifdef USE_SSL
    SSL *ssl;
#endif
    int offset = -1;	/* offset in load balancing group */
    time_t clock;
    char addrport[STRMAX+1];
#ifdef WINDOWS
    u_long param;
#endif
    if (p1 == NULL) return -1;
    p2 = p1->pair;
    if (p2 == NULL) return -1;
    if (!(p2->proto & proto_connect)) return 0;
    bcopy(sa, dst, salen);
    dstlen = salen;
    time(&clock);
    if (Debug > 8) message(LOG_DEBUG, "%d TCP %d: doconnect",
			   p1->stone->sd, p1->sd);
#ifdef USE_SSL
    ssl = p2->ssl;
    if (ssl) {
	SSL_SESSION *sess = SSL_get1_session(ssl);
	if (sess) {
	    char **match;
	    if (Debug > 2) {
		unsigned char str[SSL_MAX_SSL_SESSION_ID_LENGTH * 2 + 1];
		int i;
		for (i=0; i < sess->session_id_length; i++)
		    sprintf(&str[i*2], "%02x", sess->session_id[i]);
		message(LOG_DEBUG, "%d TCP %d: SSL session ID=%s",
			p2->stone->sd, p2->sd, str);
	    }
	    match = SSL_SESSION_get_ex_data(sess, MatchIndex);
	    if (match && p2->stone->ssl_server) {
		int lbparm = p2->stone->ssl_server->lbparm;
		int lbmod = p2->stone->ssl_server->lbmod;
		unsigned char *s;
		if (0 <= lbparm && lbparm <= 9) s = match[lbparm];
		else s = match[1];
		if (!s) s = match[0];
		if (lbmod) {
		    offset = 0;
		    while (*s) {
			offset <<= 6;
			offset += (*s & 0x3f);
			s++;
		    }
		    offset %= lbmod;
		    if (Debug > 2)
			message(LOG_DEBUG, "%d TCP %d: pair %d lb%d=%d",
				p1->stone->sd, p1->sd, p2->sd, lbparm, offset);
		}
	    }
	    SSL_SESSION_free(sess);
	}
    }
#endif
    if (offset < 0 && p1->stone->ndsts > 1) {	/* load balancing */
	int n = p1->stone->ndsts;
	offset = (p1->stone->proto & state_mask) % n;
	if (p1->stone->backups) {
	    int i;
	    for (i=0; i < n; i++) {
		Backup *b = p1->stone->backups[(offset+i) % n];
		if (!b || b->bn == 0) {	/* no backup or healthy, use it */
		    offset = (offset+i) % n;
		    break;
		}
		if (Debug > 8)
		    message(LOG_DEBUG, "%d TCP %d: ofs=%d is unhealthy, skipped",
			    p1->stone->sd, p1->sd, (offset+i) % n);
	    }
	}
	/* round robin */
	p1->stone->proto = ((p1->stone->proto & ~state_mask)
			    | ((offset+1) & state_mask));
    }
    if (offset >= 0) {
	dstlen = p1->stone->dsts[offset]->len;
	bcopy(&p1->stone->dsts[offset]->addr, dst, dstlen);
    }
    if (p1->stone->backups) {
	Backup *backup;
	if (offset >= 0) backup = p1->stone->backups[offset];
	else backup = p1->stone->backups[0];
	if (backup) {
	    backup->used = 2;
	    if (backup->bn) {	/* unhealthy */
		dstlen = backup->backup->len;
		bcopy(&backup->backup->addr, dst, dstlen);
	    }
	}
    }
    /*
      now destination is determined, engage
    */
    if (!(p1->stone->proto & proto_block_d)) {
#ifdef WINDOWS
	param = 1;
	ioctlsocket(p1->sd, FIONBIO, &param);
#else
	fcntl(p1->sd, F_SETFL, O_NONBLOCK);
#endif
    }
    addrport2str(dst, dstlen, (p1->proto & proto_pair_d), addrport, STRMAX, 0);
    addrport[STRMAX] = '\0';
    if (Debug > 2)
	message(LOG_DEBUG, "%d TCP %d: connecting to TCP %d %s",
		p1->stone->sd, p2->sd, p1->sd, addrport);
    ret = connect(p1->sd, dst, dstlen);
    if (ret < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EINPROGRESS) {
	    p1->proto |= (proto_conninprog | proto_dirty);
	    if (Debug > 3)
		message(LOG_DEBUG, "%d TCP %d: connection in progress",
			p1->stone->sd, p1->sd);
	    return 1;
	} else if (errno == EINTR) {
	    if (Debug > 4)
		message(LOG_DEBUG, "%d TCP %d: connect interrupted",
			p1->stone->sd, p1->sd);
	    if (clock - p1->clock < CONN_TIMEOUT) return 0;
	    message(priority(p2), "%d TCP %d: connect timeout to %s",
		    p2->stone->sd, p2->sd, addrport);
	} else if (errno == EISCONN || errno == EADDRINUSE
#ifdef EALREADY
		   || errno == EALREADY
#endif
	    ) {
	    if (Debug > 4) {	/* SunOS's bug ? */
		message(LOG_DEBUG, "%d TCP %d: connect bug err=%d",
			p1->stone->sd, p1->sd, errno);
		message_pair(LOG_DEBUG, p1);
	    }
	} else {
	    message(priority(p1),
		    "%d TCP %d: can't connect err=%d: to %s",
		    p1->stone->sd, p1->sd, errno, addrport);
	}
    }
    if (ret < 0		/* fail to connect */
	|| (p1->proto & proto_close)
	|| (p2->proto & proto_close)) {
	if (!(p2->proto & proto_shutdown))
	    if (doshutdown(p2, 2) >= 0)
		p2->proto |= (proto_shutdown | proto_dirty);
	p2->proto |= (proto_close | proto_dirty);
	p1->proto |= (proto_close | proto_dirty);
	return -1;
    }
    connected(p1);
    return 1;
}

void freeConn(Conn *conn) {
    if (conn->dst) free(conn->dst);
    free(conn);
}

int reqconn(Pair *pair,		/* request pair to connect to destination */
	    struct sockaddr *dst, socklen_t dstlen) {	/* connect to */
    int ret;
    Conn *conn;
    Pair *p = pair->pair;
    if ((pair->proto & proto_command) == command_proxy
	|| (pair->proto & proto_command) == command_health
	|| (pair->proto & proto_command) == command_identd) {
	pair->proto |= proto_noconnect;
	if (p && !(p->proto & (proto_eof | proto_close))) {
	    /* must read request header */
	    p->proto |= (proto_select_r | proto_dirty);
	}
	return 0;
    }
    ret = doconnect(pair, dst, dstlen);
    if (ret < 0) return -1;	/* error */
    if (ret > 0) return ret;	/* connected or connection in progress */
    conn = malloc(sizeof(Conn));
    if (!conn) {
    memerr:
	message(LOG_CRIT, "%d TCP %d: out of memory",
		(p ? p->stone->sd : -1), (p ? p->sd : -1));
	return -1;
    }
    time(&pair->clock);
    p->clock = pair->clock;
    pair->count += REF_UNIT;	/* request to connect */
    conn->pair = pair;
    conn->dst = saDup(dst, dstlen);
    if (!conn->dst) {
	free(conn);
	goto memerr;
    }
    conn->lock = 0;
    waitMutex(ConnMutex);
    conn->next = conns.next;
    conns.next = conn;
    freeMutex(ConnMutex);
    return 0;
}

void asyncConn(Conn *conn) {
    Pair *p1, *p2;
    ASYNC_BEGIN;
    if (Debug > 8) message(LOG_DEBUG, "asyncConn");
    p1 = conn->pair;
    if (p1 == NULL ||
	doconnect(p1, &conn->dst->addr, conn->dst->len) != 0) {
	if (p1) p1->count -= REF_UNIT;	/* no more request to connect */
	conn->pair = NULL;
	conn->lock = -1;
    } else {
	conn->lock = 0;
    }
    if (p1) {
#ifdef USE_EPOLL
	if (!(p1->proto & (proto_noconnect | proto_close))) {
	    struct epoll_event ev;
	    ev.events = EPOLLONESHOT;
	    ev.data.ptr = p1;
	    if (Debug > 6)
		message(LOG_DEBUG, "%d TCP %d: asyncConn1 "
			"epoll_ctl %d ADD %x",
			p1->stone->sd, p1->sd, ePollFd, (int)ev.data.ptr);
	    if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, p1->sd, &ev) < 0) {
		message(LOG_ERR, "%d TCP %d: asyncConn1 "
			"epoll_ctl %d ADD err=%d",
			p1->stone->sd, p1->sd, ePollFd, errno);
	    }
	}
	/* must be added to ePollFd before unset proto_thread */
#endif
	p1->proto &= ~proto_thread;
	p1->proto |= proto_dirty;
	p2 = p1->pair;
    } else {
	p2 = NULL;
    }
    if (p2) {
#ifdef USE_EPOLL
	if (!(p2->proto & proto_close)) {
	    struct epoll_event ev;
	    ev.events = EPOLLONESHOT;
	    ev.data.ptr = p2;
	    if (Debug > 6)
		message(LOG_DEBUG, "%d TCP %d: asyncConn2 "
			"epoll_ctl %d ADD %x",
			p2->stone->sd, p2->sd, ePollFd, (int)ev.data.ptr);
	    if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, p2->sd, &ev) < 0) {
		message(LOG_ERR, "%d TCP %d: asyncConn2 "
			"epoll_ctl %d ADD err=%d",
			p2->stone->sd, p2->sd, ePollFd, errno);
	    }
	}
	/* must be added to ePollFd before unset proto_thread */
#endif
	p2->proto &= ~proto_thread;
	p2->proto |= proto_dirty;
    }
    ASYNC_END;
}

/* scan conn request */
int scanConns(void) {
    Conn *conn, *pconn;
    Pair *p1, *p2;
    if (Debug > 8) message(LOG_DEBUG, "scanConns");
    pconn = &conns;
    for (conn=conns.next; conn != NULL; conn=conn->next) {
	p1 = conn->pair;
	if (p1) p2 = p1->pair;
	if (p1 && !(p1->proto & proto_close) &&
	    p2 && !(p2->proto & proto_close)) {
	    if ((p2->proto & proto_connect) && conn->lock == 0 &&
		!(p1->proto & proto_thread) &&
		!(p2->proto & proto_thread)) {
		conn->lock = 1;		/* lock conn */
		if (Debug > 4) message_conn(LOG_DEBUG, conn);
		p1->proto |= (proto_thread | proto_dirty);
		p2->proto |= (proto_thread | proto_dirty);
		ASYNC(asyncConn, conn);
	    }
	} else {
	    waitMutex(ConnMutex);
	    if (pconn->next == conn && conn->lock <= 0) {
		pconn->next = conn->next;	/* remove conn */
		freeConn(conn);
		conn = pconn;
	    }
	    freeMutex(ConnMutex);
	}
	pconn = conn;
    }
    return 1;
}

Pair *acceptPair(Stone *stonep) {
    struct sockaddr_storage ss;
    struct sockaddr *from = (struct sockaddr*)&ss;
    socklen_t fromlen = sizeof(ss);
    Pair *pair;
    SOCKET nsd = accept(stonep->sd, from, &fromlen);
    if (InvalidSocket(nsd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EINTR) {
	    if (Debug > 4)
		message(LOG_DEBUG, "stone %d: accept interrupted", stonep->sd);
	    return NULL;
	} else if (errno == EAGAIN) {
	    if (Debug > 4)
		message(LOG_DEBUG, "stone %d: accept no connection",
			stonep->sd);
	    return NULL;
	}
#ifndef NO_FORK
	else if (errno == EBADF && Debug < 5) {
	    return NULL;
	}
#endif
	message(LOG_ERR, "stone %d: accept error err=%d", stonep->sd, errno);
	return NULL;
    }
    pair = newPair();
    if (!pair) {
	message(LOG_CRIT, "stone %d: out of memory, closing TCP %d",
		stonep->sd, nsd);
	closesocket(nsd);
	freePair(pair);
	return NULL;
    }
    bcopy(&fromlen, pair->t->buf, sizeof(fromlen));	/* save to ExBuf */
    bcopy(from, pair->t->buf + sizeof(fromlen), fromlen);
    pair->sd = nsd;
    pair->stone = stonep;
    pair->proto = ((stonep->proto & proto_pair_s & ~proto_command) |
		   proto_first_r | proto_first_w | command_source);
    pair->timeout = stonep->timeout;
    return pair;
}

int getident(char *str, struct sockaddr *sa, socklen_t salen,
	     int cport, struct sockaddr *csa, socklen_t csalen) {
    /* (size of str) >= STRMAX+1 */
    SOCKET sd;
    struct sockaddr_storage ss;
    struct sockaddr *peer = (struct sockaddr*)&ss;
    socklen_t peerlen = sizeof(ss);
    int sport = getport(sa);
    char buf[LONGSTRMAX+1];
    char c;
    int len;
    int ret;
    char addr[STRMAX+1];
#ifdef WINDOWS
    u_long param;
#endif
    time_t start, now;
#ifdef USE_EPOLL
    int epfd = INVALID_SOCKET;
    struct epoll_event ev;
    struct epoll_event evs[1];
#endif
    time(&start);
    bcopy(sa, peer, salen);
    peerlen = salen;
    if (str) {
	str[0] = '\0';
    }
    sd = socket(peer->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (InvalidSocket(sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG, "ident: can't create socket err=%d", errno);
	return 0;
    }
    saPort(csa, 0);
    if (bind(sd, csa, csalen) < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG, "ident: can't bind socket err=%d", errno);
	/* hope default source address is adequate */
    }
    saPort(peer, 113);	/* ident protocol */
    addr2str(peer, peerlen, addr, STRMAX, 0);
    addr[STRMAX] = '\0';
#ifdef WINDOWS
    param = 1;
    ioctlsocket(sd, FIONBIO, &param);
#else
    fcntl(sd, F_SETFL, O_NONBLOCK);
#endif
#ifdef USE_EPOLL
    epfd = epoll_create(BACKLOG_MAX);
    if (epfd < 0) {
	message(LOG_ERR, "ident: can't create epoll err=%d", errno);
	epfd = INVALID_SOCKET;
	goto noconnect;	/* I can't tell the master is healthy or not */
    }
    ev.events = (EPOLLOUT | EPOLLONESHOT);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev) < 0) {
	message(LOG_ERR, "ident: epoll_ctl ADD err=%d", errno);
	goto noconnect;
    }
#endif
    ret = connect(sd, peer, peerlen);
    if (ret < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EINPROGRESS) {
#ifndef USE_EPOLL
	    fd_set wout;
	    struct timeval tv;
#endif
	    do {
		time(&now);
		if (now - start >= CONN_TIMEOUT) {
		    if (Debug > 0)
			message(LOG_DEBUG, "ident: connect to %s, timeout",
				addr);
		    goto noconnect;
		}
#ifndef USE_EPOLL
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&wout);
		FdSet(sd, &wout);
#endif
	    } while (
#ifdef USE_EPOLL
		epoll_wait(epfd, evs, 1, 1000) == 0
#else
		select(FD_SETSIZE, NULL, &wout, NULL, &tv) == 0
#endif
		);
	} else {
	    if (Debug > 0)
		message(LOG_DEBUG, "ident: can't connect to %s, err=%d",
			addr, errno);
	noconnect:
#ifdef USE_EPOLL
	    if (ValidSocket(epfd)) close(epfd);
#endif
	    closesocket(sd);
	    return 0;
	}
    }
#ifdef USE_EPOLL
    ev.events = (EPOLLIN | EPOLLONESHOT);
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev) < 0) {
	message(LOG_ERR, "ident: epoll_ctl MOD err=%d", errno);
	goto noconnect;
    }
#endif
    snprintf(buf, LONGSTRMAX, "%d, %d%c%c", sport, cport, '\r', '\n');
    len = strlen(buf);
    ret = send(sd, buf, len, 0);
    if (ret != len) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (Debug > 0)
	    message(LOG_DEBUG,
		    "ident: can't send  to %s ret=%d err=%d buf=%s",
		    addr, ret, errno, buf);
    error:
	shutdown(sd, 2);
#ifdef USE_EPOLL
	if (ValidSocket(epfd)) close(epfd);
#endif
	closesocket(sd);
	return 0;
    } else {
#ifndef USE_EPOLL
	fd_set rout;
	struct timeval tv;
#endif
	do {
	    time(&now);
	    if (now - start >= CONN_TIMEOUT) {
		if (Debug > 0)
		    message(LOG_DEBUG, "ident: read from %s, timeout", addr);
		goto error;
	    }
#ifndef USE_EPOLL
	    tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    FD_ZERO(&rout);
	    FdSet(sd, &rout);
#endif
	} while (
#ifdef USE_EPOLL
	    epoll_wait(epfd, evs, 1, 1000) == 0
#else
	    select(FD_SETSIZE, &rout, NULL, NULL, &tv) == 0
#endif
	    );
	ret = recv(sd, buf, LONGSTRMAX, 0);
	if (ret <= 0) {
	    if (Debug > 0)
		message(LOG_DEBUG, "ident: can't read from %s, ret=%d",
			addr, ret);
	    goto error;
	}
	shutdown(sd, 2);
#ifdef USE_EPOLL
	if (ValidSocket(epfd)) close(epfd);
#endif
	closesocket(sd);
    }
    do {
	ret--;
	c = buf[ret];
    } while (ret > 0 && (c == '\r' || c == '\n'));
    ret++;
    buf[ret] = '\0';
    if (Debug > 2)
	message(LOG_DEBUG, "ident: sent %s:%d, %d got %s",
		addr, sport, cport, buf);
    if (str) {
	char *p;
	p = rindex(buf, ':');
	if (p) {
	    int i;
	    do {
		p++;
	    } while (*p == ' ');
	    for (i=0; i < STRMAX && *p; i++) str[i] = *p++;
	    str[i] = '\0';
	}
    }
    return 1;
}

int acceptCheck(Pair *pair1) {
    struct sockaddr_storage ss1, ss2;
    struct sockaddr *from = (struct sockaddr*)&ss1;
    socklen_t fromlen = sizeof(ss1);
    struct sockaddr *to = (struct sockaddr*)&ss2;
    socklen_t tolen = sizeof(ss2);
    Stone *stonep = pair1->stone;
    Pair *pair2 = NULL;
    int satype;
    int saproto = 0;
    int len;
#ifdef ENLARGE
    int prevXferBufMax = XferBufMax;
#endif
    XHosts *xhost;
    char ident[STRMAX+1];
    char fromstr[STRMAX*2+1];
    len = 0;
    ident[0] = '\0';
    bcopy(pair1->t->buf, &fromlen, sizeof(fromlen));	/* restore */
    if (0 < fromlen && fromlen <= sizeof(ss1)) {
	bcopy(pair1->t->buf + sizeof(fromlen), from, fromlen);
    } else {
	message(LOG_ERR, "%d TCP %d: acceptCheck Can't happen fromlen=%d",
		stonep->sd, pair1->sd, fromlen);
	if (getpeername(pair1->sd, from, &fromlen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR,
		    "%d TCP %d: acceptCheck Can't get peer's name err=%d",
		    stonep->sd, pair1->sd, errno);
	    return 0;
	}
    }
    if (stonep->proto & proto_ident) {
	if (getsockname(pair1->sd, to, &tolen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "stone %d: acceptCheck "
		    "Can't get socket's name sd=%d err=%d",
		    stonep->sd, pair1->sd, errno);
	    shutdown(pair1->sd, 2);
	    return 0;
	}
	if (getident(ident, from, fromlen, stonep->port, to, tolen)) {
	    strncpy(fromstr, ident, STRMAX);	/* (size of ident) <= STRMAX */
	    fromstr[STRMAX] = '\0';
	    len = strlen(fromstr);
	    fromstr[len++] = '@';  /* omit size check, because len <= STRMAX */
	}
    }
    addrport2str(from, fromlen, (stonep->proto & proto_stone_s),
		 fromstr+len, STRMAX*2-len, 0);
    fromstr[STRMAX*2] = '\0';
    xhost = checkXhost(stonep->xhosts, from, fromlen);
    if (!xhost) {
	message(LOG_WARNING, "stone %d: access denied: from %s",
		stonep->sd, fromstr);
	shutdown(pair1->sd, 2);
	return 0;
    }
    if (AccFp) {
	char str[STRMAX+1];
	char tstr[STRMAX+1];
	short port = 0;
	time_t clock;
	time(&clock);
	if (from->sa_family == AF_INET) {
	    port = ntohs(((struct sockaddr_in*)from)->sin_port);
	}
#ifdef AF_INET6
	else if (from->sa_family == AF_INET6) {
	    port = ntohs(((struct sockaddr_in6*)from)->sin6_port);
	}
#endif
	addr2str(from, fromlen, str, STRMAX, NI_NUMERICHOST);
	str[STRMAX] = '\0';
	strntime(tstr, STRMAX, &clock, -1);
	tstr[STRMAX] = '\0';
	fprintf(AccFp, "%s%d[%d] %s[%s]%d\n",
		tstr, stonep->port, stonep->sd, fromstr, str, port);
		
    }
    if ((xhost->mode & XHostsMode_Dump) > 0 || Debug > 1)
	message(LOG_DEBUG, "stone %d: accepted TCP %d from %s mode=%d",
		stonep->sd, pair1->sd, fromstr, xhost->mode);
    pair2 = newPair();
    if (!pair2) {
	message(LOG_CRIT, "stone %d: out of memory, closing TCP %d",
		stonep->sd, pair1->sd);
	if (pair2) freePair(pair2);
	return 0;
    }
    pair2->stone = stonep;
    pair1->xhost = pair2->xhost = xhost;
    pair2->proto = ((stonep->proto & proto_pair_d) |
		    proto_first_r | proto_first_w);
    pair2->timeout = stonep->timeout;
    /* now successfully accepted */
    if (!(stonep->proto & proto_block_d)) {
#ifdef WINDOWS
	u_long param;
	param = 1;
	ioctlsocket(pair1->sd, FIONBIO, &param);
#else
	fcntl(pair1->sd, F_SETFL, O_NONBLOCK);
#endif
    }
#ifdef USE_SSL
    if (stonep->proto & proto_ssl_s) {
	if (doSSL_accept(pair1) < 0) goto error;
    } else
#endif	/* src & pair1 is connected */
	pair1->proto |= (proto_connect | proto_dirty);
    /*
      SSL connection may not be established yet,
      but we can prepare the pair for connecting to the destination
    */
    if (stonep->proto & proto_udp_d) {
	satype = SOCK_DGRAM;
	saproto = IPPROTO_UDP;
    } else {
	satype = SOCK_STREAM;
	saproto = IPPROTO_TCP;
    }
#ifdef AF_LOCAL
    if (stonep->proto & proto_unix_d) {
	saproto = 0;
	pair2->sd = socket(AF_LOCAL, satype, saproto);
    } else
#endif
#ifdef AF_INET6
    if (stonep->proto & proto_v6_d)
	pair2->sd = socket(AF_INET6, satype, saproto);
    else
#endif
	pair2->sd = socket(AF_INET, satype, saproto);
    if (InvalidSocket(pair2->sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(priority(pair1), "%d TCP %d: can't create socket err=%d",
		stonep->sd, pair1->sd, errno);
#ifdef USE_SSL
    error:
#endif
	freePair(pair2);
	return 0;
    }
    if (stonep->from) {
	if (bind(pair2->sd, &stonep->from->addr, stonep->from->len) < 0) {
	    char str[STRMAX+1];
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    addrport2str(&stonep->from->addr, stonep->from->len, 0,
			 str, STRMAX, 0);
	    str[STRMAX] = '\0';
	    message(LOG_ERR, "stone %d: can't bind %s err=%d",
		    stonep->sd, str, errno);
	}
    }
    pair2->pair = pair1;
    pair1->pair = pair2;
    return 1;
}

int strnAddr(char *buf, int limit, SOCKET sd, int which, int isport) {
    struct sockaddr_storage ss;
    struct sockaddr *name = (struct sockaddr*)&ss;
    socklen_t namelen = sizeof(ss);
    int len;
    char str[STRMAX+1];
    int ret;
    switch (which) {
#ifdef SO_ORIGINAL_DST
    case 1:	/* original destination */
	ret = getsockopt(sd, SOL_IP, SO_ORIGINAL_DST, name, &namelen);
	break;
#endif
    default:	/* peer */
	ret = getpeername(sd, name, &namelen);
    }
    if (ret < 0) {
	if (isport) {
	    strcpy(str, "0.0.0.0:0");
	} else {
	    strcpy(str, "0.0.0.0");
	}
    } else {
	if (isport) {
	    addrport2str(name, namelen, 0, str, STRMAX, 0);
	} else {
	    addr2str(name, namelen, str, STRMAX, 0);
	}
	str[STRMAX] = '\0';
    }
    len = strlen(str);
    if (len > limit) len = limit;
    strncpy(buf, str, len);
    return len;
}

#ifdef SO_PEERCRED
#include <pwd.h>
int strnUser(char *buf, int limit, SOCKET sd, int which,
	     struct ucred *crp, int *cretp) {
    int len;
    char str[STRMAX+1];
    if (*cretp < -1) {
	len = sizeof(*crp);
	*cretp = getsockopt(sd, SOL_SOCKET, SO_PEERCRED, crp, &len);
    }
    if (*cretp < 0) {
	
    }
    switch (which) {
    case 1:	/* gid */
	snprintf(str, STRMAX, "%d", (*cretp >= 0 ? crp->gid : -1));
	break;
    case 2:	/* user name */
	*str = '\0';
	if (*cretp >= 0) {
	    struct passwd *passwd = getpwuid(crp->uid);
	    if (passwd) snprintf(str, STRMAX, "%s", passwd->pw_name);
	}
	break;
    case 3:	/* group name */
	*str = '\0';
	if (*cretp >= 0) {
	    struct group *group = getgrgid(crp->gid);
	    if (group) snprintf(str, STRMAX, "%s", group->gr_name);
	}
	break;
    default:	/* uid */
	snprintf(str, STRMAX, "%d", (*cretp >= 0 ? crp->uid : -1));
	break;
    }
    len = strlen(str);
    if (len > limit) len = limit;
    strncpy(buf, str, len);
    return len;
}
#endif

int strnparse(char *buf, int limit, char **pp, Pair *pair, char term) {
    int i = 0;
    char *p;
    char c;
#ifdef USE_SSL
    char **match = NULL;
    SSL *ssl = pair->ssl;
    SSL_SESSION *sess = NULL;
    int cond;
#endif
#ifdef SO_PEERCRED
    struct ucred cr;
    int cret = -2;
#endif
    p = *pp;
    while (i < limit && (c = *p++)) {
	if (c == '\\') {
	    c = *p++;
	    if (c == term) break;
#ifdef USE_SSL
	    cond = -1;
	    if (c == '?') {
		cond = 0;
		c = *p++;
	    }
	    if ('0' <= c && c <= '9') {
		if (ssl && !match) {
		    sess = SSL_get1_session(ssl);
		    if (sess)
			match = SSL_SESSION_get_ex_data(sess, MatchIndex);
		    if (!match) ssl = NULL;
		    /* now (match || ssl == NULL) holds */
		}
		if (match) {
		    int num = c - '0';
		    if (match[num]) {
			if (cond >= 0) {
			    if (*match[num]) cond = 1;
			} else {
			    int len = strlen(match[num]);
			    if (len >= limit - i) len = limit - i;
			    if (buf) {
				strncpy(buf+i, match[num], len);
				i += len;
			    }
			}
		    }
		}
		if (cond > 0) {
		    if (buf) {
			i += strnparse(buf+i, limit-i, &p, pair, ':');
			strnparse(NULL, limit-i, &p, pair, '/');
		    }
		} else if (cond == 0) {
		    if (buf) {
			strnparse(NULL, limit-i, &p, pair, ':');
			i += strnparse(buf+i, limit-i, &p, pair, '/');
		    }
		}
		continue;
	    }
#endif
	    switch(c) {
	    case 'n':  c = '\n';  break;
	    case 'r':  c = '\r';  break;
	    case 't':  c = '\t';  break;
	    case 'a':	/* peer address */
		if (buf) i += strnAddr(buf+i, limit-i, pair->sd, 0, 0);
		continue;
	    case 'A':	/* peer address:port */
		if (buf) i += strnAddr(buf+i, limit-i, pair->sd, 0, 1);
		continue;
#ifdef SO_ORIGINAL_DST
	    case 'd':	/* dst address */
		if (buf) i += strnAddr(buf+i, limit-i, pair->sd, 1, 0);
		continue;
	    case 'D':	/* dst address:port (transparent proxy) */
		if (buf) i += strnAddr(buf+i, limit-i, pair->sd, 1, 1);
		continue;
#endif
#ifdef SO_PEERCRED
	    case 'u':
		if (buf) i += strnUser(buf+i, limit-i, pair->sd, 0,
				       &cr, &cret);
		continue;
	    case 'g':
		if (buf) i += strnUser(buf+i, limit-i, pair->sd, 1,
				       &cr, &cret);
		continue;
	    case 'U':
		if (buf) i += strnUser(buf+i, limit-i, pair->sd, 2,
				       &cr, &cret);
		continue;
	    case 'G':
		if (buf) i += strnUser(buf+i, limit-i, pair->sd, 3,
				       &cr, &cret);
		continue;
#endif
	    case '\0':
		c = '\\';
		p--;
	    }
	}
	if (buf) buf[i++] = c;
    }
#ifdef USE_SSL
    if (sess) SSL_SESSION_free(sess);
#endif
    if (buf) buf[i] = '\0';
    *pp = p;
    return i;
}

int scanClose(Pair *pairs) {	/* scan close request */
    Pair *p1, *p2, *p;
    int n = 0;
    int m = 0;
    int all;
    if (pairs) {
	all = 0;
    } else {
	pairs = PairTop;
	all = 1;
    }
    p1 = trash.next;
    while (p1 != NULL) {
	SOCKET sd;
	p2 = p1;
	p1 = p1->next;
	if (p2->proto & proto_thread) continue;
	if (p2->count > 0) {
	    p2->count--;
	    n++;
	    continue;
	}
	sd = p2->sd;
	if (p2->proto & (proto_select_r | proto_select_w)) {
	    p2->proto &= ~(proto_select_r | proto_select_w);
	    p2->proto |= proto_dirty;
	    p2->count = REF_UNIT;
	}
#ifdef USE_SSL
	if (p2->ssl_flag) {
	    p2->ssl_flag = 0;
	    p2->count = REF_UNIT;
	}
#endif
	p = p2->prev;
	if (p) p->next = p1;	/* remove `p2' from trash */
	if (p1) p1->prev = p;
	freePair(p2);
	m++;
    }
    if (Debug > 8 && (n > 0 || m > 0))
	message(LOG_DEBUG, "trash: queued=%d, removed=%d", n, m);
    p1 = pairs->next;
    while (p1 != NULL) {
	if (p1->clock == -1) {	/* top */
	    if (all) {
		pairs = p1;
		p1 = pairs->next;
		continue;
	    } else {
		break;
	    }
	}
	p2 = p1;
	p1 = p1->next;
	if (!(p2->proto & proto_close)) continue;	/* skip */
	if (p2->count > 0) {
	    p2->count--;
	    continue;
	}
	waitMutex(PairMutex);
	p = p2->prev;
	if (p) p->next = p1;	/* remove `p2' from list */
	if (p1) p1->prev = p;
	p = p2->pair;
	if (p) p->pair = NULL;
	freeMutex(PairMutex);
	if (trash.next) trash.next->prev = p2;	/* push `p2' to trash */
	p2->prev = &trash;
	p2->count = REF_UNIT;
	p2->next = trash.next;
	trash.next = p2;
    }
    return 1;
}

void message_buf(Pair *pair, int len, char *str) {	/* dump for debug */
    char head[STRMAX+1];
    Pair *p = pair->pair;
    if (p == NULL) return;
    head[STRMAX] = '\0';
    if ((pair->proto & proto_command) == command_source) {
	snprintf(head, STRMAX, "%d %s%d<%d",
		 pair->stone->sd, str, pair->sd, p->sd);
    } else {
	snprintf(head, STRMAX, "%d %s%d>%d",
		 pair->stone->sd, str, p->sd, pair->sd);
    }
    packet_dump(head, pair->t->buf + pair->t->start, len, pair->xhost);
}

void message_pairs(int pri) {	/* dump for debug */
    Pair *pair;
    for (pair=PairTop; pair != NULL; pair=pair->next) {
	if (pair->clock != -1) {	/* not top */
	    message_pair(pri, pair);
	} else if (Debug > 2) {
	    message(LOG_DEBUG, "%d TCP %d: top", pair->stone->sd, pair->sd);
	}
    }
}

void message_origins(int pri) {	/* dump for debug */
    Origin *origin;
    for (origin=OriginTop; origin != NULL; origin=origin->next) {
	if (origin->from) {
	    message_origin(pri, origin);
	} else if (Debug > 2) {
	    message(LOG_DEBUG, "%d UDP %d: top",
		    origin->stone->sd, origin->sd);
	}
    }
}

void message_conns(int pri) {	/* dump for debug */
    Conn *conn;
    for (conn=conns.next; conn != NULL; conn=conn->next)
	message_conn(pri, conn);
}

/* read write thread */
/* no Mutex are needed because in the single thread */

void setclose(Pair *pair, int flag) {	/* set close flag */
    SOCKET sd = pair->sd;
    message_time_log(pair);
    if (!(pair->proto & proto_close)) {		/* request to close */
	pair->proto |= (flag | proto_close);
	if (Debug > 2 && ValidSocket(sd))
	    message(LOG_DEBUG, "%d TCP %d: close tx:%d rx:%d lp:%d",
		    pair->stone->sd, sd, pair->tx, pair->rx, pair->loop);
    }
#ifdef USE_EPOLL
    if (ValidSocket(sd)) {
	pair->sd = INVALID_SOCKET;
	closesocket(sd);
    }
#endif
}

int dowrite(Pair *pair) {	/* write from buf from pair->t->start */
    SOCKET sd = pair->sd;
    Pair *p;
    int len;
    ExBuf *ex;
    ex = pair->t;	/* top */
    if (!ex) return 0;
    while (ex->len <= 0 && ex->next) {
	pair->t = ex->next;
	ex->next = NULL;
	pair->nbuf--;
	if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: before dowrite "
			       "unget ExBuf nbuf=%d nfex=%d",
			       pair->stone->sd, pair->sd,
			       pair->nbuf, nFreeExBuf);
	ungetExBuf(ex);
    }
    if (ex->len <= 0) return 0;	/* nothing to write */
    if (Debug > 5) message(LOG_DEBUG, "%d TCP %d: write %d bytes",
			   pair->stone->sd, sd, ex->len);
    if (InvalidSocket(sd)) return -1;
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_write(pair->ssl, &ex->buf[ex->start], ex->len);
	if (pair->proto & proto_close) return -1;
	if (len <= 0) {
	    int err;
	    err = SSL_get_error(pair->ssl, len);
	    if (err == SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_WRITE) {
		if (Debug > 4)
		    message(LOG_DEBUG,
			    "%d TCP %d: SSL_write interrupted err=%d",
			    pair->stone->sd, sd, err);
		return 0;	/* EINTR */
	    } else if (err == SSL_ERROR_WANT_READ) {
		if (Debug > 4)
		    message(LOG_DEBUG,
			    "%d TCP %d: SSL_write blocked on read err=%d",
			    pair->stone->sd, sd, err);
		pair->ssl_flag |= sf_wb_on_r;
		return 0;	/* EINTR */
	    }
	    if (err == SSL_ERROR_SYSCALL) {
		unsigned long e = ERR_get_error();
		if (e == 0) {
#ifdef WINDOWS
		    errno = WSAGetLastError();
#endif
		    if (errno == EINTR) {
			if (Debug > 4)
			    message(LOG_DEBUG,
				    "%d TCP %d: SSL_write I/O interrupted",
				    pair->stone->sd, sd);
			return 0;
		    }
		    message(priority(pair),
			    "%d TCP %d: SSL_write I/O error err=%d, closing",
			    pair->stone->sd, sd, errno);
		    message_pair(LOG_ERR, pair);
		} else {
		    message(priority(pair),
			    "%d TCP %d: SSL_write I/O %s, closing",
			    pair->stone->sd, sd, ERR_error_string(e, NULL));
		    message_pair(LOG_ERR, pair);
		}
		return -1;	/* error */
	    } else if (err != SSL_ERROR_ZERO_RETURN) {
		message(priority(pair),
			"%d TCP %d: SSL_write err=%d %s, closing",
			pair->stone->sd, sd,
			err, ERR_error_string(ERR_get_error(), NULL));
		message_pair(LOG_ERR, pair);
		return len;	/* error */
	    }
	}
    } else {
#endif
	len = send(sd, &ex->buf[ex->start], ex->len, 0);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG, "%d TCP %d: write interrupted",
			    pair->stone->sd, sd);
		return 0;
	    }
	    if (errno == ECONNABORTED) {
		if (Debug > 3)
		    message(LOG_DEBUG, "%d TCP %d: write aborted",
			    pair->stone->sd, sd);
		return -1;
	    }
	    message(priority(pair), "%d TCP %d: write error err=%d, closing",
		    pair->stone->sd, sd, errno);
	    message_pair(LOG_ERR, pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: %d bytes written",
			   pair->stone->sd, sd, len);
    if ((pair->xhost->mode & XHostsMode_Dump) > 0
	|| ((pair->proto & proto_first_w) && Debug > 3))
	message_buf(pair, len, "");
    time(&pair->clock);
    p = pair->pair;
    if (p) p->clock = pair->clock;
    if (ex->len <= len) {
	ex->start = 0;
    } else {
	ex->start += len;
	message(LOG_NOTICE,
		"%d TCP %d: write %d bytes, but only %d bytes written",
		pair->stone->sd, sd, ex->len, len);
	message_pair(LOG_NOTICE, pair);
    }
    ex->len -= len;
    if (ex->len <= 0 && ex->next) {
	pair->t = ex->next;
	ex->next = NULL;
	pair->nbuf--;
	if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: after dowrite "
			       "unget ExBuf nbuf=%d nfex=%d",
			       pair->stone->sd, pair->sd,
			       pair->nbuf, nFreeExBuf);
	ungetExBuf(ex);
    }
    pair->tx += len;
    if ((p->proto & proto_command) != command_health)
	lastReadWrite = pair->clock;
    return len;
}

static unsigned char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int baseEncode(unsigned char *buf, int len, int max) {
    unsigned char *org = buf + max - len;
    unsigned char c1, c2, c3;
    int blen = 0;
    int i;
    bcopy(buf, org, len);
    for (i=0; i < len; i += 3) {
	switch (len - i) {
	case 1:
	    c2 = '\0';
	    buf[blen+2] = '=';
	case 2:
	    c3 = '\0';
	    buf[blen+3] = '=';
	}
	switch (len - i) {
	default:
	    c3 = org[i+2];
	    buf[blen+3] = basis_64[c3 & 0x3F];
	case 2:
	    c2 = org[i+1];
	    buf[blen+2] = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
	case 1:
	    c1 = org[i];
	    buf[blen+1] = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];
	    buf[blen] = basis_64[c1>>2];
	}
	blen += 4;
    }
    if (buf[blen-1] != '=') buf[blen++] = '=';
    return blen;
}

#define XX      255	/* illegal base64 char */
#define EQ      254	/* padding */

static unsigned char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,EQ,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,

    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};

int baseDecode(unsigned char *buf, int len, char *rest) {
    int blen = 0;
    unsigned char c[4], o[4];
    int i, j;
    j = 0;
    for (i=0; i < len; i++) {
	c[j] = index_64[buf[i]];
	if (c[j] == XX) continue;
	if (j == 0 && c[j] == EQ) continue;
	o[j++] = buf[i];
	if (j == 4) {
	    j = 0;
	    buf[blen++] = (c[0] << 2) | ((c[1] & 0x30) >> 4);
	    if (c[2] == EQ) continue;
	    buf[blen++] = ((c[1] & 0x0F) << 4) | ((c[2] & 0x3C) >> 2);
	    if (c[3] == EQ) continue;
	    buf[blen++] = ((c[2] & 0x03) << 6) | c[3];
	}
    }
    *rest = j;
    for (i=0; i < j; i++) *(rest-1-i) = o[i];
    return blen;
}

int doread(Pair *pair) {	/* read into buf from pair->pair->b->start */
    SOCKET sd = pair->sd;
    Pair *p;
    int len, i;
    ExBuf *ex;
    int bufmax, start;
    if (InvalidSocket(sd)) return -1;
    if (Debug > 5) message(LOG_DEBUG, "%d TCP %d: read", pair->stone->sd, sd);
    p = pair->pair;
    if (p == NULL) {	/* no pair, no more read */
	char _buf[BUFMAX];
#ifdef USE_SSL
	if (pair->ssl) {
	    len = SSL_read(pair->ssl, _buf, BUFMAX);
	} else
#endif
	    len = recv(sd, _buf, BUFMAX, 0);
	if (pair->proto & proto_close) return -1;
	if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: read %d bytes",
			       pair->stone->sd, sd, len);
	if (len == 0) return -1;	/* EOF w/o pair */
	if (len > 0) {
	    message(priority(pair), "%d TCP %d: no pair, closing",
		    pair->stone->sd, sd);
	    message_pair(LOG_ERR, pair);
	    len = -1;
	}
	return len;
    }
    ex = p->b;	/* bottom */
    if (ex->len > 0) {	/* not emply */
	ex = getExBuf();
	if (!ex) return -1;	/* out of memory */
	p->b->next = ex;
	p->b = ex;
	p->nbuf++;
	if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: get ExBuf nbuf=%d",
			       pair->stone->sd, p->sd, p->nbuf);
    }
    bufmax = ex->bufmax - ex->start;
    start = ex->start;
    if (p->proto & proto_base) bufmax = (bufmax - 1) / 4 * 3;
    else if (pair->proto & proto_base) {
	if (!(pair->proto & proto_first_r)) {
	    len = *(ex->buf+ex->bufmax-1);
	    for (i=0; i < len; i++) {
		ex->buf[start++] = ex->buf[ex->bufmax-2-i];
	    }
	    bufmax -= len;
	}
	*(ex->buf+ex->bufmax-1) = 0;
	bufmax -= 5;
    }
    if (((p->proto & proto_command) == command_ihead) ||
	((p->proto & proto_command) == command_iheads)) bufmax = bufmax / 2;
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_read(pair->ssl, &ex->buf[start], bufmax);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
	    int err;
	    err = SSL_get_error(pair->ssl, len);
	    if (err == SSL_ERROR_NONE
		|| err == SSL_ERROR_WANT_READ) {
		if (Debug > 4)
		    message(LOG_DEBUG,
			    "%d TCP %d: SSL_read interrupted err=%d",
			    pair->stone->sd, sd, err);
		return 0;	/* EINTR */
	    } else if (err == SSL_ERROR_WANT_WRITE) {
		if (Debug > 4)
		    message(LOG_DEBUG,
			    "%d TCP %d: SSL_read blocked on write err=%d",
			    pair->stone->sd, sd, err);
		pair->ssl_flag |= sf_rb_on_w;
		return 0;	/* EINTR */
	    }
	    if (err == SSL_ERROR_SYSCALL) {
		unsigned long e = ERR_get_error();
		if (e == 0) {
#ifdef WINDOWS
		    errno = WSAGetLastError();
#endif
		    if (errno == EINTR) {
			if (Debug > 4)
			    message(LOG_DEBUG,
				    "%d TCP %d: SSL_read I/O interrupted",
				    pair->stone->sd, sd);
			return 0;
		    }
		    message(priority(pair),
			    "%d TCP %d: SSL_read I/O error err=%d, closing",
			    pair->stone->sd, sd, errno);
		    message_pair(LOG_ERR, pair);
		} else {
		    message(priority(pair),
			    "%d TCP %d: SSL_read I/O %s, closing",
			    pair->stone->sd, sd, ERR_error_string(e, NULL));
		    message_pair(LOG_ERR, pair);
		}
		return -1;	/* error */
	    } else if (err != SSL_ERROR_ZERO_RETURN) {
		message(priority(pair),
			"%d TCP %d: SSL_read err=%d %s, closing",
			pair->stone->sd, sd,
			err, ERR_error_string(ERR_get_error(), NULL));
		message_pair(LOG_ERR, pair);
		return -1;	/* error */
	    }
	}
    } else {
#endif
	len = recv(sd, &ex->buf[start], bufmax, 0);
	if (pair->proto & proto_close) return -1;
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG, "%d TCP %d: read interrupted",
			    pair->stone->sd, sd);
		return 0;	/* EINTR */
	    }
	    if (errno == ECONNRESET) {
		if (Debug > 3)
		    message(LOG_DEBUG, "%d TCP %d: read but reset by peer",
			    pair->stone->sd, sd);
		return -1;
	    }
	    message(priority(pair), "%d TCP %d: read error err=%d, closing",
		    pair->stone->sd, sd, errno);
	    message_pair(LOG_ERR, pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (len > 0) {
	pair->rx += len;
#ifdef ENLARGE
	if (len > ex->bufmax - 10
	    && XferBufMax < ex->bufmax * 2) {
	    XferBufMax = ex->bufmax * 2;
	    message(LOG_NOTICE, "%d TCP %d: XferBufMax becomes %d byte",
		    pair->stone->sd, sd, XferBufMax);
	}
#endif
	ex->len = start + len - ex->start;
	if (Debug > 4) {
	    SOCKET psd = p->sd;
	    if (start > ex->start) {
		message(LOG_DEBUG, "%d TCP %d: read %d+%d bytes to %d",
			pair->stone->sd, sd, len, start - ex->start, psd);
	    } else {
		message(LOG_DEBUG, "%d TCP %d: read %d bytes to %d",
			pair->stone->sd, sd, ex->len, psd);
	    }
	}
	time(&pair->clock);
	p->clock = pair->clock;
	if (p->proto & proto_base) {
	    ex->len = baseEncode(&ex->buf[ex->start], ex->len,
				 ex->bufmax - ex->start);
	} else if (pair->proto & proto_base) {
	    ex->len = baseDecode(&ex->buf[ex->start], ex->len,
				 ex->buf+ex->bufmax-1);
	    len = *(ex->buf+ex->bufmax-1);
	    if (Debug > 4 && len > 0) {	/* len < 4 */
		char str[STRMAX+1];
		for (i=0; i < len; i++)
		    sprintf(&str[i*3], " %02x", ex->buf[ex->bufmax-2-i]);
		str[0] = '(';
		message(LOG_DEBUG, "%d TCP %d: save %d bytes \"%s\")",
			pair->stone->sd, sd, len, str);
	    }
	}
	if ((p->proto & proto_command) != command_health)
	    lastReadWrite = pair->clock;
    }
    if (p->t->len <= 0) {	/* top */
	message_time_log(pair);
	if (Debug > 2)
	    message(LOG_DEBUG, "%d TCP %d: EOF", pair->stone->sd, sd);
	return -2;	/* EOF w/ pair */
    }
    return p->t->len;
}

/* http */

#define METHOD_LEN_MAX	10

int commOutput(Pair *pair, char *fmt, ...) {
    Pair *p = pair->pair;
    ExBuf *ex;
    SOCKET psd;
    char *str;
    va_list ap;
    if (p == NULL) return -1;
    psd = p->sd;
    if ((p->proto & (proto_shutdown | proto_close)) || InvalidSocket(psd))
	return -1;
    ex = p->b;	/* bottom */
    if (ex->bufmax - (ex->start + ex->len) < STRMAX+1) {
	ExBuf *new = getExBuf();
	if (new) {
	    ex = new;
	    p->b->next = ex;
	    p->b = ex;
	    p->nbuf++;
	    if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: get ExBuf nbuf=%d",
				   pair->stone->sd, p->sd, p->nbuf);
	}
    }
    str = &ex->buf[ex->start + ex->len];
    ex->buf[ex->bufmax-1] = '\0';
    va_start(ap, fmt);
    vsnprintf(str, ex->bufmax-1 - (ex->start + ex->len), fmt, ap);
    va_end(ap);
    if (p->proto & proto_base)
	ex->len += baseEncode(str, strlen(str),
			       ex->bufmax-1 - (ex->start + ex->len));
    else ex->len += strlen(str);
    p->proto |= (proto_select_w | proto_dirty);	/* need to write */
    return ex->len;
}

static char *comm_match(char *buf, char *str) {
    while (*str) {
	if (toupper(*buf++) != *str++) return NULL;	/* unmatch */
    }
    if (*buf) {
	if (!isspace(*buf)) return NULL;
/*	while (isspace(*buf)) buf++;	*/
	if (*buf == ' ') buf++;
    }
    return buf;
}

#ifdef ADDRCACHE
unsigned int str2hash(char *str) {
    unsigned int hash = 0;
    while (*str) {
	hash  = hash * 7 + *str;
	str++;
    }
    return hash;
}

struct hashtable {
    char *host;
    char *serv;
    time_t clock;
    int len;
    struct sockaddr_storage ss;
} *hashtable;

int addrcache(char *name, char *serv, struct sockaddr *sa, socklen_t *salenp) {
    struct hashtable *t;
    time_t now;
    time(&now);
    if (!hashtable) {
	hashtable = malloc(AddrCacheSize * sizeof(struct hashtable));
	if (!hashtable) {
	    message(LOG_ERR, "addrcache: out of memory");
	    return host2sa(name, serv, sa, salenp, NULL, NULL, 0);
	}
	bzero(hashtable, AddrCacheSize * sizeof(struct hashtable));
    }
    t = &hashtable[(str2hash(name) ^ str2hash(serv)) % AddrCacheSize];
    waitMutex(HashMutex);
    if (t->host && strcmp(t->host, name) == 0
	&& t->serv && strcmp(t->serv, serv) == 0
	&& t->len <= *salenp
	&& now - t->clock < CACHE_TIMEOUT) {
	bcopy(&t->ss, sa, t->len);
	*salenp = t->len;
	freeMutex(HashMutex);
	if (Debug > 5) message(LOG_DEBUG, "addrcache hit: %s:%s %d",
			       name, serv, (int)(now - t->clock));
	return 1;
    }
    freeMutex(HashMutex);
    if (Debug > 9) message(LOG_DEBUG, "addrcache %s %s", name, serv);
    if (!host2sa(name, serv, sa, salenp, NULL, NULL, 0)) {
	return 0;
    }
    waitMutex(HashMutex);
    if ((t->host && strcmp(t->host, name) != 0) ||
	(t->serv && strcmp(t->serv, serv) != 0) ||
	(t->len > *salenp)) {
	free(t->host);
	free(t->serv);
	t->host = NULL;
	t->serv = NULL;
	t->len = sizeof(t->ss);
    }
    if (!t->host) t->host = strdup(name);
    if (!t->serv) t->serv = strdup(serv);
    bcopy(sa, &t->ss, *salenp);
    t->len = *salenp;
    t->clock = now;
    freeMutex(HashMutex);
    return 1;
}
#endif

int doproxy(Pair *pair, char *host, char *serv) {
    SOCKET sd = pair->sd;
    int reconnect = 0;
    PortXHosts *pxh;
    struct sockaddr_storage name_s;
    struct sockaddr *name = (struct sockaddr*)&name_s;
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t namelen = sizeof(name_s);
    socklen_t salen = sizeof(ss);
    if ((pair->stone->proto & proto_ip_only_d)) {
#ifdef AF_INET6
	if ((pair->stone->proto & proto_v6_d))
	    sa->sa_family = AF_INET6;
	else
#endif
	    sa->sa_family = AF_INET;
    } else {
	sa->sa_family = AF_UNSPEC;
    }
#ifdef ADDRCACHE
    if (AddrCacheSize > 0) {
	if (!addrcache(host, serv, sa, &salen)) return -1;
    } else
#endif
	if (!host2sa(host, serv, sa, &salen, NULL, NULL, 0)) return -1;
    if (islocalhost(sa)) {
	TimeLog *log = pair->log;
	pair->log = NULL;
	if (log) free(log);
    }
    if ((pair->stone->proto & proto_nobackup) == 0) {
	Backup *backup = findBackup(sa);
	if (backup && backup->bn) {	/* unhealthy */
	    sa = &backup->backup->addr;
	    salen = backup->backup->len;
	}
    }
    pxh = (PortXHosts*)pair->stone->dsts[1];
    if (pxh) {
	for (; pxh; pxh=pxh->next) {
	    XPorts *ports;
	    XHosts *xhost;
	    int isok = 0;
	    short port = getport(sa);
	    for (ports=pxh->ports; ports; ports=ports->next) {
		if (ports->from <= port && port <= ports->end) {
		    isok = 1;
		}
	    }
	    if (!isok) continue;
	    xhost = checkXhost(pxh->xhosts, sa, salen);
	    if (xhost) {
		if (xhost->mode) {
		    Pair *p = pair->pair;
		    pair->xhost = xhost;
		    if (p) p->xhost = xhost;
		}
		if (Debug > 7) {
		    message(LOG_DEBUG,
			    "stone %d: proxy can connect to %s:%s mode=%d",
			    pair->stone->sd, host, serv, xhost->mode);
		}
		break;
	    } else {
		message(LOG_WARNING, "stone %d: proxy may not connect to %s",
			pair->stone->sd, host);
		return -1;
	    }
	}
	if (!pxh) {
	    message(LOG_WARNING, "stone %d: proxy may not connect to port %s",
		    pair->stone->sd, serv);
	    return -1;
	}
    }
    if ((pair->proto & proto_connect) && !(pair->proto & proto_close)
	  && getpeername(sd, name, &namelen) >= 0) {	/* reconnect proxy */
	Pair *p = pair->pair;
	if (Debug > 7) {
	    char str[STRMAX+1];
	    message(LOG_DEBUG, "%d TCP %d: old proxy connection: %s",
		    pair->stone->sd, sd,
		    addrport2str(name, namelen, 0, str, STRMAX, 0));
	}
	if (p) p->proto |= (proto_first_w | proto_dirty);
	if (saComp(sa, name)) return 0;	/* same sa, so need not to connect */
	reconnect = 1;
    }
    if (reconnect
	|| ((pair->stone->proto & proto_v6_d) && sa->sa_family == AF_INET)
#ifdef AF_INET6
	|| (!(pair->stone->proto & proto_v6_d) && sa->sa_family == AF_INET6)
#endif
	) {
	SOCKET nsd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (ValidSocket(nsd)) {
	    pair->sd = nsd;
	    message(LOG_INFO, "stone %d: close %d, reopen %d as family=%d",
		    pair->stone->sd, sd, nsd, sa->sa_family);
	    closesocket(sd);
	}
    }
    pair->proto &= ~proto_command;
    if (reqconn(pair, sa, salen) < 0) return -1;
    if ((pair->proto & state_mask) == 1) {
	if (Debug > 7) message(LOG_DEBUG, "%d TCP %d: command_proxy again",
			       pair->stone->sd, pair->sd);
	pair->proto |= command_proxy;
    }
    return 0;
}

int proxyCONNECT(Pair *pair, char *parm, int start) {
    char *port = "443";	/* default: https */
    char *r = parm;
    char *q = NULL;
    Pair *p;
    message_time(pair, LOG_INFO, "CONNECT %s", parm);
    while (*r) {
	if (isspace(*r)) {
	    *r = '\0';
	    break;
	}
	if (*r == ':') q = r;
	r++;
    }
    if (q) {
	port = q + 1;
	*q = '\0';
    }
    pair->b->len += pair->b->start;
    pair->b->start = 0;
    p = pair->pair;
    if (p) p->proto |= proto_ohttp_s;	/* remove request header */
    return doproxy(pair, parm, port);
}

int proxyCommon(Pair *pair, char *parm, int start) {
    char *port = "80";	/* default port of http:// */
    char *host;
    ExBuf *ex;
    char *top;
    char *p, *q;
    int i;
    ex = pair->b;	/* bottom */
    top = &ex->buf[start];
    for (i=0; i < METHOD_LEN_MAX; i++) {
	if (parm[i] == ':') break;
    }
    if (strncmp(parm, "http", i) != 0
	|| parm[i+1] != '/' || parm[i+2] != '/') {
	message(LOG_ERR, "Unknown URL format: %s", parm);
	return -1;
    }
    host = &parm[i+3];
    p = host;
    while (*p) {
	if (*p == ':') {
	    port = p + 1;
	    *p++ = '\0';
	    continue;
	}
	if (isspace(*p) || *p == '/') {
	    *p = '\0';
	    break;
	}
	p++;
    }
    i = p - parm;		/* length of 'http://host' */
    p = top;
    while (!isspace(*p)) p++;	/* skip 'GET http://host' */
    while (isspace(*p)) p++;	/* now p points url */
    q = p + i;			/* now q points path */
    if (*q != '/') *--q = '/';
    bcopy(q, p, ex->start + ex->len - (q - top));
    ex->len = ex->start + ex->len - (q - p);
    ex->start = 0;
    if (Debug > 1) {
	Pair *r = pair->pair;
	message(LOG_DEBUG, "proxy %d -> http://%s:%s",
		(r ? r->sd : INVALID_SOCKET), host, port);
    }
#ifdef USE_EPOLL
    if (pair->proto & proto_noconnect) {
	struct epoll_event ev;
	ev.events = EPOLLONESHOT;
	ev.data.ptr = pair;
	if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, pair->sd, &ev) < 0) {
	    message(LOG_ERR, "%d TCP %d: proxyCommon "
		    "epoll_ctl %d ADD err=%d",
		    pair->stone->sd, pair->sd, ePollFd, errno);
	}
    }
#endif
    pair->proto &= ~(proto_noconnect | state_mask);
    pair->proto |= (proto_dirty | 1);
    return doproxy(pair, host, port);
}

int proxyGET(Pair *pair, char *parm, int start) {
    message_time(pair, LOG_INFO, "GET %s", parm);
    return proxyCommon(pair, parm, start);
}

int proxyHEAD(Pair *pair, char *parm, int start) {
    message_time(pair, LOG_INFO, "HEAD %s", parm);
    return proxyCommon(pair, parm, start);
}

int proxyPOST(Pair *pair, char *parm, int start) {
    message_time(pair, LOG_INFO, "POST %s", parm);
    return proxyCommon(pair, parm, start);
}

int proxyErr(Pair *pair, char *parm, int start) {
    message(LOG_ERR, "Unknown method: %s", parm);
    return -1;
}

Comm proxyComm[] = {
    { "CONNECT", proxyCONNECT },
    { "POST", proxyPOST },
    { "GET", proxyGET },
    { "HEAD", proxyHEAD },
    { NULL, proxyErr },
};

#ifdef USE_POP
int popUSER(Pair *pair, char *parm, int start) {
    int ulen, tlen;
    if (Debug) message(LOG_DEBUG, ": USER %s", parm);
    ulen = strlen(parm);
    tlen = strlen(pair->p);
    if (ulen + 1 + tlen + 1 >= BUFMAX-1) {
	commOutput(pair, "+Err Too long user name\r\n");
	return -1;
    }
    bcopy(pair->p, pair->p + ulen + 1, tlen + 1);
    strcpy(pair->p, parm);
    commOutput(pair, "+OK Password required for %s\r\n", parm);
    pair->proto &= ~state_mask;
    pair->proto |= 1;
    return -2;	/* read more */
}

#define DIGEST_LEN 16

int popPASS(Pair *pair, char *parm, int start) {
    MD5_CTX context;
    unsigned char digest[DIGEST_LEN];
    char *str;
    int ulen, tlen, plen, i;
    int state = (pair->proto & state_mask);
    ExBuf *ex = pair->b;	/* bottom */
    char *p = pair->p;
    pair->p = NULL;
    if (Debug > 5) message(LOG_DEBUG, ": PASS %s", parm);
    if (state < 1) {
	commOutput(pair, "-ERR USER first\r\n");
	return -2;	/* read more */
    }
    ulen = strlen(p);
    str = p + ulen + 1;
    tlen = strlen(str);
    plen = strlen(parm);
    if (ulen + 1 + tlen + plen + 1 >= BUFMAX-1) {
	commOutput(pair, "+Err Too long password\r\n");
	return -1;
    }
    strcat(str, parm);
    sprintf(ex->buf, "APOP %s ", p);
    ulen = strlen(ex->buf);
    MD5Init(&context);
    MD5Update(&context, str, tlen + plen);
    MD5Final(digest, &context);
    free(p);
    for (i=0; i < DIGEST_LEN; i++) {
	sprintf(ex->buf + ulen + i*2, "%02x", digest[i]);
    }
    message_time(pair, LOG_INFO, "POP -> %s", ex->buf);
    strcat(ex->buf, "\r\n");
    ex->start = 0;
    ex->len = strlen(ex->buf);
    return 0;
}

int popAUTH(Pair *pair, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": AUTH %s", parm);
    commOutput(pair, "-ERR authorization first\r\n");
    return -2;	/* read more */
}

int popCAPA(Pair *pair, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": CAPA %s", parm);
    commOutput(pair, "-ERR authorization first\r\n");
    return -2;	/* read more */
}

int popAPOP(Pair *pair, char *parm, int start) {
    ExBuf *ex = pair->b;	/* bottom */
    message_time(pair, LOG_INFO, "APOP %s", parm);
    ex->len += ex->start - start;
    ex->start = start;
    return 0;
}

int popErr(Pair *pair, char *parm, int start) {
    message(LOG_ERR, "Unknown POP command: %s", parm);
    return -1;
}

Comm popComm[] = {
    { "USER", popUSER },
    { "PASS", popPASS },
    { "APOP", popAPOP },
    { "AUTH", popAUTH },
    { "CAPA", popCAPA },
    { NULL, popErr },
};
#endif

Pair *identd(int cport, struct sockaddr *ssa, socklen_t ssalen) {
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t salen;
    Pair *pair;
    for (pair=PairTop; pair != NULL; pair=pair->next) {
	SOCKET sd;
	if ((pair->proto & proto_command) == command_source) continue;
	sd = pair->sd;
	salen = sizeof(ss);
	if (InvalidSocket(sd) || getsockname(sd, sa, &salen) < 0) {
	    continue;
	}
	if (getport(sa) != cport) continue;
	salen = sizeof(ss);
	if (getpeername(sd, sa, &salen) < 0) {
	    continue;
	}
	if (!saComp(sa, ssa)) continue;
	return pair;
    }
    return NULL;
}

int identdQUERY(Pair *pair, char *parm, int start) {
    int cport = 0;
    int sport = 0;
    char mesg[STRMAX+1];
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    socklen_t salen = sizeof(ss);
    Pair *p = pair->pair;
    strcpy(mesg, "ERROR : NO-USER");
    if (p) {
	SOCKET sd = p->sd;
	if (sscanf(parm, "%d,%d", &cport, &sport) == 2
	    && ValidSocket(sd) && getpeername(sd, sa, &salen) >= 0) {
	    if (Debug > 8) {
		char addrport[STRMAX+1];
		addrport2str(sa, salen, 0, addrport, STRMAX, 0);
		message(LOG_DEBUG, "%d TCP %d: identd query %d,%d from %s",
			pair->stone->sd, sd, cport, sport, addrport);
	    }
	    saPort(sa, sport);
	    p = identd(cport, sa, salen);
	    if (p) {
		int port = -1;
		Stone *stone = p->stone;
		if (stone) port = stone->port;
		snprintf(mesg, STRMAX, "USERID : STONE : %d", port);
	    }
	    if (Debug > 2) {
		char addrport[STRMAX+1];
		addrport2str(sa, salen, 0, addrport, STRMAX, 0);
		message(LOG_DEBUG, "identd %d %s %s", cport, addrport, mesg);
	    }
	} else {
	    return -1;
	}
    }
    commOutput(pair, "%d , %d : %s\r\n", cport, sport, mesg);
    return -2;	/* read more */
}

int identdQUIT(Pair *pair, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, "identd QUIT %s", parm);
    return -1;
}

Comm identdComm[] = {
    { "QUIT", identdQUIT },
    { "", identdQUERY },
    { NULL, identdQUERY },
};

int nStones(void) {
    int n = 0;
    Stone *stone;
    for (stone=stones; stone != NULL; stone=stone->next) n++;
    return n;
}

int nPairs(Pair *top) {
    int n = 0;
    Pair *pair;
    for (pair=top; pair != NULL; pair=pair->next)
	if (pair->clock != -1) n++;	/* not top */
    return n;
}

int nConns(void) {
    int n = 0;
    Conn *conn;
    for (conn=conns.next; conn != NULL; conn=conn->next) n++;
    return n;
}

int nOrigins(void) {
    int n = 0;
    Origin *origin;
    for (origin=OriginTop; origin != NULL; origin=origin->next)
	if (origin->from) n++;
    return n;
}

int limitCommon(Pair *pair, int var, int limit, char *str) {
    if (Debug) message(LOG_DEBUG, ": LIMIT %s %d: %d", str, limit, var);
    if (var < limit) {
	commOutput(pair, "200 %s=%d is less than %d\r\n",
		   str, var, limit);
    } else {
	commOutput(pair, "500 %s=%d is not less than %d\r\n", str, var, limit);
    }
    return -2;	/* read more */
}

int limitPair(Pair *pair, char *parm, int start) {
    return limitCommon(pair, nPairs(PairTop), atoi(parm), "pair");
}

int limitConn(Pair *pair, char *parm, int start) {
    return limitCommon(pair, nConns(), atoi(parm), "conn");
}

int limitEstablished(Pair *pair, char *parm, int start) {
    time_t now;
    time(&now);
    return limitCommon(pair, (int)(now - lastEstablished),
		       atoi(parm), "established");
}

int limitReadWrite(Pair *pair, char *parm, int start) {
    time_t now;
    time(&now);
    return limitCommon(pair, (int)(now - lastReadWrite),
		       atoi(parm), "readwrite");
}

int limitAsync(Pair *pair, char *parm, int start) {
    return limitCommon(pair, AsyncCount, atoi(parm), "async");
}

int limitErr(Pair *pair, char *parm, int start) {
    if (Debug) message(LOG_ERR, ": Illegal LIMIT %s", parm);
    commOutput(pair, "500 Illegal LIMIT\r\n");
    return -2;	/* read more */
}

Comm limitComm[] = {
    { "PAIR", limitPair },
    { "CONN", limitConn },
    { "ESTABLISHED", limitEstablished },
    { "READWRITE", limitReadWrite },
    { "ASYNC", limitAsync },
    { NULL, limitErr },
};

int healthHELO(Pair *pair, char *parm, int start) {
    char str[LONGSTRMAX+1];
    snprintf(str, LONGSTRMAX,
	     "stone=%d pair=%d trash=%d conn=%d origin=%d",
	     nStones(), nPairs(PairTop), nPairs(trash.next),
	     nConns(), nOrigins());
    str[LONGSTRMAX] = '\0';
    if (Debug) message(LOG_DEBUG, ": HELO %s: %s", parm, str);
    commOutput(pair, "250 stone:%s debug=%d %s\r\n",
	       VERSION, Debug, str);
    return -2;	/* read more */
}

int healthSTAT(Pair *pair, char *parm, int start) {
    char str[LONGSTRMAX+1];
    int mc = MutexConflict;
    MutexConflict = 0;
    snprintf(str, LONGSTRMAX,
	     "async=%d mutex=%d",
	     AsyncCount, mc);
    str[LONGSTRMAX] = '\0';
    if (Debug) message(LOG_DEBUG, ": STAT %s: %s", parm, str);
    commOutput(pair, "250 stone:%s debug=%d %s\r\n",
	       VERSION, Debug, str);
    return -2;	/* read more */
}

int healthFREE(Pair *pair, char *parm, int start) {
    char str[LONGSTRMAX+1];
    snprintf(str, LONGSTRMAX,
	     "fpair=%d nfexbuf=%d nfexbot=%d nfpktbuf=%d",
	     nFreePairs, nFreeExBuf, nFreeExBot, nFreePktBuf);
    str[LONGSTRMAX] = '\0';
    if (Debug) message(LOG_DEBUG, ": FREE %s: %s", parm, str);
    commOutput(pair, "250 stone:%s debug=%d %s\r\n",
	       VERSION, Debug, str);
    return -2;	/* read more */
}

int healthCLOCK(Pair *pair, char *parm, int start) {
    char str[LONGSTRMAX+1];
    time_t now;
    time(&now);
    snprintf(str, LONGSTRMAX,
	     "now=%ld established=%d readwrite=%d", (long)now,
	     (int)(now - lastEstablished), (int)(now - lastReadWrite));
    str[LONGSTRMAX] = '\0';
    if (Debug) message(LOG_DEBUG, ": CLOCK %s: %s", parm, str);
    commOutput(pair, "250 stone:%s debug=%d %s\r\n",
	       VERSION, Debug, str);
    return -2;	/* read more */
}

int healthCVS_ID(Pair *pair, char *parm, int start) {
    commOutput(pair, "200 stone %s %s\r\n", VERSION, CVS_ID);
    return -2;	/* read more */
}

int healthCONFIG(Pair *pair, char *parm, int start) {
    int i;
    for (i=1; i < ConfigArgc; i++)
	commOutput(pair, "200%c%s\n", (i < ConfigArgc-1 ? '-' : ' '),
		   ConfigArgv[i]);
    return -2;	/* read more */
}

int healthSTONE(Pair *pair, char *parm, int start) {
    Stone *stone;
    char str[STRMAX+1];
    for (stone=stones; stone != NULL; stone=stone->next)
	commOutput(pair, "200%c%s\n", (stone->next ? '-' : ' '),
		   stone2str(stone, str, STRMAX));
    return -2;	/* read more */
}

int healthLIMIT(Pair *pair, char *parm, int start) {
    Comm *comm = limitComm;
    char *q;
    while (comm->str) {
	if ((q=comm_match(parm, comm->str)) != NULL) break;
	comm++;
    }
    if (!q) return limitErr(pair, parm, start);
    return (*comm->func)(pair, q, start);
}

int healthQUIT(Pair *pair, char *parm, int start) {
    if (Debug) message(LOG_DEBUG, ": QUIT %s", parm);
    return -1;
}

int healthErr(Pair *pair, char *parm, int start) {
    if (*parm) message(LOG_ERR, "Unknown health command: %s", parm);
    return -1;
}

Comm healthComm[] = {
    { "HELO", healthHELO },
    { "STAT", healthSTAT },
    { "FREE", healthFREE },
    { "CLOCK", healthCLOCK },
    { "CVS_ID", healthCVS_ID },
    { "CONFIG", healthCONFIG },
    { "STONE", healthSTONE },
    { "LIMIT", healthLIMIT },
    { "QUIT", healthQUIT },
    { NULL, healthErr },
};

int memCheck(void) {
    char *buf = malloc(BUFMAX * 10);
    if (buf) {
	free(buf);
	return 1;
    }
    message(LOG_CRIT, "memCheck: out of memory");
    return 0;
}

int docomm(Pair *pair, Comm *comm) {
    ExBuf *ex = pair->b;	/* bottom */
    char buf[BUFMAX];
    char *p;
    char *q = &ex->buf[ex->start + ex->len];
    int start, i;
    for (p=&ex->buf[ex->start]; p < q; p++) {
	if (*p == '\r' || *p == '\n') break;
    }
    if (p >= q && p < &ex->buf[ex->bufmax]) {
	ex->start += ex->len;
	ex->len = 0;
	return -2;	/* read more */
    }
    for (start=p-ex->buf-1; start >= 0; start--) {
	if (ex->buf[start] == '\r' || ex->buf[start] == '\n') break;
    }
    start++;
    while ((*p == '\r' || *p == '\n') && p < q) p++;
    ex->start = p - ex->buf;
    if (p < q) {
	ex->len = q - p;
    } else {
	ex->len = 0;
    }
    while (comm->str) {
	if ((q=comm_match(&ex->buf[start], comm->str)) != NULL) break;
	comm++;
    }
    if (q == NULL) q = &ex->buf[start];
    for (i=0; q < p && i < BUFMAX-1; i++) {
	if (*q == '\r' || *q == '\n') break;
	buf[i] = *q++;
    }
    buf[i] = '\0';
    return (*comm->func)(pair, buf, start);
}

int insheader(Pair *pair) {	/* insert header */
    ExBuf *ex = pair->b;	/* bottom */
    char *p;
    int bufmax = ex->bufmax;
    int len, i;
    len = ex->start + ex->len;
    for (i=ex->start; i < len; i++) {
	if (ex->buf[i] == '\n') break;
    }
    if (i >= len) {
	if (Debug > 3)
	    message(LOG_DEBUG, "%d TCP %d: insheader needs more",
		    pair->stone->sd, pair->sd);
	return -1;
    }
    i++;
    len -= i;
    if (len > 0) {
	bufmax -= len;		/* reserve */
	/* save rest header */
	bcopy(&ex->buf[i], &ex->buf[bufmax], len);
    }
    p = pair->stone->p;
    i += strnparse(&ex->buf[i], bufmax - i, &p, pair->pair, 0xFF);
    ex->buf[i++] = '\r';
    ex->buf[i++] = '\n';
    if (Debug > 5) {
	message(LOG_DEBUG,
		"%d TCP %d: insheader start=%d, ins=%d, rest=%d, max=%d",
		pair->stone->sd, pair->sd, ex->start, i-ex->start, len, ex->bufmax);
    }
    if (len > 0)	/* restore */
	bcopy(&ex->buf[bufmax], &ex->buf[i], len);
    ex->len = i - ex->start + len;
    return ex->len;
}

int rmheader(Pair *pair) {	/* remove header */
    ExBuf *ex = pair->b;	/* bottom */
    char *p;
    char *q = &ex->buf[ex->start+ex->len];
    int state = (pair->proto & state_mask);
    if (Debug > 3) message_buf(pair, ex->len, "rm");
    for (p=&ex->buf[ex->start]; p < q; p++) {
	if (*p == '\r') continue;
	if (*p == '\n') {
	    state++;
	    if (state >= 3) {
		p++;
		break;	/* end of header */
	    }
	} else {
	    state = 1;
	}
    }
    if (state < 3) {
	ex->len = ex->start = 0;
	pair->proto = ((pair->proto & ~state_mask) | state);
	return -2;	/* header will continue... */
    }
    ex->len = q - p;	/* remove header */
    ex->start = p - ex->buf;
    pair->proto &= ~state_mask;
    return ex->len;
}

int first_read(Pair *pair) {
    SOCKET sd = pair->sd;
    SOCKET psd;
    Pair *p = pair->pair;
    ExBuf *ex;
    Stone *stone = pair->stone;
    int len;
    if (p == NULL || (p->proto & (proto_shutdown | proto_close))
	|| InvalidSocket(sd)) return -1;
    ex = p->b;	/* bottom */
    psd = p->sd;
    len = ex->len;
    pair->proto &= ~proto_first_r;
    if (p->proto & proto_command) {	/* proxy */
	switch(p->proto & proto_command) {
	case command_proxy:
	    len = docomm(p, proxyComm);
	    break;
#ifdef USE_POP
	case command_pop:
	    if (p->p) len = docomm(p, popComm);
	    break;
#endif
	case command_health:
	    if (!memCheck()) len = -1;
	    else len = docomm(p, healthComm);
	    break;
	case command_identd:
	    len = docomm(p, identdComm);
	    break;
	default:
	    ;
	}
	if (len == -2) {	/* read more */
	    if (Debug > 3) {
		message(LOG_DEBUG, "%d TCP %d: read more from %d",
			stone->sd, psd, sd);
	    }
	} else if (len < 0) {
	    int flag = 0;
	    if (!(pair->proto & proto_shutdown))
		if (doshutdown(pair, 2) >= 0) flag = proto_shutdown;
	    setclose(pair, flag);
	    if (ValidSocket(psd)) {
		flag = 0;
		if (!(p->proto & proto_shutdown))
		    if (doshutdown(p, 2) >= 0) flag = proto_shutdown;
		setclose(p, flag);
	    }
	    return -1;
	} else {
	    len = ex->len;
	}
    }
    if (pair->proto & proto_ohttp) {	/* over http */
	len = rmheader(p);
	if (len >= 0) {
	    if (pair->proto & proto_ohttp_s) {
		commOutput(p, "HTTP/1.0 200 OK\r\n\r\n");
		pair->proto &= ~proto_ohttp_s;
	    } else if (pair->proto & proto_ohttp_d) {
		if (Debug > 3)
		    message(LOG_DEBUG, "%d TCP %d: request to read, "
			    "because response header from %d finished",
			    stone->sd, psd, sd);
		p->proto |= (proto_select_r | proto_dirty);
	    }
	}
    }
#ifdef USE_POP
    if ((pair->proto & proto_command) == command_pop	/* apop */
	&& pair->p == NULL) {
	int i;
	char *q;
	for (i=ex->start; i < ex->start + ex->len; i++) {
	    if (ex->buf[i] == '<') {	/* time stamp of APOP banner */
		q = pair->p = malloc(BUFMAX);
		if (!q) {
		    message(LOG_CRIT, "%d TCP %d: out of memory",
			    stone->sd, sd);
		    break;
		}
		for (; i < ex->start + ex->len; i++) {
		    *q++ = ex->buf[i];
		    if (ex->buf[i] == '>') break;
		}
		*q = '\0';
		break;
	    }
	}
    }
#endif
    if (len <= 0 && !(pair->proto & (proto_eof | proto_close))) {
	if (Debug > 8) {
	    message(LOG_DEBUG, "%d TCP %d: read more", stone->sd, sd);
	}
	pair->proto |= (proto_select_r | proto_dirty);	/* read more */
	if (len < 0) pair->proto |= (proto_first_r | proto_dirty);
    }
    return len;
}

#ifndef USE_EPOLL
static void message_select(int pri, char *msg,
			   fd_set *rout, fd_set *wout, fd_set *eout) {
    int i, r, w, e;
    for (i=0; i < FD_SETSIZE; i++) {
	r = FD_ISSET(i, rout);
	w = FD_ISSET(i, wout);
	e = FD_ISSET(i, eout);
	if (r || w || e)
	    message(pri, "%s %d: %c%c%c", msg,
		    i, (r ? 'r' : ' '), (w ? 'w' : ' '), (e ? 'e' : ' '));
    }
}
#endif

/* main event loop */

void proto2fdset(Pair *pair, int isthread,
#ifdef USE_EPOLL
		 int epfd
#else
		 fd_set *routp, fd_set *woutp, fd_set *eoutp
#endif
    ) {
    SOCKET sd;
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLONESHOT;
    ev.data.ptr = pair;
#endif
    if (!pair) return;
    sd = pair->sd;
    if (InvalidSocket(sd)) return;
    if (!isthread && (pair->proto & proto_thread)) return;
#ifdef USE_SSL
    if (pair->ssl_flag & (sf_sb_on_r | sf_sb_on_w)) {
#ifdef USE_EPOLL
	if (pair->ssl_flag & sf_sb_on_r) ev.events |= EPOLLIN;
	if (pair->ssl_flag & sf_sb_on_w) ev.events |= EPOLLOUT;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FD_CLR(sd, routp);
	FD_CLR(sd, woutp);
	if (pair->ssl_flag & sf_sb_on_r) FdSet(sd, routp);
	if (pair->ssl_flag & sf_sb_on_w) FdSet(sd, woutp);
#endif
    } else
#endif
    if (pair->proto & proto_close) {
	return;
    } else if (pair->proto & proto_conninprog) {
#ifdef USE_EPOLL
	ev.events |= (EPOLLOUT | EPOLLPRI);
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FdSet(sd, woutp);
	FdSet(sd, eoutp);
#endif
#ifdef USE_SSL
    } else if (pair->ssl_flag & sf_wb_on_r) {
#ifdef USE_EPOLL
	ev.events |= EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FD_CLR(sd, woutp);
	FdSet(sd, routp);
#endif
    } else if (pair->ssl_flag & sf_rb_on_w) {
#ifdef USE_EPOLL
	ev.events |= EPOLLOUT;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FD_CLR(sd, routp);
	FdSet(sd, woutp);
#endif
    } else if (pair->ssl_flag & (sf_cb_on_r | sf_cb_on_w)) {
	Pair *p = pair->pair;
	if (p) {
	    /*
	      suppress hasty read/write until established connection.
	      assumes p is located before pair in pairs list
	    */
	    SOCKET psd = p->sd;
	    if (ValidSocket(psd)) {
#ifdef USE_EPOLL
		struct epoll_event pev;
		pev.events = EPOLLONESHOT;
		pev.data.ptr = p;
		epoll_ctl(epfd, EPOLL_CTL_MOD, psd, &pev);
		if (Debug > 7)
		    message(LOG_DEBUG, "%d TCP %d: proto2fdset2 "
			    "epoll_ctl %d MOD %x events=%x",
			    p->stone->sd, psd, epfd,
			    (int)pev.data.ptr, pev.events);
#else
		FD_CLR(psd, routp);
		FD_CLR(psd, woutp);
#endif
	    }
	}
#ifdef USE_EPOLL
	if (pair->ssl_flag & (sf_cb_on_r)) ev.events |= EPOLLIN;
	if (pair->ssl_flag & (sf_cb_on_w)) ev.events |= EPOLLOUT;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FD_CLR(sd, routp);
	FD_CLR(sd, woutp);
	if (pair->ssl_flag & (sf_cb_on_r)) FdSet(sd, routp);
	if (pair->ssl_flag & (sf_cb_on_w)) FdSet(sd, woutp);
#endif
    } else if (pair->ssl_flag & (sf_ab_on_r | sf_ab_on_w)) {
#ifdef USE_EPOLL
	if (pair->ssl_flag & (sf_ab_on_r)) ev.events |= EPOLLIN;
	if (pair->ssl_flag & (sf_ab_on_w)) ev.events |= EPOLLOUT;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	FD_CLR(sd, routp);
	FD_CLR(sd, woutp);
	if (pair->ssl_flag & (sf_ab_on_r)) FdSet(sd, routp);
	if (pair->ssl_flag & (sf_ab_on_w)) FdSet(sd, woutp);
#endif
#endif
    } else if (pair->proto & proto_connect) {
	int isset = 0;
	if (!(pair->proto & proto_eof)
	    && (pair->proto & proto_select_r)) {
#ifdef USE_EPOLL
	    ev.events |= EPOLLIN;
#else
	    FdSet(sd, routp);
#endif
	    isset = 1;
	}
	if (!(pair->proto & proto_shutdown)
	    && (pair->proto & proto_select_w)) {
#ifdef USE_EPOLL
	    ev.events |= EPOLLOUT;
#else
	    FdSet(sd, woutp);
#endif
	    isset = 1;
	}
	if (isset)
#ifdef USE_EPOLL
	    ev.events |= EPOLLPRI;
	epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	    FdSet(sd, eoutp);
#endif
    }
#ifdef USE_EPOLL
    if (Debug > 7)
	message(LOG_DEBUG, "%d TCP %d: proto2fdset "
		"epoll_ctl %d MOD %x events=%x",
		pair->stone->sd, sd, epfd, (int)ev.data.ptr, ev.events);
#endif
    pair->proto &= ~proto_dirty;
}

enum {
    RW_LEAVE = 0,
    RW_CONTINUE,
    RW_EINTR,
    RW_ONCE,
};

int doReadWritePair(Pair *pair, Pair *opposite,
		    int ready_r, int ready_w, int ready_e,
		    int hangup, int error) {
    Pair *rPair, *wPair;
    SOCKET stsd, sd, rsd, wsd;
    int len;
    int ret = RW_CONTINUE;	/* assume to continue */
    sd = pair->sd;
    if (InvalidSocket(sd)) return ret;
    stsd = pair->stone->sd;
    pair->loop++;
    if (hangup && (pair->proto & proto_connect)) ready_r = 1;
    if ((pair->proto & proto_conninprog)
	&& (ready_w || ready_e || hangup)) {
	int optval;
	socklen_t optlen = sizeof(optval);
	pair->proto &= ~proto_conninprog;
	pair->proto |= proto_dirty;
	if (getsockopt(sd, SOL_SOCKET, SO_ERROR,
		       (char*)&optval, &optlen) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "%d TCP %d: getsockopt err=%d", stsd, sd, errno);
	    pair->proto |= (proto_close | proto_dirty);
	    opposite->proto |= (proto_close | proto_dirty);
	    return RW_LEAVE;	/* leave */
	}
	if (optval) {
	    message(LOG_ERR, "%d TCP %d: connect getsockopt err=%d",
		    stsd, sd, optval);
	    pair->proto |= (proto_close | proto_dirty);
	    opposite->proto |= (proto_close | proto_dirty);
	    return RW_LEAVE;	/* leave */
	} else {	/* succeed in connecting */
	    if (Debug > 4)
		message(LOG_DEBUG, "%d TCP %d: connecting completed",
			stsd, sd);
	    connected(pair);
	}
    } else if (ready_e) {	/* Out-of-Band Data */
	char buf[1];
	len = recv(sd, buf, 1, MSG_OOB);
	if (len == 1) {
	    if (opposite) wsd = opposite->sd; else wsd = INVALID_SOCKET;
	    if (Debug > 3)
		message(LOG_DEBUG, "%d TCP %d: MSG_OOB 0x%02x to %d",
			stsd, sd, buf[0], wsd);
	    if (ValidSocket(wsd)) {
		len = send(wsd, buf, 1, MSG_OOB);
		if (len != 1) {
#ifdef WINDOWS
		    errno = WSAGetLastError();
#endif
		    message(LOG_ERR,
			    "%d TCP %d: send MSG_OOB ret=%d, err=%d",
			    stsd, sd, len, errno);
		}
	    }
	} else {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "%d TCP %d: recv MSG_OOB ret=%d, err=%d",
		    stsd, sd, len, errno);
	}
#ifdef USE_SSL
    } else if (((pair->ssl_flag & sf_sb_on_r) && ready_r)
	       || ((pair->ssl_flag & sf_sb_on_w) && ready_w)
	) {
	pair->ssl_flag &= ~(sf_sb_on_r | sf_sb_on_w);
	pair->proto |= proto_dirty;
	doSSL_shutdown(pair, -1);
    } else if (((pair->ssl_flag & sf_cb_on_r) && ready_r)
	       || ((pair->ssl_flag & sf_cb_on_w) && ready_w)) {
	pair->ssl_flag &= ~(sf_cb_on_r | sf_cb_on_w);
	pair->proto |= proto_dirty;
	if (doSSL_connect(pair) < 0) {
	    /* SSL_connect fails, shutdown pairs */
	    if (opposite && !(opposite->proto & proto_shutdown))
		if (doshutdown(opposite, 2) >= 0)
		    opposite->proto |= (proto_shutdown | proto_dirty);
	    opposite->proto |= (proto_close | proto_dirty);
	    pair->proto |= (proto_close | proto_dirty);
	}
    } else if (((pair->ssl_flag & sf_ab_on_r) && ready_r)
	       || ((pair->ssl_flag & sf_ab_on_w) && ready_w)) {
	pair->ssl_flag &= ~(sf_ab_on_r | sf_ab_on_w);
	pair->proto |= proto_dirty;
	if (doSSL_accept(pair) < 0) {
	    /* SSL_accept fails */
	    pair->proto |= (proto_close | proto_dirty);
	    opposite->proto |= (proto_close | proto_dirty);
	}
	if (pair->proto & proto_connect)
	    reqconn(opposite, &pair->stone->dsts[0]->addr,
		    pair->stone->dsts[0]->len);
#endif
    } else if (((pair->proto & proto_select_r) && ready_r	/* read */
#ifdef USE_SSL
		&& !(pair->ssl_flag & sf_wb_on_r))
	       || ((pair->ssl_flag & sf_rb_on_w)
		   && ready_w	/* WANT_WRITE */
#endif
		   )) {
#ifdef USE_SSL
	pair->ssl_flag &= ~sf_rb_on_w;
	pair->proto |= proto_dirty;
#endif
	rPair = pair;
	wPair = opposite;
	rsd = sd;
	if (wPair) wsd = wPair->sd; else wsd = INVALID_SOCKET;
#ifdef USE_SSL
    read_pending:
#endif
	rPair->proto &= ~proto_select_r;
	rPair->proto |= proto_dirty;
	rPair->count += REF_UNIT;
	len = doread(rPair);
	rPair->count -= REF_UNIT;
	if (len < 0 || (rPair->proto & proto_close) || wPair == NULL) {
	    if (len == -2	/* if EOF w/ pair, */
		&& !(rPair->proto & proto_shutdown)
		/* and not yet shutdowned, */
		&& wPair
		&& !(wPair->proto & (proto_eof | proto_shutdown
				     | proto_close))
		/* and not bi-directional EOF
		   and peer is not yet shutdowned, */
		&& (wPair->proto & proto_connect)
		&& ValidSocket(wsd)) {	/* and pair is valid, */
		/*
		  recevied EOF from rPair,
		  so reply SSL notify to rPair
		  and send SSL notify and FIN to wPair...
		*/
		/* no more to read */
		rPair->proto |= (proto_eof | proto_dirty);
		/*
		  Don't send notify, or further SSL_write will fail
		  if (rPair->ssl) doSSL_shutdown(rPair, 0);
		*/
		if (!(wPair->proto & proto_shutdown))
		    if (doshutdown(wPair, 1) >= 0)	/* send FIN */
			wPair->proto |= (proto_shutdown | proto_dirty);
		wPair->proto &= ~proto_select_w;
		wPair->proto |= proto_dirty;
	    } else {
		/*
		  error, already shutdowned, or bi-directional EOF,
		  so reply SSL notify to rPair,
		  send SSL notify to wPair and shutdown wPair,
		  set close flag
		*/
		int flag = 0;
		if (!(rPair->proto & proto_shutdown))
		    if (doshutdown(rPair, 2) >= 0)
			flag = proto_shutdown;
		rPair->proto &= ~proto_select_w;
		rPair->proto |= proto_dirty;
		setclose(rPair, (proto_eof | flag));
		flag = 0;
		if (!(wPair->proto & proto_shutdown))
		    if (doshutdown(wPair, 2) >= 0)
			flag = proto_shutdown;
		wPair->proto &= ~proto_select_w;
		wPair->proto |= proto_dirty;
		setclose(wPair, flag);
	    }
	} else {
	    if (len > 0) {
		int first_flag;
		first_flag = (rPair->proto & proto_first_r);
		if (first_flag) len = first_read(rPair);
		if (len > 0 && ValidSocket(wsd)
		    && (wPair->proto & proto_connect)
		    && !(wPair->proto & (proto_shutdown | proto_close))
		    && !(rPair->proto & proto_close)) {
		    /* (wPair->proto & proto_eof) may be true */
		    wPair->proto |= (proto_select_w | proto_dirty);
#ifdef ALWAYS_BUFFERING
		    rPair->proto |= (proto_select_r | proto_dirty);
#endif
		} else {
		    return RW_LEAVE;	/* leave */
		}
	    } else {	/* EINTR */
		rPair->proto |= (proto_select_r | proto_dirty);
		ret = RW_EINTR;
	    }
	}
    } else if (((pair->proto & proto_select_w) && ready_w) /* write */
#ifdef USE_SSL
	       || ((pair->ssl_flag & sf_wb_on_r)
		   && ready_r)	/* WANT_READ */
#endif
	) {
#ifdef USE_SSL
	pair->ssl_flag &= ~sf_wb_on_r;
	pair->proto |= proto_dirty;
#endif
	wPair = pair;
	rPair = opposite;
	wsd = sd;
	if (rPair) rsd = rPair->sd; else rsd = INVALID_SOCKET;
	wPair->proto &= ~proto_select_w;
	wPair->proto |= proto_dirty;
	if (((wPair->proto & proto_command) == command_ihead) ||
	    ((wPair->proto & proto_command) == command_iheads)) {
	    int state = (wPair->proto & state_mask);
	    if (state == 0) {
		if (insheader(wPair) >= 0)	/* insert header */
		    wPair->proto |= ++state;
	    }
	}
	wPair->count += REF_UNIT;
	len = dowrite(wPair);
	wPair->count -= REF_UNIT;
	if (len < 0 || (wPair->proto & proto_close) || rPair == NULL) {
	    int flag = 0;
	    if (rPair && ValidSocket(rsd)
		&& !(rPair->proto & proto_shutdown))
		if (doshutdown(rPair, 2) >= 0) flag = proto_shutdown;
	    rPair->proto &= ~proto_select_w;
	    rPair->proto |= proto_dirty;
	    setclose(rPair, flag);
	    flag = 0;
	    if (!(wPair->proto & proto_shutdown))
		if (doshutdown(wPair, 2) >= 0) flag = proto_shutdown;
	    setclose(wPair, flag);
	} else {
	    ExBuf *ex;
	    ex = wPair->t;	/* top */
	    /* (wPair->proto & proto_eof) may be true */
	    if (ex->len <= 0) {	/* all written */
		if (wPair->proto & proto_first_w) {
		    wPair->proto &= ~proto_first_w;
		    wPair->proto |= proto_dirty;
		    if (rPair && ValidSocket(rsd)
			&& ((rPair->proto & proto_command)
			    == command_proxy)
			&& ((rPair->proto & state_mask) == 1)) {
			message_time_log(rPair);
			if (Debug > 7)
			    message(LOG_DEBUG,
				    "%d TCP %d: reconnect proxy",
				    stsd, wPair->sd);
			wPair->proto |= (proto_first_r | proto_dirty);
		    }
		}
		if (rPair && ValidSocket(rsd)
		    && ((rPair->proto & proto_command)
			== command_iheads)) {
		    if (Debug > 7)
			message(LOG_DEBUG,
				"%d TCP %d: insheader again",
				stsd, wPair->sd);
		    rPair->proto &= ~state_mask;
		}
		if (rPair && ValidSocket(rsd)
		    && (rPair->proto & proto_connect)
		    && !(rPair->proto & (proto_eof | proto_close))
		    && !(wPair->proto & (proto_shutdown | proto_close))
		    ) {
#ifdef USE_SSL
		    if (rPair->ssl && SSL_pending(rPair->ssl)) {
			if (Debug > 4)
			    message(LOG_DEBUG,
				    "%d TCP %d: SSL_pending, read again",
				    stsd, rPair->sd);
			ret = RW_ONCE;	/* read once */
			goto read_pending;
		    }
#endif
		    rPair->proto |= (proto_select_r | proto_dirty);
		} else {
		    return RW_LEAVE;	/* leave */
		}
	    } else {	/* EINTR */
		wPair->proto |= (proto_select_w | proto_dirty);
		ret = RW_EINTR;
	    }
	}
    } else if (error) {
	if (Debug > 3) message(LOG_DEBUG, "%d TCP %d: error", stsd, sd);
	pair->proto |= (proto_close | proto_dirty);
	opposite->proto |= (proto_close | proto_dirty);
	return RW_LEAVE;	/* leave */
    }
    return ret;
}

#ifndef USE_EPOLL
void doReadWrite(Pair *pair) {	/* pair must be source side */
    int npairs = 1;
    Pair *p[2];
    SOCKET stsd;
    int loop;
    int rx[2];
    int tx[2];
    int i;
    fd_set ri, wi, ei;
    fd_set ro, wo, eo;
    struct timeval tv;
    p[0] = pair;
    p[1] = pair->pair;
    stsd = pair->stone->sd;
    if (Debug > 8) message(LOG_DEBUG, "%d TCP %d, %d: doReadWrite", stsd,
			   (p[0] ? p[0]->sd : INVALID_SOCKET),
			   (p[1] ? p[1]->sd : INVALID_SOCKET));
    if (p[1]) npairs++;
    FD_ZERO(&ri);
    FD_ZERO(&wi);
    FD_ZERO(&ei);
    rx[0] = p[0]->rx;
    tx[0] = p[0]->tx;
    if (p[1]) {
	rx[1] = p[1]->rx;
	tx[1] = p[1]->tx;
    } else {
	rx[1] = -1;
	tx[1] = -1;
    }
    loop = 0;
    for (;;) {	/* loop until timeout or EOF/error */
	tv.tv_sec = 0;
	tv.tv_usec = TICK_SELECT;
	ro = ri;
	wo = wi;
	eo = ei;
	for (i=0; i < npairs; i++) proto2fdset(p[i], 1, &ro, &wo, &eo);
	if (Debug > 10)
	    message_select(LOG_DEBUG, "selectReadWrite1", &ro, &wo, &eo);
	if (select(FD_SETSIZE, &ro, &wo, &eo, &tv) <= 0) goto leave;
	if (Debug > 10)
	    message_select(LOG_DEBUG, "selectReadWrite2", &ro, &wo, &eo);
	for (i=0; i < npairs; i++) {
	    SOCKET sd;
	    int ret;
	    if (!p[i]) continue;
	    sd = p[i]->sd;
	    if (InvalidSocket(sd)) continue;
	    ret = doReadWritePair(p[i], p[1-i], FD_ISSET(sd, &ro),
				  FD_ISSET(sd, &wo), FD_ISSET(sd, &eo), 0, 0);
	    if (ret == RW_LEAVE) goto leave;
	    if (ret == RW_ONCE) break;		/* read once */
	    if (ret == RW_EINTR) loop = 0;	/* EINTR */
	}
	if (++loop > 10) {	/* check if spin occured */
	    if (rx[0] == p[0]->rx && tx[0] == p[0]->tx	/* no update => spin */
		&& (!p[1] || (rx[1] == p[1]->rx && tx[1] == p[1]->tx))) {
		message(LOG_ERR, "%d TCP %d, %d: doReadWrite Can't happen "
			"spin occured tx/rx: %d/%d, %d/%d", stsd,
			(p[0] ? p[0]->sd : INVALID_SOCKET),
			(p[1] ? p[1]->sd : INVALID_SOCKET),
			tx[0], rx[0], tx[1], rx[1]);
		goto leave;
	    }
	    rx[0] = p[0]->rx;
	    tx[0] = p[0]->tx;
	    if (p[1]) {
		rx[1] = p[1]->rx;
		tx[1] = p[1]->tx;
	    }
	    loop = 0;
	}
    }
 leave:
    for (i=0; i < npairs; i++) {
	p[i]->proto &= ~proto_thread;
	p[i]->proto |= proto_dirty;
	p[i]->count -= REF_UNIT;
    }
    if (Debug > 8) message(LOG_DEBUG, "%d TCP %d, %d: doReadWrite end", stsd,
			   (p[0] ? p[0]->sd : INVALID_SOCKET),
			   (p[1] ? p[1]->sd : INVALID_SOCKET));
}

void asyncReadWrite(Pair *pair) {	/* pair must be source side */
    ASYNC_BEGIN;
    doReadWrite(pair);
    ASYNC_END;
}

int doPair(Pair *pair) {
    SOCKET psd;
    Pair *p = pair->pair;
    if (!p || (pair->proto & proto_thread)) return 0;
    psd = p->sd;
    if (InvalidSocket(psd)) return 0;
    pair->count += REF_UNIT;
    p->count += REF_UNIT;
    pair->proto |= (proto_thread | proto_dirty);
    p->proto |= (proto_thread | proto_dirty);
    if ((pair->proto & proto_command) == command_source) {
	ASYNC(asyncReadWrite, pair);
    } else {
	ASYNC(asyncReadWrite, p);
    }
    return 1;
}
#endif

void doAcceptConnect(Pair *p1) {
    Stone *stone = p1->stone;
    Pair *p2;
    int ret;
    if (Debug > 8) message(LOG_DEBUG, "%d TCP %d: doAcceptConnect",
			   stone->sd, p1->sd);
    if (!acceptCheck(p1)) {
	freePair(p1);
	return;
    }
    p2 = p1->pair;
    if (p2->proto & proto_ohttp_d) {
	int i;
	char *p = stone->p;
	ExBuf *ex = p2->b;	/* bottom */
	i = strnparse(ex->buf, ex->bufmax - 5, &p, p1, 0xFF);
	ex->buf[i++] = '\r';
	ex->buf[i++] = '\n';
	ex->buf[i++] = '\r';
	ex->buf[i++] = '\n';
	ex->len = i;
    }
    ret = -1;
    if (p1->proto & proto_connect) {
	ret = reqconn(p2, &stone->dsts[0]->addr,	/* 0 is default */
		      stone->dsts[0]->len);
	if (ret < 0) {
	    freePair(p2);
	    freePair(p1);
	    return;
	}
    }
#ifdef USE_EPOLL
    if (!(p1->proto & proto_close)) {
	struct epoll_event ev;
	ev.events = EPOLLONESHOT;
	ev.data.ptr = p1;
	if (Debug > 6)
	    message(LOG_DEBUG, "%d TCP %d: doAcceptConnect1 "
		    "epoll_ctl %d ADD %x",
		    stone->sd, p1->sd, ePollFd, (int)ev.data.ptr);
	if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, p1->sd, &ev) < 0) {
	    message(LOG_ERR, "%d TCP %d: doAcceptConnect1 "
		    "epoll_ctl %d ADD err=%d",
		    stone->sd, p1->sd, ePollFd, errno);
	}
	if (!(p2->proto & (proto_noconnect | proto_close))) {
	    ev.data.ptr = p2;
	    if (Debug > 6)
		message(LOG_DEBUG, "%d TCP %d: doAcceptConnect2 "
			"epoll_ctl %d ADD %x",
			stone->sd, p2->sd, ePollFd, (int)ev.data.ptr);
	    if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, p2->sd, &ev) < 0) {
		message(LOG_ERR, "%d TCP %d: doAcceptConnect2 "
			"epoll_ctl %d ADD err=%d",
			stone->sd, p2->sd, ePollFd, errno);
	    }
	}
    }
    /* must be added to ePollFd before unset proto_thread */
#else
    if (ret > 0) {
	p1->proto |= (proto_thread | proto_dirty);
	p2->proto |= (proto_thread | proto_dirty);
	doReadWrite(p1);
    }
#endif
    if (!(p1->proto & proto_close)) {
	p1->proto |= proto_dirty;
	p2->proto |= proto_dirty;
	insertPairs(p1);
    } else {
	freePair(p2);
	freePair(p1);
    }
}

void asyncAcceptConnect(Pair *pair) {
    ASYNC_BEGIN;
    doAcceptConnect(pair);
    ASYNC_END;
}

void asyncClose(Pair *pair) {
    SOCKET sd = pair->sd;
#ifdef USE_SSL
    int count = 0;
#ifdef USE_EPOLL
    int epfd = -1;
#else
    fd_set ro, wo;
    struct timeval tv;
#endif
#endif
    ASYNC_BEGIN;
    if (InvalidSocket(sd) || (pair->proto & proto_shutdown)) goto exit;
    if (Debug > 8) message(LOG_DEBUG, "asyncClose");
#ifdef USE_SSL
    if (pair->ssl) {
	int want;
#ifdef USE_EPOLL
	int epfd = epoll_create(BACKLOG_MAX);
	struct epoll_event ev;
	struct epoll_event evs[1];
	if (epfd < 0) {
	    message(LOG_ERR, "asyncClose: can't create epoll err=%d", errno);
	    goto exit;
	}
	ev.events = EPOLLONESHOT;
	ev.data.ptr = pair;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev) < 0) {
	    message(LOG_ERR, "asyncClose: epoll_ctl %d ADD err=%d",
		    epfd, errno);
	    close(epfd);
	    goto exit;
	}
#endif
	do {
	    want = 0;
	    doSSL_shutdown(pair, 2);
#ifdef USE_EPOLL
	    ev.events = EPOLLONESHOT;
	    if (pair->ssl_flag & sf_sb_on_r) {
		ev.events |= EPOLLIN;
		want = 1;
	    }
	    if (pair->ssl_flag & sf_sb_on_w) {
		ev.events |= EPOLLOUT;
		want = 1;
	    }
	    epoll_ctl(epfd, EPOLL_CTL_MOD, sd, &ev);
#else
	    FD_ZERO(&ro);
	    FD_ZERO(&wo);
	    if (pair->ssl_flag & sf_sb_on_r) {
		FdSet(sd, &ro);
		want = 1;
	    }
	    if (pair->ssl_flag & sf_sb_on_w) {
		FdSet(sd, &wo);
		want = 1;
	    }
	    tv.tv_sec = 0;
	    tv.tv_usec = TICK_SELECT;
#endif
	} while (want &&
#ifdef USE_EPOLL
		 epoll_wait(epfd, evs, 1, TICK_SELECT / 1000) >= 0
#else
		 select(FD_SETSIZE, &ro, &wo, NULL, &tv) >= 0
#endif
		 && (count++ < (3000000 / TICK_SELECT)));  /* timeout 3 sec */
    }
#endif
    shutdown(sd, 2);
 exit:
#ifdef USE_SSL
#ifdef USE_EPOLL
    if (epfd >= 0) close(epfd);
#endif
#endif
    setclose(pair, proto_shutdown);
    pair->proto &= ~proto_thread;
    pair->proto |= proto_dirty;
    ASYNC_END;
}

#ifdef USE_EPOLL
void dispatch(int epfd, struct epoll_event *evs, int nevs) {
    int i;
    for (i=0; i < nevs; i++) {
	int common;
	int other;
	struct epoll_event ev = evs[i];
	union {
	    Stone stone;
	    Pair pair;
	    Origin origin;
	} *p;
	if (Debug > 8) message(LOG_DEBUG, "epoll %d: evs[%d].data=%x",
			       epfd, i, (int)ev.data.ptr);
	common = *(int*)ev.data.ptr;
	other = (ev.events & ~(EPOLLIN | EPOLLPRI | EPOLLOUT));
	p = ev.data.ptr;
	switch(common & type_mask) {
	case type_stone:
	    if (Debug > 10 || (other && Debug > 2))
		message(LOG_DEBUG, "stone %d: epoll %d events=%x type=%d",
			p->stone.sd, epfd, ev.events, common);
	    if (p->stone.proto & proto_udp_s) {
		PktBuf *pb = recvUDP(&p->stone);
		if (pb) {
		    sendUDP(pb);
		    ungetPktBuf(pb);
		}
	    } else {
		Pair *pair = acceptPair(&p->stone);
		if (pair) {
		    if (p->stone.proto & proto_ident) {
			ASYNC(asyncAcceptConnect, pair);
		    } else {
			doAcceptConnect(pair);
		    }
		}
	    }
	    break;
	case type_pair:
	    if (Debug > 10 || (other && Debug > 2))
		message(LOG_DEBUG, "TCP %d: epoll %d events=%x type=%d",
			p->pair.sd, epfd, ev.events, common);
	    doReadWritePair(&p->pair, p->pair.pair,
			    (ev.events & EPOLLIN)  != 0,
			    (ev.events & EPOLLOUT) != 0,
			    (ev.events & EPOLLPRI) != 0,
			    (ev.events & EPOLLHUP) != 0,
			    (ev.events & EPOLLERR) != 0);
	    break;
	case type_origin:
	    {
		Origin *origin = &p->origin;
		PktBuf *pb;
		if (Debug > 10 || (other && Debug > 2))
		    message(LOG_DEBUG, "%d UDP %d: epoll %d events=%x type=%d",
			    origin->stone->sd, origin->sd,
			    epfd, ev.events, common);
		pb = recvUDP((Stone*)origin);
		if (pb) {
		    sendUDP(pb);
		    ungetPktBuf(pb);
		}
	    }
	    break;
	default:
	    message(LOG_ERR, "Irregular event events=%x type=%d",
		    ev.events, common);
	}
    }
}
#endif

int scanPairs(
#ifndef USE_EPOLL
    fd_set *rop, fd_set *wop, fd_set *eop,
#endif
    Pair *pairs
    ) {
    Pair *pair;
    int ret = 1;
    int all;
    if (Debug > 8) message(LOG_DEBUG, "scanPairs");
    if (pairs) {
	all = 0;
    } else {
	pairs = PairTop;
	all = 1;
    }
    for (pair=pairs->next;
	 pair != NULL && (all || pair->clock != -1);	/* until top */
	 pair=pair->next) {
	SOCKET sd = pair->sd;
	if (all && pair->clock == -1) {	/* skip top */
	    pairs = pair;
	    continue;
	}
	if (!(pair->proto & proto_thread) && ValidSocket(sd)) {
	    time_t clock;
	    int idle = 1;	/* assume no events happen on sd */
#ifndef USE_EPOLL
	    if (FD_ISSET(sd, rop) || FD_ISSET(sd, wop) || FD_ISSET(sd, eop)) {
		if (doPair(pair)) idle = 0;
	    }
#endif
	    if (idle && pair->timeout > 0
		&& (time(&clock), clock - pair->clock > pair->timeout)) {
		if (Debug > 2) {
		    message(LOG_DEBUG, "%d TCP %d: idle time exceeds",
			    pair->stone->sd, sd);
		    message_pair(LOG_DEBUG, pair);
		}
		if (pair->count > 0) pair->count -= REF_UNIT;
		pair->proto |= (proto_thread | proto_dirty);
#ifdef USE_EPOLL
		/* must be set proto_thread before delete from ePollFd */
		if (Debug > 6)
		    message(LOG_DEBUG, "%d TCP %d: scanPairs "
			    "epoll_ctl %d DEL %x",
			    pair->stone->sd, sd, ePollFd, (int)pair);
		epoll_ctl(ePollFd, EPOLL_CTL_DEL, pair->sd, NULL);
#endif
		ASYNC(asyncClose, pair);
	    }
	}
    }
    if (Debug > 8) message(LOG_DEBUG, "scanPairs done");
    return ret;
}

#ifndef USE_EPOLL
int scanStones(fd_set *rop, fd_set *wop, fd_set *eop) {
    Stone *stone;
    for (stone=stones; stone != NULL; stone=stone->next) {
	int isset;
	waitMutex(FdEinMutex);
	isset = (FD_ISSET(stone->sd, eop) && FD_ISSET(stone->sd, &ein));
	if (isset) FD_CLR(stone->sd, &ein);
	freeMutex(FdEinMutex);
	if (isset) {
	    message(LOG_ERR, "stone %d: exception", stone->sd);
	} else {
	    if (FD_ISSET(stone->sd, rop) && FD_ISSET(stone->sd, &rin)) {
		if (stone->proto & proto_udp_s) {
		    PktBuf *pb = recvUDP(stone);
		    if (pb) {
			sendUDP(pb);
			ungetPktBuf(pb);
		    }
		} else {
		    Pair *pair = acceptPair(stone);
		    if (pair) ASYNC(asyncAcceptConnect, pair);
		}
	    }
	}
	if (stone->proto & proto_udp_s) {
	    scanUDP(rop, eop, (Origin *)stone->p);
	}
	if (!(stone->proto & proto_udp_s) || !(stone->proto & proto_udp_d)) {
	    scanPairs(rop, wop, eop, stone->pairs);
	}
    }
    return 1;
}
#endif

/* stone */

#ifdef USE_SSL
static int newMatch(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			      int idx, long argl, void *argp) {
    char **match = malloc(sizeof(char*) * (NMATCH_MAX+1));
    if (match) {
	int i;
	for (i=0; i <= NMATCH_MAX; i++) match[i] = NULL;
	if (Debug > 4) message(LOG_DEBUG, "newMatch %d: %x",
			       NewMatchCount++, (int)match);
	return CRYPTO_set_ex_data(ad, idx, match);
    }
    return 0;
}

static void freeMatch(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
		      int idx, long argl, void *argp) {
    char **match = ptr;
    int i;
    for (i=0; i <= NMATCH_MAX; i++) {
	if (match[i]) free(match[i]);
    }
    if (Debug > 4) message(LOG_DEBUG, "freeMatch %d: %x",
			   --NewMatchCount, (int)match);
    free(match);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    X509 *err_cert;
    int err, depth, depthmax;
    regex_t *re;
    long serial = -1;
    SSL *ssl;
    Pair *pair;
    StoneSSL *ss;
    char buf[BUFMAX];
    char *p;
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    ssl = X509_STORE_CTX_get_ex_data
		(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl) {
	message(LOG_ERR, "SSL callback can't get SSL object");
	return 0;	/* always fail */
    }
    pair = SSL_get_ex_data(ssl, PairIndex);
    if (!pair) {
	message(LOG_ERR, "SSL callback don't have ex_data, verify fails");
	return 0;	/* always fail */
    }
    if ((pair->proto & proto_command) == command_source) {
	ss = pair->stone->ssl_server;
    } else {
	ss = pair->stone->ssl_client;
    }
    depthmax = ((pair->ssl_flag & sf_depth) >> sf_depth_bit);
    if (depth >= depthmax) {
	depthmax = depth + 1;
	pair->ssl_flag = ((pair->ssl_flag & ~sf_depth)
			  | (depthmax << sf_depth_bit));
    }
    if (depth == 0) {
	ASN1_INTEGER *n = X509_get_serialNumber(err_cert);
	if (n) serial = ASN1_INTEGER_get(n);
	if (ss->serial == -1 && serial >= 0) {
	    ss->serial = serial;
	} else if (ss->serial >= 0 && serial != ss->serial) {
	    message(LOG_ERR, "%d TCP %d: SSL callback serial number mismatch "
		    "%lx != %lx", pair->stone->sd, pair->sd,
		    serial, ss->serial);
	    return 0;	/* fail */
	}
    }
    if (Debug > 3)
	message(LOG_DEBUG,
		"%d TCP %d: callback: err=%d, depth=%d/%d, preverify=%d",
		pair->stone->sd, pair->sd, err, depth, depth - depthmax,
		preverify_ok);
    p = X509_NAME_oneline(X509_get_subject_name(err_cert), buf, BUFMAX-1);
    if (!p) return 0;
    if (ss->verbose) message(LOG_DEBUG, "%d TCP %d: [depth%d=%s]",
			     pair->stone->sd, pair->sd, depth, p);
    if (depth > ss->depth) {
	preverify_ok = 0;
	X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
    }
    if (!preverify_ok) {
	if (ss->verbose)
	    message(LOG_DEBUG, "%d TCP %d: verify error err=%d %s",
		    pair->stone->sd, pair->sd,
		    err, X509_verify_cert_error_string(err));
	return 0;
    }
    re = ss->re[DEPTH_MAX - depthmax + depth];
    if (!re) re = ss->re[depth];
    if (depth < DEPTH_MAX && re) {
	SSL_SESSION *sess = NULL;
	regmatch_t pmatch[NMATCH_MAX];
	char **match;
	err = regexec(re, p, (size_t)NMATCH_MAX, pmatch, 0);
	if (Debug > 3) message(LOG_DEBUG, "%d TCP %d: regexec%d=%d",
			       pair->stone->sd, pair->sd, depth, err);
	if (err) return 0;	/* not match */
	sess = SSL_get1_session(ssl);
	if (sess && (match = SSL_SESSION_get_ex_data(sess, MatchIndex))) {
	    int i;
	    int j = 1;
	    if (serial >= 0) {
		char str[STRMAX+1];
		int len;
		snprintf(str, STRMAX, "%lx", serial);
		len = strlen(str);
		if (match[0]) free(match[0]);
		match[0] = malloc(len+1);
		if (match[0]) {
		    strncpy(match[0], str, len);
		    match[0][len] = '\0';
		}
	    }
	    for (i=1; i <= NMATCH_MAX; i++) {
		if (match[i]) continue;
		if (pmatch[j].rm_so >= 0) {
		    int len = pmatch[j].rm_eo - pmatch[j].rm_so;
		    match[i] = malloc(len+1);
		    if (match[i]) {
			strncpy(match[i], p + pmatch[j].rm_so, len);
			match[i][len] = '\0';
			if (Debug > 4) message(LOG_DEBUG, "%d TCP %d: \\%d=%s",
					       pair->stone->sd, pair->sd,
					       i, match[i]);
		    }
		    j++;
		}
	    }
	} else {
	    message(LOG_ERR,
		    "%d TCP %d: SSL callback can't get session's ex_data",
		    pair->stone->sd, pair->sd);
	}
	if (sess) SSL_SESSION_free(sess);
    } else {
	if (Debug > 3) message(LOG_DEBUG, "%d TCP %d: re%d=NULL",
			       pair->stone->sd, pair->sd, depth);
    }
    return 1;	/* if re is null, always succeed */
}

static int passwd_callback(char *buf, int size, int rwflag, void *passwd) {
    strncpy(buf, (char *)(passwd), size);
    buf[size-1] = '\0';
    return(strlen(buf));
}

StoneSSL *mkStoneSSL(SSLOpts *opts, int isserver) {
    StoneSSL *ss;
    int err;
    int i;
    ss = malloc(sizeof(StoneSSL));
    if (!ss) {
    memerr:
	message(LOG_CRIT, "Out of memory");
	exit(1);
    }
    ss->verbose = opts->verbose;
    ss->shutdown_mode = opts->shutdown_mode;
    ss->ctx = SSL_CTX_new(opts->meth);
    if (!ss->ctx) {
	message(LOG_ERR, "SSL_CTX_new error");
	goto error;
    }
    SSL_CTX_set_options(ss->ctx, opts->off);
    SSL_CTX_set_mode(ss->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_verify(ss->ctx, opts->mode, opts->callback);
    SSL_CTX_set_verify_depth(ss->ctx, opts->depth + 1);
    ss->depth = opts->depth;
    ss->serial = opts->serial;
    ss->lbmod = opts->lbmod;
    ss->lbparm = opts->lbparm;
    if (opts->caFile || opts->caPath) {
	if (!SSL_CTX_load_verify_locations(ss->ctx,
					   opts->caFile, opts->caPath)) {
	    message(LOG_ERR, "SSL_CTX_load_verify_locations(%s,%s) error",
		    opts->caFile, opts->caPath);
	    goto error;
	}
	if (opts->vflags)
	    X509_STORE_set_flags(SSL_CTX_get_cert_store(ss->ctx),
				 opts->vflags);
    }
    if (isserver) {
	if (opts->sid_ctx) {
	    int ret;
	    int len = strlen(opts->sid_ctx);
	    ret = SSL_CTX_set_session_id_context(ss->ctx, opts->sid_ctx, len);
	    if (!ret) {
		len = SSL_MAX_SSL_SESSION_ID_LENGTH;
		opts->sid_ctx[len] = '\0';
		message(LOG_ERR, "Too long sid_ctx, truncated to '%s'",
			opts->sid_ctx);
	    }
	}
	SSL_CTX_set_session_cache_mode(ss->ctx,
				       (SSL_SESS_CACHE_SERVER
					   | SSL_SESS_CACHE_NO_AUTO_CLEAR));
    }
    if (opts->pfxFile) {
	FILE *fp = fopen(opts->pfxFile, "r");
	PKCS12 *p12;
	EVP_PKEY *key;
	X509 *cert;
	if (!fp) {
	    message(LOG_ERR, "Can't open pfx file: %s", opts->pfxFile);
	    goto error;
	}
	p12 = d2i_PKCS12_fp(fp, NULL);
	if (!p12) {
	    message(LOG_ERR, "Can't read pfx file: %s", opts->pfxFile);
	    fclose(fp);
	    goto error;
	}
	fclose(fp);
	key = NULL;
	cert = NULL;
	if (!PKCS12_parse(p12, opts->passwd, &key, &cert, NULL)) {
	    message(LOG_ERR, "Can't parse PKCS12(%s) %s",
		    opts->pfxFile, ERR_error_string(ERR_get_error(), NULL));
	    goto error;
	}
	if (cert) {
	    if (!SSL_CTX_use_certificate(ss->ctx, cert)) {
		message(LOG_ERR, "SSL_CTX_use_certificate(%s) %s",
			opts->pfxFile,
			ERR_error_string(ERR_get_error(), NULL));
		X509_free(cert);
		goto error;
	    }
	    X509_free(cert);
	}
	if (key) {
	    if (!SSL_CTX_use_PrivateKey(ss->ctx, key)) {
		message(LOG_ERR, "SSL_CTX_use_PrivateKey(%s) %s",
			opts->pfxFile,
			ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_free(key);
		goto error;
	    }
	    EVP_PKEY_free(key);
	}
	PKCS12_free(p12);
    } else {
	if (opts->passwd) {
	    SSL_CTX_set_default_passwd_cb(ss->ctx, passwd_callback);
	    SSL_CTX_set_default_passwd_cb_userdata(ss->ctx, opts->passwd);
	}
	if (opts->keyFile
	    && !SSL_CTX_use_PrivateKey_file
	    (ss->ctx, opts->keyFile, X509_FILETYPE_PEM)) {
	    message(LOG_ERR, "SSL_CTX_use_PrivateKey_file(%s) %s",
		    opts->keyFile, ERR_error_string(ERR_get_error(), NULL));
	    goto error;
	}
	if (opts->certFile
	    && !SSL_CTX_use_certificate_file(ss->ctx, opts->certFile,
					     X509_FILETYPE_PEM)) {
	    message(LOG_ERR, "SSL_CTX_use_certificate_file(%s) error",
		    opts->certFile);
	    goto error;
	}
    }
#ifdef CRYPTOAPI
    if (opts->certStore) {
	if (!SSL_CTX_use_CryptoAPI_certificate(ss->ctx, opts->certStore)) {
	    message(LOG_ERR, "Can't load certificate \"%s\" "
		    "from Microsoft Certificate Store, %s",
		    opts->certStore, ERR_error_string(ERR_get_error(), NULL));
	    goto error;
        }
    }
#endif
    if (opts->cipherList
	&& !SSL_CTX_set_cipher_list(ss->ctx, opts->cipherList)) {
	message(LOG_ERR, "SSL_CTX_set_cipher_list(%s) error",
		opts->cipherList);
	goto error;
    }
    for (i=0; i < DEPTH_MAX; i++) {
	if (opts->regexp[i]) {
	    ss->re[i] = malloc(sizeof(regex_t));
	    if (!ss->re) goto memerr;
	    err = regcomp(ss->re[i], opts->regexp[i], REG_EXTENDED|REG_ICASE);
	    if (err) {
		message(LOG_ERR, "RegEx compiling error %d", err);
		goto error;
	    }
	    if (Debug > 5) {
		message(LOG_DEBUG, "regexp[%d]=%s", i, opts->regexp[i]);
	    }
	} else {
	    ss->re[i] = NULL;
	}
    }
    return ss;
 error:
    if (opts->verbose)
	message(LOG_INFO, "%s", ERR_error_string(ERR_get_error(), NULL));
    exit(1);
}

void rmStoneSSL(StoneSSL *ss) {
    int i;
    SSL_CTX_free(ss->ctx);
    for (i=0; i < DEPTH_MAX; i++) {
	if (ss->re[i]) {
	    regfree(ss->re[i]);
	    free(ss->re[i]);
	}
    }
    free(ss);
}
#endif

void rmoldstone(void) {
    Stone *stone, *next;
    stone = oldstones;
    oldstones = NULL;
    for ( ; stone != NULL; stone=next) {
	next = stone->next;
	if (stone->port) {
#ifdef USE_EPOLL
	    epoll_ctl(ePollFd, EPOLL_CTL_DEL, stone->sd, NULL);
#else
	    waitMutex(FdRinMutex);
	    waitMutex(FdEinMutex);
	    FD_CLR(stone->sd, &rin);
	    FD_CLR(stone->sd, &ein);
	    freeMutex(FdEinMutex);
	    freeMutex(FdRinMutex);
#endif
	    closesocket(stone->sd);
	}
#ifdef USE_SSL
	if (stone->ssl_server) rmStoneSSL(stone->ssl_server);
	if (stone->ssl_client) rmStoneSSL(stone->ssl_client);
#endif
	free(stone);
    }
}

void rmoldconfig(void) {
    int i;
    for (i=0; i < OldConfigArgc; i++) {
	free(OldConfigArgv[i]);
    }
    OldConfigArgc = 0;
    free(OldConfigArgv);
    OldConfigArgv = NULL;
}

void repeater(void) {
    int ret;
    static int spin = 0;
    static int nerrs = 0;
    static time_t scantime = 0;
    time_t now;
    Pair *pair;
#ifdef USE_EPOLL
    int timeout;
    struct epoll_event evs[EVSMAX];
    for (pair=PairTop; pair != NULL; pair=pair->next)
	if (pair->clock != -1 &&	/* not top */
	    !(pair->proto & proto_thread) && (pair->proto & proto_dirty))
	    proto2fdset(pair, 0, ePollFd);
    if (conns.next || trash.next || spin > 0 || AsyncCount > 0) {
	if (AsyncCount == 0 && spin > 0) spin--;
	timeout = TICK_SELECT / 1000;
    } else if (MinInterval > 0) {
	timeout = MinInterval * 1000;
    } else {
	timeout = -1;
    }
    ret = epoll_wait(ePollFd, evs, EVSMAX, timeout);
    if (Debug > 10) {
	message(LOG_DEBUG, "epoll %d: %d", ePollFd, ret);
    }
#else
    struct timeval tv, *timeout;
    fd_set rout, wout, eout;
    rout = rin;
    wout = win;
    eout = ein;
    for (pair=PairTop; pair != NULL; pair=pair->next)
	if (pair->clock != -1 &&	/* not top */
	    !(pair->proto & proto_thread))
	    proto2fdset(pair, 0, &rout, &wout, &eout);
    if (conns.next || trash.next || spin > 0 || AsyncCount > 0) {
	if (AsyncCount == 0 && spin > 0) spin--;
	timeout = &tv;
	timeout->tv_sec = 0;
	timeout->tv_usec = TICK_SELECT;
    } else if (MinInterval > 0) {
	timeout = &tv;
	timeout->tv_sec = MinInterval;
	timeout->tv_usec = 0;
    } else {
	timeout = NULL;		/* block indefinitely */
    }
    if (Debug > 10) {
	message(LOG_DEBUG, "select main(%ld)",
		(timeout ? timeout->tv_usec : 0));
	message_select(LOG_DEBUG, "select main IN ", &rout, &wout, &eout);
    }
    ret = select(FD_SETSIZE, &rout, &wout, &eout, timeout);
    if (Debug > 10) {
	message(LOG_DEBUG, "select main: %d", ret);
	message_select(LOG_DEBUG, "select main OUT", &rout, &wout, &eout);
    }
#endif
    if (ret > 0) {
	nerrs = 0;
	spin = SPIN_MAX;
#ifdef USE_EPOLL
	dispatch(ePollFd, evs, ret);
#else
	(void)(scanStones(&rout, &wout, &eout) > 0);
#endif
    } else if (ret < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno != EINTR) {
#ifdef USE_EPOLL
	    message(LOG_ERR, "epoll %d error err=%d", ePollFd, errno);
#else
	    message(LOG_ERR, "select error err=%d", errno);
#endif
	    if (++nerrs >= NERRS_MAX) {
#ifdef USE_EPOLL
		message(LOG_ERR, "epoll %d error %d times, exiting",
			ePollFd, nerrs);
#else
		message(LOG_ERR, "select error %d times, exiting", nerrs);
		message_select(LOG_INFO, "IN", &rin, &win, &ein);
#endif
		message_pairs(LOG_INFO);
		message_origins(LOG_INFO);
		message_conns(LOG_INFO);
		exit(1);
	    }
	}
	usleep(TICK_SELECT);
    }
    if (conns.next) scanConns();
    time(&now);
    if (now == scantime) return;
    scantime = now;
    if (backups && scantime - lastScanBackups >= MinInterval) {
	lastScanBackups = scantime;
	scanBackups();
    }
#ifdef USE_EPOLL
    if (PairTop) scanPairs(NULL);
    if (OriginTop) scanUDP(NULL);
#endif
    if (PairTop) scanClose(NULL);
    if (oldstones) rmoldstone();
    if (OldConfigArgc) rmoldconfig();
#ifdef USE_SSL
    ERR_remove_state(0);
#endif
}

int reusestone(Stone *stone) {
    Stone *s;
    if (!oldstones) return 0;
    for (s=oldstones; s != NULL; s=s->next) {
	if (s->port == stone->port && s->proto == stone->proto) {
	    if (Debug > 5)
		message(LOG_DEBUG, "stone %d: reused port %d", s->sd, s->port);
	    stone->sd = s->sd;
	    s->port = 0;
	    return 1;
	}
    }
    return 0;
}

#ifdef NO_FAMILY_T
typedef int sa_family_t;
#endif

void mkXhostsExt(char *host, char *str, XHosts *ext) {
    int kind = 0;
    char *top;
    u_long num;
    int i = 0;
    do {
	switch(kind) {
	case -3:	/* pass if digit or '.' until ',' */
	    if (str[i] == '.') break;
	case -2:	/* pass if digit until ',' */
	    if (isdigit(str[i])) break;
	case -1:	/* pass ',' */
	    if (str[i] == ',' || str[i] == '\0') {
		kind = 0;	/* found next ext */
		break;
	    }
	error:
	    message(LOG_ERR, "Unknown extension: \"%s\" in %s/%s",
		    &str[i], host, str);
	    exit(1);
	case 0:
	    top = &str[i];
	    if (isdigit(*top)) {
		num = *top - '0';
		kind = 1;
		break;
	    }
	    if (*top == 'v') {
		i++;
		if (top[1] == '4') {
		    ext->xhost.addr.sa_family = AF_INET;
#ifdef AF_INET6
		} else if (top[1] == '6') {
		    ext->xhost.addr.sa_family = AF_INET6;
#endif
		} else {
		    goto error;
		}
		kind = -1;	/* expect ',' or end of string */
		break;
	    }
	    if (*top == 'p') {
		if (isdigit(top[1])) {
		    ext->mode = atoi(top+1);
		} else {
		    ext->mode = 1;
		}
		kind = -2;	/* skip to the next ext */
		break;
	    }
	    goto error;
	case 1:	/* net mask */
	    if (str[i] == ',' || str[i] == '\0') {
		ext->mbits = num;
		if (ext->mbits > 32) {
#ifdef AF_INET6
		    /* force to set IPv6 */
		    ext->xhost.addr.sa_family = AF_INET6;
		}
		if (ext->mbits > 128) {
#endif
		    goto error;
		}
		kind = 0;	/* found next ext */
		break;
	    }
	case 2:	/* nnn.<nnn>.nnn.nnn */
	case 3:	/* nnn.nnn.<nnn>.nnn */
	    if (str[i] == '.') {
		i++;
		num <<= 8;
		kind++;
	    }
	case 4:	/* nnn.nnn.nnn.<nnn> */
	    if (isdigit(str[i])) {
		num = ((num & 0xFFFFFF00)
		       | ((num & 0xFF) * 10 + (str[i] - '0')));
		break;
	    }
	    ext->xhost.addr.sa_family = AF_INET;	/* force to set IPv4 */
	    for (ext->mbits=0; ext->mbits < 32 && num; ext->mbits++) {
		if (!(num & 0x80000000)) {
		    message(LOG_ERR, "netmask by bits pattern "
			    "is deprecated: %s/%s", host, top);
		    exit(1);
		}
		num <<= 1;
	    }
	    i--;	/* unget */
	    kind = -1;	/* expect ',' or end of string */
	    break;
	default:
	    message(LOG_ERR, "Can't happen: kind=%d in mkXhostsExt", kind);
	    exit(1);
	}
    } while (str[i++]);
    if (Debug > 9) message(LOG_DEBUG, "mkXhostsExt: host=%s ext=%s "
			   "family=%d mbits=%d mode=%d",
			   host, str, ext->xhost.addr.sa_family,
			   ext->mbits, ext->mode);
}

XHosts *mkXhosts(int nhosts, char *hosts[], sa_family_t family, char *mesg) {
    XHosts *top = NULL;
    XHosts *bot = NULL;
    char xhost[STRMAX+1];
    int allow = 1;
    int i;
    char *p;
    for (i=0; i < nhosts; i++) {
	XHosts *new;
	if (Debug > 10) message(LOG_DEBUG, "xhost[%d]=\"%s\"", i, hosts[i]);
	if (!strcmp(hosts[i], "!")) {
	    new = malloc(XHostsBaseSize);
	    if (!new) goto memerr;
	    new->mbits = -1;
	    allow = !allow;
	} else {
	    short mbits = -1;
	    short mode = 0;
	    struct sockaddr_storage ss;
	    struct sockaddr *sa = (struct sockaddr*)&ss;
	    int salen = sizeof(ss);
	    strcpy(xhost, hosts[i]);
	    p = strchr(xhost, '/');
	    if (p) {
		XHosts ext;
		*p++ = '\0';
		ext.mbits = mbits;
		ext.mode = mode;
		ext.xhost.addr.sa_family = family;
		mkXhostsExt(xhost, p, &ext);
		mbits = ext.mbits;
		mode = ext.mode;
		family = ext.xhost.addr.sa_family;
	    }
	    sa->sa_family = family;
	    if (!host2sa(xhost, NULL, sa, &salen, NULL, NULL, 0)) exit(1);
	    new = malloc(XHostsBaseSize+salen);
	    if (!new) goto memerr;
	    new->xhost.len = salen;
	    bcopy(sa, &new->xhost.addr, salen);
	    if (mbits < 0) {
		if (sa->sa_family == AF_INET) {
		    mbits = 32;
#ifdef AF_INET6
		} else if (sa->sa_family == AF_INET6) {
		    mbits = 128;
#endif
		} else {
		    message(LOG_ERR, "mkXhosts: unknown family=%d",
			    sa->sa_family);
		    exit(1);
		}
	    }
	    new->mbits = mbits;
	    new->mode = mode;
	    if (mesg) {
		char str[STRMAX+1];
		int pos = 0;
		addr2str(&new->xhost.addr, new->xhost.len,
			 str, STRMAX, NI_NUMERICHOST);
		pos = strlen(str);
		snprintf(str+pos, STRMAX-pos, "/%d", new->mbits);
		pos += strlen(str+pos);
		message(LOG_DEBUG, "%s%s is %s", mesg, str,
			(allow ? "permitted" : "denied"));
	    }
	}
	new->next = NULL;
	if (!top) top = new;
	if (bot) bot->next = new;
	bot = new;
    }
    return top;
 memerr:
    message(LOG_CRIT, "Out of memory");
    exit(1);
}

int mkPortXhosts(int argc, int i, char *argv[]) {
    PortXHosts *pxh;
    XPorts *top = NULL;
    XPorts *bot = NULL;
    char **hosts;
    char *p, *q;
    char str[STRMAX+1];
    int isnum;
    int from;
    int j;
    i++;
    if (!strcmp(argv[i], "--")) {
	portXHosts = NULL;
	return i;
    }
    p = argv[i];
    q = str;
    isnum = 1;
    from = -1;
    for (;;) {
	if (*p == ',' || *p == '-' || *p == '\0') {
	    int port;
	    *q = '\0';
	    if (str[0]) {
		if (isnum) port = atoi(str);
		else {
		    struct sockaddr_storage ss;
		    struct sockaddr *sa = (struct sockaddr*)&ss;
		    socklen_t salen = sizeof(ss);
		    if (!host2sa(NULL, str, sa, &salen, NULL, NULL, 0)) {
			goto opterr;
		    }
		    port = getport(sa);
		}
	    } else {
	    opterr:
		message(LOG_ERR, "Illegal option: -x requires port list: %s",
			argv[i]);
		exit(1);
	    }
	    if (*p == '-') {
		from = port;
	    } else {
		XPorts *new = malloc(sizeof(XPorts));
		if (!new) goto memerr;
		new->next = NULL;
		if (from >= 0) new->from = from;
		else new->from = port;
		new->end = port;
		from = -1;
		if (bot) bot->next = new;
		bot = new;
		if (!top) top = new;
		if (*p == '\0') break;
	    }
	    p++;
	    q = str;
	    isnum = 1;
	    continue;
	} else if (!isdigit(*p)) {
	    isnum = 0;
	}
	*q++ = *p++;
    }
    if (Debug > 5) {
	char buf[BUFMAX];
	XPorts *cur;
	j = 0;
	for (cur=top; j < BUFMAX && cur; cur=cur->next) {
	    if (j > 0) buf[j++] = ',';
	    snprintf(buf+j, BUFMAX-1-j, "%d-%d", cur->from, cur->end);
	    j += strlen(buf+j);
	}
	buf[j] = '\0';
	message(LOG_DEBUG, "XPorts: %s", buf);
    }
    i++;
    hosts = &argv[i];
    j = 0;
    for (; i < argc; i++, j++) if (!strcmp(argv[i], "--")) break;
    pxh = malloc(sizeof(PortXHosts));
    if (!pxh) goto memerr;
    pxh->ports = top;
    if (Debug > 5) p = "XHosts: "; else p = NULL;
    pxh->xhosts = mkXhosts(j, hosts, AF_UNSPEC, p);
    pxh->next = portXHosts;
    portXHosts = pxh;
    return i;
 memerr:
    message(LOG_CRIT, "Out of memory");
    exit(1);
}

/* make stone */
Stone *mkstone(
    char *dhost,	/* destination hostname */
    char *dserv,	/* destination port */
    char *host,		/* listening host */
    char *serv,		/* listening port */
    int nhosts,		/* # of hosts to permit */
    char *hosts[],	/* hosts to permit */
    int proto) {	/* UDP/TCP/SSL */
    Stone *stonep;
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr*)&ss;
    int salen = sizeof(ss);
    int satype;
    int saproto = 0;
    sa_family_t family;
    char *mesg;
    char str[STRMAX+1];
    stonep = calloc(1, sizeof(Stone));
    if (!stonep) {
	message(LOG_CRIT, "Out of memory");
	exit(1);
    }
    stonep->common = type_stone;
    stonep->p = NULL;
    stonep->timeout = PairTimeOut;
    if (proto & proto_udp_s) {
	satype = SOCK_DGRAM;
	saproto = IPPROTO_UDP;
    } else {
	satype = SOCK_STREAM;
	saproto = IPPROTO_TCP;
    }
#ifdef AF_LOCAL
    if (proto & proto_unix_s) {
	struct sockaddr_un *sun = (struct sockaddr_un*)sa;
	salen = sizeof(struct sockaddr_un);
	bzero(sa, salen);
	sun->sun_family = AF_LOCAL;
	snprintf(sun->sun_path, sizeof(sun->sun_path)-1, "%s", host);
	saproto = 0;
    } else
#endif
#ifdef AF_INET6
    if (proto & proto_v6_s) {
	struct sockaddr_in6 *sin6p = (struct sockaddr_in6*)sa;
	sa->sa_family = AF_INET6;
	if (!host2sa(host, serv, sa, &salen, &satype, &saproto, AI_PASSIVE))
	    exit(1);
	stonep->port = ntohs(sin6p->sin6_port);
    } else
#endif
    {
	struct sockaddr_in *sinp = (struct sockaddr_in*)sa;
	sa->sa_family = AF_INET;
	if (!host2sa(host, serv, sa, &salen, &satype, &saproto, AI_PASSIVE))
	    exit(1);
	stonep->port = ntohs(sinp->sin_port);
    }
    if ((proto & proto_command) == command_proxy
	|| (proto & proto_command) == command_health
	|| (proto & proto_command) == command_identd) {
	stonep->ndsts = 1;
	if ((proto & proto_command) == command_proxy) {
	    stonep->dsts = malloc(sizeof(SockAddr*) + sizeof(PortXHosts*));
	    if (stonep->dsts) ((PortXHosts**)stonep->dsts)[1] = portXHosts;
	    /* only proxy stone needs portXHosts,
	       so we divert dsts into holding current portXHosts */
	} else {
	    stonep->dsts = malloc(sizeof(SockAddr*));	/* dummy */
	}
	if (!stonep->dsts) goto memerr;
	stonep->dsts[0] = saDup(sa, salen);	/* dummy */
#ifdef AF_LOCAL
    } else if (proto & proto_unix_d) {
	struct sockaddr_storage dss;
	struct sockaddr_un *sun = (struct sockaddr_un*)&dss;
	stonep->ndsts = 1;
	stonep->dsts = malloc(sizeof(SockAddr*));
	if (!stonep->dsts) goto memerr;
	bzero(sun, sizeof(dss));
	sun->sun_family = AF_LOCAL;
	snprintf(sun->sun_path, sizeof(sun->sun_path)-1, "%s", dhost);
	stonep->dsts[0] = saDup((struct sockaddr*)sun,
				sizeof(struct sockaddr_un));
	if (!stonep->dsts[0]) goto memerr;
#endif
    } else {
	struct sockaddr_storage dss;
	struct sockaddr *dsa = (struct sockaddr*)&dss;
	socklen_t dsalen = sizeof(dss);
	int dsatype = satype;
	int dsaproto = 0;
	LBSet *lbset;
#ifdef AF_INET6
	if (proto & proto_v6_d) dsa->sa_family = AF_INET6;
	else
#endif
	    dsa->sa_family = AF_INET;
	if (!host2sa(dhost, dserv, dsa, &dsalen, &dsatype, &dsaproto, 0)) {
	    exit(1);
	}
	lbset = findLBSet(dsa);
	if (lbset) {
	    stonep->ndsts = lbset->ndsts;
	    stonep->dsts = lbset->dsts;
	} else {
	    stonep->ndsts = 1;
	    stonep->dsts = malloc(sizeof(SockAddr*));
	    if (!stonep->dsts) {
	    memerr:
		message(LOG_CRIT, "Out of memory");
		exit(1);
	    }
	    stonep->dsts[0] = saDup(dsa, dsalen);
	    if (!stonep->dsts[0]) goto memerr;
	}
    }
    stonep->proto = proto;
    stonep->from = ConnectFrom;
    if (!reusestone(stonep)) {	/* recycle stone */
	stonep->sd = socket(sa->sa_family, satype, saproto);
	if (InvalidSocket(stonep->sd)) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR, "stone %d: Can't get socket "
		    "family=%d type=%d proto=%d err=%d",
		    stonep->sd, sa->sa_family, satype, saproto, errno);
	    exit(1);
	}
#ifdef IPV6_V6ONLY
	if ((proto & proto_v6_s) && (proto & proto_ip_only_s)) {
	    int i = 1;
	    setsockopt(stonep->sd, IPPROTO_IPV6, IPV6_V6ONLY,
		       (char*)&i, sizeof(i));
	}
#endif
	if (!(proto & proto_udp_s) && ReuseAddr) {
	    int i = 1;
	    setsockopt(stonep->sd, SOL_SOCKET, SO_REUSEADDR,
		       (char*)&i, sizeof(i));
	}
	if (!DryRun) {
	    if (bind(stonep->sd, sa, salen) < 0) {
		char str[STRMAX+1];
#ifdef WINDOWS
		errno = WSAGetLastError();
#endif
		addrport2str(sa, salen, 0, str, STRMAX, 0);
		str[STRMAX] = '\0';
		message(LOG_ERR, "stone %d: Can't bind %s err=%d",
			stonep->sd, str, errno);
		exit(1);
	    }
	    if (!(stonep->proto & proto_block_s)) {
#ifdef WINDOWS
		u_long param;
		param = 1;
		ioctlsocket(stonep->sd, FIONBIO, &param);
#else
		fcntl(stonep->sd, F_SETFL, O_NONBLOCK);
#endif
	    }
	    if (stonep->port == 0) {
		salen = sizeof(ss);
		getsockname(stonep->sd, sa, &salen);
	    }
	    if (!(proto & proto_udp_s)) {	/* TCP */
		if (listen(stonep->sd, BacklogMax) < 0) {
#ifdef WINDOWS
		    errno = WSAGetLastError();
#endif
		    message(LOG_ERR, "stone %d: Can't listen err=%d",
			    stonep->sd, errno);
		    exit(1);
		}
	    }
	}	/* !DryRun */
    }
#ifdef USE_SSL
    if (proto & proto_ssl_s) {	/* server side SSL */
	stonep->ssl_server = mkStoneSSL(&ServerOpts, 1);
	if (stonep->ssl_server->lbmod) {
	    if (stonep->ssl_server->lbmod > stonep->ndsts) {
		message(LOG_WARNING, "LB set (%d) < lbmod (%d)",
			stonep->ndsts, stonep->ssl_server->lbmod);
		stonep->ssl_server->lbmod = stonep->ndsts;
	    }
	}
    } else {
	stonep->ssl_server = NULL;
    }
    if (proto & proto_ssl_d) {	/* client side SSL */
	stonep->ssl_client = mkStoneSSL(&ClientOpts, 0);
    } else {
	stonep->ssl_client = NULL;
    }
#endif
    mesg = NULL;
    if (Debug > 1) {
	mesg = str;
	if ((proto & proto_command) == command_proxy) {
	    snprintf(mesg, STRMAX, "stone %d: using proxy by ",
		     stonep->sd);
	} else if ((proto & proto_command) == command_health) {
	    snprintf(mesg, STRMAX, "stone %d: health check by ", stonep->sd);
	} else if ((proto & proto_command) == command_identd) {
	    snprintf(mesg, STRMAX, "stone %d: ident query by ", stonep->sd);
	} else {
	    char addrport[STRMAX+1];
	    addrport2str(&stonep->dsts[0]->addr, stonep->dsts[0]->len,
			 (stonep->proto & proto_stone_d),
			 addrport, STRMAX, 0);
	    addrport[STRMAX] = '\0';
	    snprintf(mesg, STRMAX, "stone %d: connecting to %s by ",
		     stonep->sd, addrport);
	}
    }
    family = AF_INET;
#ifdef AF_INET6
    if (stonep->proto & proto_v6_s) {
	if (host == NULL && !(stonep->proto & proto_ip_only_s)) {
	    family = AF_UNSPEC;
	} else {
	    family = AF_INET6;
	}
    }
#endif
    stonep->xhosts = mkXhosts(nhosts, hosts, family, mesg);
    message(LOG_INFO, "%s", stone2str(stonep, str, STRMAX));
    stonep->backups = NULL;
    if ((proto & proto_command) != command_proxy
	&& (proto & proto_command) != command_health
	&& (proto & proto_command) != command_identd
	&& (proto & proto_nobackup) == 0) {
	Backup *bs[LB_MAX];
	int found = 0;
	int i;
	for (i=0; i < stonep->ndsts; i++) {
	    bs[i] = findBackup(&stonep->dsts[i]->addr);
	    if (bs[i]) {
		found = 1;
		bs[i]->used = 1;
	    }
	}
	if (found) {
	    stonep->backups = malloc(sizeof(Backup*) * stonep->ndsts);
	    if (stonep->backups) {
		for (i=0; i < stonep->ndsts; i++) stonep->backups[i] = bs[i];
	    }
	}
    }
    return stonep;
}

/* main */

void help(char *com, char *sub) {
    message(LOG_INFO, "stone %s  http://www.gcd.org/sengoku/stone/", VERSION);
    message(LOG_INFO, "%s",
	    "Copyright(C)2005 by Hiroaki Sengoku <sengoku@gcd.org>");
#ifdef USE_SSL
    message(LOG_INFO, "%s",
	    "using " OPENSSL_VERSION_TEXT "  http://www.openssl.org/");
#ifdef CRYPTOAPI
    message(LOG_INFO, "%s",
	    "using cryptoapi.c by Peter 'Luna' Runestig <peter@runestig.com>");
#endif
#endif
    if (!sub) {
    help:
	fprintf(stderr,
		"Usage: %s <opt>... <stone> [-- <stone>]...\n"
		"opt:  -h opt            ; help for <opt> more\n"
		"      -h stone          ; help for <stone>\n"
#ifdef USE_SSL
		"      -h ssl            ; help for <SSL>, see -q/-z opt\n"
#endif
		, com);
	return;
    }
    if (!strcmp(sub, "opt")) {
	fprintf(stderr, "Usage: %s <opt>... <stone> [-- <stone>]...\n"
"opt:  -C <file>         ; configuration file\n"
#ifdef CPP
"      -P <command>      ; preprocessor for config. file\n"
"      -Q <options>      ; options for preprocessor\n"
#endif
"      -N                ; configuration check only\n"
"      -d                ; increase debug level\n"
"      -p                ; packet dump\n"
"      -n                ; numerical address\n"
"      -u <max>          ; # of UDP sessions\n"
#ifndef NO_FORK
"      -f <n>            ; # of child processes\n"
#endif
#ifndef NO_SYSLOG
"      -l                ; use syslog\n"
"      -ll               ; run under daemontools\n"
#endif
"      -L <file>         ; write log to <file>\n"
"      -a <file>         ; write accounting to <file>\n"
"      -i <file>         ; write process ID to <file>\n"
"      -X <n>            ; size [byte] of Xfer buffer\n"
"      -T <n>            ; timeout [sec] of TCP sessions\n"
"      -A <n>            ; length of backlog\n"
"      -r                ; reuse socket\n"
"      -x <port>[,<port>][-<port>]... <xhost> --\n"
"                        ; permit connecting to <xhost>:<port>\n"
"      -s <send> <expect>... --\n"
"                        ; health check script\n"
"      -b <n> <master>:<port> <backup>:<port>\n"
"                        ; check <master>:<port> every <n> sec\n"
"                        ; use <backup>:<port>, if check failed\n"
"      -B <host>:<port>... --\n"
"                        ; load balancing hosts\n"
#ifdef ADDRCACHE
"      -H <size>         ; cache addresses used in proxy\n"
#endif
"      -I <host>         ; local end of its connections to\n"
#ifndef NO_SETUID
"      -o <n>            ; set uid to <n>\n"
"      -g <n>            ; set gid to <n>\n"
#endif
#ifndef NO_CHROOT
"      -t <dir>          ; chroot to <dir>\n"
#endif
#ifdef UNIX_DAEMON
"      -D                ; become UNIX Daemon\n"
#endif
"      -c <dir>          ; core dump to <dir>\n"
#ifdef USE_SSL
"      -q <SSL>          ; SSL client option\n"
"      -z <SSL>          ; SSL server option\n"
"                        ; `-h ssl' for <SSL>\n"
#endif
#ifdef NT_SERVICE
"      -M install <name> ; install service as <name>\n"
"      -M remove <name>  ; remove service <name>\n"
#endif
		, com);
    } else if (!strcmp(sub, "stone")) {
	fprintf(stderr, "Usage: %s <opt>... <stone> [-- <stone>]...\n"
		"stone: <host>:<port> <sport> [<xhost>...]\n"
		"       proxy"
#ifdef AF_INET6
		"[/[v4only | v6only]]"
#endif
		" <sport> [<xhost>...]\n"
		"       health <sport> [<xhost>...]\n"
		"       identd <sport> [<xhost>...]\n"
		"       <host>:<port#>/http <sport> "
		"<Request-Line> [<xhost>...]\n"
		"       <host>:<port#>/proxy <sport> <header> [<xhost>...]\n"
		"       <host>:<port#>/mproxy <sport> <header> [<xhost>...]\n"
		"port:  <port#>[/<ext>[,<ext>]...]\n"
		"ext:   tcp | udp"
#ifdef USE_SSL
		" | ssl"
#endif
#ifdef AF_INET6
		" | v6"
#endif
#ifdef USE_POP
		" | apop"
#endif
		" | base | block | nobackup\n"
		"sport: [<host>:]<port#>[/<exts>[,<exts>]...]\n"
		"exts:  tcp | udp"
#ifdef USE_SSL
		" | ssl"
#endif
#ifdef AF_INET6
		" | v6 | v6only"
#endif
		" | http | base | block | ident\n"
		"xhost: <host>[/<ex>[,<ex>]...]\n"
		"ex:    <#bits> | p<mode#>"
#ifdef AF_INET6
		" | v6"
#endif
		"\n"
		, com);
#ifdef USE_SSL
    } else if (!strcmp(sub, "ssl")) {
	fprintf(stderr,
"opt:  -q <SSL>          ; SSL client option\n"
"      -z <SSL>          ; SSL server option\n"
"SSL:   default          ; reset to default\n"
"       verbose          ; verbose mode\n"
"       verify           ; require peer's certificate\n"
"       verify,once      ; verify client's certificate only once\n"
"       verify,ifany     ; verify client's certificate if any\n"
"       verify,none      ; don't require peer's certificate\n"
"       crl_check        ; lookup CRLs\n"
"       crl_check_all    ; lookup CRLs for whole chain\n"
"       uniq             ; check serial # of peer's certificate\n"
"       re<n>=<regex>    ; verify depth <n> with <regex>\n"
"       depth=<n>        ; set verification depth to <n>\n"
#ifndef OPENSSL_NO_TLS1
"       tls1             ; just use TLSv1\n"
#endif
#ifndef OPENSSL_NO_SSL3
"       ssl3             ; just use SSLv3\n"
#endif
#ifndef OPENSSL_NO_SSL2
"       ssl2             ; just use SSLv2\n"
#endif
"       no_tls1          ; turn off TLSv1\n"
"       no_ssl3          ; turn off SSLv3\n"
"       no_ssl2          ; turn off SSLv2\n"
"       bugs             ; SSL implementation bug workarounds\n"
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
"       serverpref       ; use server's cipher preferences (SSLv2)\n"
#endif
"       shutdown=<mode>  ; accurate, nowait, unclean\n"
"       sid_ctx=<str>    ; set session ID context\n"
"       passfile=<file>  ; password file\n"
"       key=<file>       ; key file\n"
"       cert=<file>      ; certificate file\n"
"       CAfile=<file>    ; certificate file of CA\n"
"       CApath=<dir>     ; dir of CAs\n"
"       pfx=<file>       ; PKCS#12 file\n"
#ifdef CRYPTOAPI
"       store=<prop>     ; \"SUBJ:<substr>\" or \"THUMB:<hex>\"\n"
#endif
"       cipher=<ciphers> ; list of ciphers\n"
"       lb<n>=<m>        ; load balancing based on CN\n"
	    );
#endif
    } else {
	goto help;
    }
}

static void skipcomment(FILE *fp) {
    int c;
    while ((c=getc(fp)) != EOF && c != '\r' && c != '\n')	;
    while ((c=getc(fp)) != EOF && (c == '\r' || c == '\n'))	;
    if (c != EOF) ungetc(c, fp);
}

static int getvar(FILE *fp, char *buf, int bufmax) {
    char var[STRMAX+1];
    char *val;
    int i = 0;
    int paren = 0;
    int c = getc(fp);
    if (c == EOF) {
	return 0;
    } else if (c == '{') {
	paren = 1;
    } else {
	ungetc(c, fp);
    }
    while ((c=getc(fp)) != EOF && i < STRMAX) {
	if (paren && c == '}') {
	    break;
	} else if (isalnum(c) || c == '_') {
	    var[i++] = c;
	} else {
	    ungetc(c, fp);
	    break;
	}
    }
    var[i] = '\0';
    if (*var == '\0') return 0;
    val = getenv(var);
    if (val == NULL) return 0;
    i = strlen(val);
    if (i > bufmax) i = bufmax;
    strncpy(buf, val, i);
    return i;
}

static int gettoken(FILE *fp, char *buf) {
    int i = 0;
    int quote = 0;
    int c;
    for (;;) {
	c = getc(fp);
	if (c == EOF) return -1;
	if (c == '#') {
	    skipcomment(fp);
	    continue;
	}
	if (!isspace(c)) {
	    ungetc(c, fp);
	    break;
	}
    }
    while (i < BUFMAX-1) {
	c = getc(fp);
	if (c == EOF) {
	    if (i > 0) break;
	    return -1;
	}
	if (quote != '\'') {
	    if (c == '$') {
		i += getvar(fp, &buf[i], BUFMAX-1-i);
		continue;
	    }
	    if (c == '\\') {	/* escape a char */
		c = getc(fp);
		if (c == EOF) break;
		switch(c) {
		case 'n':  c = '\n';  break;
		case 'r':  c = '\r';  break;
		case 't':  c = '\t';  break;
		}
	    }
	}
	if (quote) {
	    if (c == quote) {
		quote = 0;
		continue;
	    }
	} else if (c == '\'' || c == '\"') {
	    quote = c;
	    continue;
	} else if (isspace(c)) {
	    c = getc(fp);
	    if (c != ':' && c != '=') {
		ungetc(c, fp);
		break;
	    }
	} else if (c == '#') {
	    skipcomment(fp);
	    continue;
	}
	buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

FILE *openconfig(void) {
#ifdef CPP
    int pfd[2];
    char host[MAXHOSTNAMELEN];
    if (CppCommand != NULL && *CppCommand != '\0') {
	if (gethostname(host, MAXHOSTNAMELEN-1) < 0) {
	    message(LOG_ERR, "gethostname err=%d", errno);
	    exit(1);
	}
	if (pipe(pfd) < 0) {
	    message(LOG_ERR, "Can't get pipe err=%d", errno);
	    exit(1);
	}
	if (!fork()) {
	    char *argv[BUFMAX/2];
	    int i = 0;
	    char buf[BUFMAX];
	    int len = 0;
	    char *p;
	    if (CppOptions) {
		snprintf(buf, BUFMAX-1, "%s %s", CppCommand, CppOptions);
	    } else {
		strncpy(buf, CppCommand, BUFMAX-1);
	    }
	    argv[i] = "cpp";
	    while (buf[len]) {
		if (isspace(buf[len])) {
		    buf[len++] = '\0';
		    while (buf[len] && isspace(buf[len])) len++;
		    if (buf[len]) argv[++i] = &buf[len];
		    else break;
		}
		len++;
	    }
	    len++;
	    argv[++i] = buf + len;
	    snprintf(argv[i], BUFMAX-len, "-DHOST=%s", host);
	    len += strlen(argv[i]) + 1;
	    argv[++i] = buf + len;
	    for (p=host; *p; p++) if (*p == '.') *p = '_';
	    snprintf(argv[i], BUFMAX-len, "-DHOST_%s", host);
	    len += strlen(argv[i]) + 1;
	    if (getenv("HOME")) {
		argv[++i] = buf + len;
		snprintf(argv[i], BUFMAX-len, "-DHOME=%s", getenv("HOME"));
		len += strlen(argv[i]) + 1;
	    }
	    argv[++i] = ConfigFile;
	    argv[++i] = NULL;
	    close(pfd[0]);
	    close(1);
	    dup(pfd[1]);
	    close(pfd[1]);
	    if (Debug > 9) {
		char str[BUFMAX];
		snprintf(str, BUFMAX, "%s: ", buf);
		for (i=0; argv[i]; i++) {
		    len = strlen(str);
		    snprintf(&str[len], BUFMAX-len, " %s", argv[i]);
		}
		message(LOG_DEBUG, "%s", str);
	    }
	    execv(buf, argv);
	}
	close(pfd[1]);
	return fdopen(pfd[0], "r");
    } else
#endif
	return fopen(ConfigFile, "r");
}

void getconfig(void) {
    FILE *fp;
    int nptr = 0;
    char **new;
    char buf[BUFMAX];
    int len;
    if (ConfigFile == NULL) return;
    ConfigArgc = 0;
    ConfigArgv = NULL;
    fp = openconfig();
    if (fp == NULL) {
	message(LOG_ERR, "Can't open config file: %s err=%d",
		ConfigFile, errno);
	exit(1);
    }
    strcpy(buf, ConfigFile);
    len = strlen(buf);
    do {
	if (Debug > 9) message(LOG_DEBUG, "token: \"%s\"", buf);
	if (ConfigArgc >= nptr) {	/* allocate new ptrs */
	    new = malloc((nptr+BUFMAX)*sizeof(*ConfigArgv));
	    if (new == NULL) {
		message(LOG_CRIT, "Out of memory");
		exit(1);
	    }
	    if (ConfigArgv) {
		bcopy(ConfigArgv, new, nptr*sizeof(*ConfigArgv));
		free(ConfigArgv);
	    }
	    ConfigArgv = new;
	    nptr += BUFMAX;
	}
	ConfigArgv[ConfigArgc] = malloc(len+1);
	bcopy(buf, ConfigArgv[ConfigArgc], len+1);
	ConfigArgc++;
    } while ((len=gettoken(fp, buf)) >= 0);
    fclose(fp);
#ifdef CPP
    if (CppCommand != NULL && *CppCommand != '\0') {
	wait(NULL);
    }
#endif
}

int getdist(	/* return pos where serv begins */
    char *p,
    int *protop) {
    char *port_str, *proto_str, *top;
    top = p;
    port_str = proto_str = NULL;
    *protop = 0;	/* default */
#ifdef AF_LOCAL
    if (p[0] == '.' || p[0] == '/') {
	struct stat st;
	p++;
	while (*p) {
	    if (*p == '/') proto_str = ++p;
	    else p++;
	}
	if (proto_str) {
	    *(proto_str-1) = '\0';
	    if (stat(top, &st) >=0 && S_ISDIR(st.st_mode)) {
		*(proto_str-1) = '/';	/* restore */
		proto_str = NULL;
	    }
	}
	*protop |= proto_unix;
    } else
#endif
    while (*p) {
	if (*p == ':') port_str = ++p;
	else if (*p == '/') proto_str = ++p;
	else p++;
    }
    if (proto_str) {
	*(proto_str-1) = '\0';
	p = proto_str;
	do {
	    if (!strncmp(p, "tcp", 3)) {
		p += 3;
		*protop &= ~proto_udp;
	    } else if (!strncmp(p, "udp", 3)) {
		p += 3;
		*protop |= proto_udp;
	    } else if (!strncmp(p, "http", 4)) {
		p += 4;
		*protop |= proto_ohttp;
	    } else if (!strncmp(p, "base", 4)) {
		p += 4;
		*protop |= proto_base;
	    } else if (!strncmp(p, "ident", 5)) {
		p += 5;
		*protop |= proto_ident;
	    } else if (!strncmp(p, "proxy", 5)) {
		p += 5;
		*protop &= ~proto_command;
		*protop |= command_ihead;
	    } else if (!strncmp(p, "mproxy", 6)) {
		p += 6;
		*protop &= ~proto_command;
		*protop |= command_iheads;
	    } else if (!strncmp(p, "nobackup", 8)) {
		p += 8;
		*protop |= proto_nobackup;
#ifdef USE_SSL
	    } else if (!strncmp(p, "ssl", 3)) {
		p += 3;
		*protop |= proto_ssl;
#endif
#ifdef AF_INET6
	    } else if (!strncmp(p, "v6", 2)) {
		p += 2;
		*protop |= proto_v6;
		if (!strncmp(p, "only", 4)) {
		    p += 4;
		    *protop |= proto_ip_only;
		}
#endif
	    } else if (!strncmp(p, "v4only", 6)) {
		p += 6;
		*protop |= proto_ip_only;
	    } else if (!strncmp(p, "block", 5)) {
		p += 5;
		*protop |= proto_block;
#ifdef USE_POP
	    } else if (!strncmp(p, "apop", 4)) {
		p += 4;
		*protop &= ~proto_command;
		*protop |= command_pop;
#endif
	    } else return -1;	/* error */
	} while ((*p == ',' || *p == '/') && p++);
    }
    if (port_str) {
	*(port_str-1) = '\0';
	return port_str - top;	/* host & serv */
    } else {
#ifdef AF_LOCAL
	if (*protop & proto_unix) {
	    return 1;
	}
#endif
	if (!strcmp(top, "proxy")) {
	    *protop &= ~proto_command;
	    *protop |= command_proxy;
	    return 1;	/* host only */
	}
	if (!strcmp(top, "health")) {
	    *protop &= ~proto_command;
	    *protop |= command_health;
	    return 1;	/* host only */
	}
	if (!strcmp(top, "identd")) {
	    *protop &= ~proto_command;
	    *protop |= command_identd;
	    return 1;	/* host only */
	}
	return 0;	/* serv only */
    }
}

#ifdef USE_SSL
void sslopts_default(SSLOpts *opts, int isserver) {
    int i;
    opts->verbose = 0;
    opts->shutdown_mode = 0;
    opts->mode = SSL_VERIFY_NONE;
    opts->depth = DEPTH_MAX - 1;
    opts->vflags = 0;
    opts->off = 0;
    opts->serial = -2;
    opts->callback = verify_callback;
    opts->sid_ctx = NULL;
    if (isserver) {
	char path[BUFMAX];
	snprintf(path, BUFMAX-1, "%s/stone.pem", X509_get_default_cert_dir());
	opts->keyFile = opts->certFile = strdup(path);
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	opts->meth = SSLv23_server_method();
#elif !defined(OPENSSL_NO_SSL3)
	opts->meth = SSLv3_server_method();
#elif !defined(OPENSSL_NO_SSL2)
	opts->meth = SSLv2_server_method();
#endif
    } else {
	opts->keyFile = opts->certFile = NULL;
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	opts->meth = SSLv23_client_method();
#elif !defined(OPENSSL_NO_SSL3)
	opts->meth = SSLv3_client_method();
#elif !defined(OPENSSL_NO_SSL2)
	opts->meth = SSLv2_client_method();
#endif
    }
    opts->caFile = opts->caPath = NULL;
    opts->pfxFile = NULL;
    opts->passwd = NULL;
#ifdef CRYPTOAPI
    opts->certStore = NULL;
#endif
    opts->cipherList = getenv("SSL_CIPHER");
    for (i=0; i < DEPTH_MAX; i++) opts->regexp[i] = NULL;
    opts->lbmod = 0;
    opts->lbparm = 0xFF;
    opts->shutdown_mode = 0;
}

int sslopts(int argc, int argi, char *argv[], SSLOpts *opts, int isserver) {
    if (!strcmp(argv[argi], "default")) {
	sslopts_default(opts, isserver);
    } else if (!strcmp(argv[argi], "verbose")) {
	opts->verbose++;
    } else if (!strncmp(argv[argi], "shutdown=", 9)) {
	if (!strcmp(argv[argi]+9, "nowait")) {
	    opts->shutdown_mode = SSL_RECEIVED_SHUTDOWN;
	} else if (!strcmp(argv[argi]+9, "accurate")) {
	    opts->shutdown_mode = 0;
	} else if (!strcmp(argv[argi]+9, "unclean")) {
	    opts->shutdown_mode = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
	}
    } else if (!strncmp(argv[argi], "verify", 6)
	       && (argv[argi][6] == '\0' || argv[argi][6] == ',')) {
	if (!strcmp(argv[argi]+6, ",none")) {
	    opts->mode = SSL_VERIFY_NONE;
	} else if (isserver) {
	    opts->mode = (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	    if (argv[argi][6] == ',') {
		if (!strcmp(argv[argi]+7, "ifany")) {
		    opts->mode = (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
		} else if (!strcmp(argv[argi]+7, "once")) {
		    opts->mode |= SSL_VERIFY_CLIENT_ONCE;
		}
	    }
	} else if (argv[argi][6] == '\0') {
	    opts->mode = SSL_VERIFY_PEER;
	} else {
	    goto error;
	}
    } else if (!strncmp(argv[argi], "crl_check", 9)) {
	opts->vflags |= X509_V_FLAG_CRL_CHECK;
    } else if (!strncmp(argv[argi], "crl_check_all", 13)) {
	opts->vflags |= (X509_V_FLAG_CRL_CHECK
			 | X509_V_FLAG_CRL_CHECK_ALL);
    } else if (!strncmp(argv[argi], "re", 2) && isdigit(argv[argi][2])
	       && argv[argi][3] == '=') {
	int depth = atoi(argv[argi]+2);
	if (0 <= depth && depth < DEPTH_MAX) {
	    opts->regexp[depth] = strdup(argv[argi]+4);
	} else {
	    goto error;
	}
    } else if (!strncmp(argv[argi], "re-", 3) && isdigit(argv[argi][3])
	       && argv[argi][4] == '=') {
	int depth = atoi(argv[argi]+3);
	if (0 < depth && depth <= DEPTH_MAX) {
	    opts->regexp[DEPTH_MAX-depth] = strdup(argv[argi]+5);
	} else {
	    goto error;
	}
    } else if (!strncmp(argv[argi], "depth=", 6)) {
	opts->depth = atoi(argv[argi]+6);
	if (opts->depth >= DEPTH_MAX) opts->depth = DEPTH_MAX - 1;
	else if (opts->depth < 0) opts->depth = 0;
    } else if (!strcmp(argv[argi], "bugs")) {
	opts->off |= SSL_OP_ALL;
#ifndef OPENSSL_NO_TLS1
    } else if (!strcmp(argv[argi], "tls1")) {
	if (isserver) opts->meth = TLSv1_server_method();
	else opts->meth = TLSv1_client_method();
#endif
#ifndef OPENSSL_NO_SSL3
    } else if (!strcmp(argv[argi], "ssl3")) {
	if (isserver) opts->meth = SSLv3_server_method();
	else opts->meth = SSLv3_client_method();
#endif
#ifndef OPENSSL_NO_SSL2
    } else if (!strcmp(argv[argi], "ssl2")) {
	if (isserver) opts->meth = SSLv2_server_method();
	else opts->meth = SSLv2_client_method();
#endif
    } else if (!strcmp(argv[argi], "no_tls1")) {
	opts->off |= SSL_OP_NO_TLSv1;
    } else if (!strcmp(argv[argi], "no_ssl3")) {
	opts->off |= SSL_OP_NO_SSLv3;
    } else if (!strcmp(argv[argi], "no_ssl2")) {
	opts->off |= SSL_OP_NO_SSLv2;
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    } else if (!strcmp(argv[argi], "serverpref")) {
	opts->off |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
    } else if (!strcmp(argv[argi], "uniq")) {
	opts->serial = -1;
    } else if (!strncmp(argv[argi], "sid_ctx=", 8)) {
	opts->sid_ctx = strdup(argv[argi]+8);
    } else if (!strncmp(argv[argi], "key=", 4)) {
	opts->keyFile = strdup(argv[argi]+4);
    } else if (!strncmp(argv[argi], "cert=", 5)) {
	opts->certFile = strdup(argv[argi]+5);
    } else if (!strncmp(argv[argi], "CAfile=", 7)) {
	opts->caFile = strdup(argv[argi]+7);
    } else if (!strncmp(argv[argi], "CApath=", 7)) {
	opts->caPath = strdup(argv[argi]+7);
    } else if (!strncmp(argv[argi], "pfx=", 4)) {
	opts->pfxFile = strdup(argv[argi]+4);
    } else if (!strncmp(argv[argi], "passfile=", 9)) {
	FILE *fp = fopen(argv[argi]+9, "r");
	char str[STRMAX+1];
	int i;
	if (!fp) {
	    message(LOG_ERR, "Can't open passwd file: %s", argv[argi]+9);
	    help(argv[0], "ssl");
	    exit(1);
	}
	for (i=0; i < STRMAX; i++) {
	    int c = getc(fp);
	    if (c == '\r' || c == '\n' || c == EOF) break;
	    str[i] = c;
	}
	str[i] = '\0';
	fclose(fp);
	opts->passwd = strdup(str);
#ifdef CRYPTOAPI
    } else if (!strncmp(argv[argi], "store=", 6)) {
	opts->certStore = strdup(argv[argi]+6);
#endif
    } else if (!strncmp(argv[argi], "cipher=", 7)) {
	opts->cipherList = strdup(argv[argi]+7);
    } else if (!strncmp(argv[argi], "lb", 2) && isdigit(argv[argi][2])
	       && argv[argi][3] == '=') {
	opts->lbparm = argv[argi][2] - '0';
	opts->lbmod = atoi(argv[argi]+4);
    } else {
    error:
	message(LOG_ERR, "Invalid SSL Option: %s", argv[argi]);
	help(argv[0], "ssl");
	exit(1);
    }
    return argi;
}

#ifndef NO_THREAD
/* SSL callback */
unsigned long sslthread_id_callback(void) {
    unsigned long ret;
#ifdef WINDOWS
    ret = (unsigned long)GetCurrentThreadId();
#else
#ifdef PTHREAD
    ret = (unsigned long)pthread_self();
#endif
#endif
    if (Debug > 19) message(LOG_DEBUG, "SSL_thread id=%ld", ret);
    return ret;
}

void sslthread_lock_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	if (Debug > 19)
	    message(LOG_DEBUG, "SSL_lock mode=%x n=%d file=%s line=%d",
		    mode, n, file, line);
#ifdef WINDOWS
	WaitForSingleObject(SSLMutex[n], 500);
#else
#ifdef PTHREAD
	pthread_mutex_lock(&SSLMutex[n]);
#endif
#endif
    } else {
	if (Debug > 19)
	    message(LOG_DEBUG, "SSL_unlock mode=%x n=%d file=%s line=%d",
		    mode, n, file, line);
#ifdef WINDOWS
	ReleaseMutex(SSLMutex[n]);
#else
#ifdef PTHREAD
	pthread_mutex_unlock(&SSLMutex[n]);
#endif
#endif
    }
}

int sslthread_initialize(void) {
    int i;
    NSSLMutexs = CRYPTO_num_locks();
    SSLMutex = malloc(NSSLMutexs * sizeof(*SSLMutex));
    if (!SSLMutex) return -1;
    if (Debug > 1) message(LOG_DEBUG, "SSL thread nlocks=%d", NSSLMutexs);
    for (i=0; i < NSSLMutexs; i++) {
#ifdef WINDOWS
	SSLMutex[i] = CreateMutex(NULL, FALSE, NULL);
	if (!SSLMutex[i]) return -1;
#else
#ifdef PTHREAD
	pthread_mutex_init(&SSLMutex[i], NULL);
#endif
#endif
    }
#if defined(WINDOWS) || defined(PTHREAD)
    CRYPTO_set_id_callback(sslthread_id_callback);
    CRYPTO_set_locking_callback(sslthread_lock_callback);
    return 1;
#else
    return 0;
#endif
}
#endif
#endif

int dohyphen(char opt, int argc, char *argv[], int argi) {
    switch(opt) {
    case 'd':
	Debug++;
	break;
    case 'p':
	XHostsTrue->mode = ((XHostsTrue->mode & ~XHostsMode_Dump)
			    | (((XHostsTrue->mode & XHostsMode_Dump) + 1)
			       & XHostsMode_Dump));
	break;
#ifndef NO_SYSLOG
    case 'l':
	Syslog++;
	break;
#endif
    case 'L':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires log <file>", opt);
	    exit(1);
	}
	if (DryRun) break;
	if (!strcmp(argv[argi], "-")) {
	    LogFp = stdout;
	} else {
	    if (LogFp && LogFp != stderr) fclose(LogFp);
	    LogFp = fopen(argv[argi], "a");
	    if (LogFp == NULL) {
		LogFp = stderr;
		message(LOG_ERR, "Can't create log file: %s err=%d",
			argv[argi], errno);
		exit(1);
	    }
	    LogFileName = strdup(argv[argi]);
	}
	setbuf(LogFp, NULL);
	break;
    case 'a':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires accounting <file>", opt);
	    exit(1);
	}
	if (DryRun) break;
	if (!strcmp(argv[argi], "-")) {
	    AccFp = stdout;
	} else {
	    if (AccFp && AccFp != stdout) fclose(AccFp);
	    AccFp = fopen(argv[argi], "a");
	    if (AccFp == NULL) {
		message(LOG_ERR,
			"Can't create account log file: %s err=%d",
			argv[argi], errno);
		exit(1);
	    }
	    AccFileName = strdup(argv[argi]);
	}
	setbuf(AccFp, NULL);
	break;
    case 'i':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires pid <file>", opt);
	    exit(1);
	}
	PidFile = strdup(argv[argi]);
	break;
#ifndef NO_CHROOT
    case 't':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires <dir>", opt);
	    exit(1);
	}
	RootDir = strdup(argv[argi]);
	break;
#endif
    case 'n':
	AddrFlag = 1;
	break;
    case 'u':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires # of <max> UDP sessions",
		    opt);
	    exit(1);
	}
	OriginMax = atoi(argv[argi]);
	break;
    case 'X':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires size of Xfer buffer <n>",
		    opt);
	    exit(1);
	}
	XferBufMax = atoi(argv[argi]);
	break;
    case 'T':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires timeout <n>", opt);
	    exit(1);
	}
	PairTimeOut = atoi(argv[argi]);
	break;
    case 'A':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires length of backlog <n>", opt);
	    exit(1);
	}
	BacklogMax = atoi(argv[argi]);
	break;
#ifndef NO_SETUID
    case 'o':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires <uid>", opt);
	    exit(1);
	}
	SetUID = atoi(argv[argi]);
	break;
    case 'g':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires <gid>", opt);
	    exit(1);
	}
	SetGID = atoi(argv[argi]);
	break;
#endif
    case 'c':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires <dir> for core dump", opt);
	    exit(1);
	}
	CoreDumpDir = strdup(argv[argi]);
	break;
#ifndef NO_FORK
    case 'f':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires # of child processes <n>",
		    opt);
	    exit(1);
	}
	NForks = atoi(argv[argi]);
	break;
#endif
#ifdef UNIX_DAEMON
    case 'D':
	DaemonMode = 1;
	break;
#endif
    case 'r':
	ReuseAddr = 1;
	break;
    case 'x':
	argi = mkPortXhosts(argc, argi, argv);
	break;
    case 's':
	argi = mkChat(argc, argi, argv);
	break;
    case 'b':
	argi = mkBackup(argc, argi, argv);
	break;
    case 'B':
	argi = lbsopts(argc, argi, argv);
	break;
#ifdef ADDRCACHE
    case 'H':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires addr cache size <n>", opt);
	    exit(1);
	}
	AddrCacheSize = atoi(argv[argi]);
	break;
#endif
    case 'I':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires local interface <host>",
		    opt);
	    exit(1);
	}
	if (!argv[argi] || argv[argi][0] == '\0') {
	    ConnectFrom = NULL;
	} else {
	    char host[STRMAX+1];
	    char port[STRMAX+1];
	    struct sockaddr_storage ss;
	    struct sockaddr *sa = (struct sockaddr*)&ss;
	    socklen_t salen = sizeof(ss);
	    int pos = hostPortExt(argv[argi], host, port);
	    if (pos < 0) {
		sa->sa_family = AF_UNSPEC;
		if (!host2sa(argv[argi], NULL, sa, &salen, NULL, NULL, 0)) {
		    return -1;
		}
	    } else {
		sa->sa_family = AF_UNSPEC;
#ifdef AF_INET6
		if (pos && !strcmp(argv[argi]+pos, "v6"))
		    sa->sa_family = AF_INET6;
#endif
		if (!host2sa(host, port, sa, &salen, NULL, NULL, 0)) {
		    return -1;
		}
	    }
	    ConnectFrom = saDup(sa, salen);
	    if (!ConnectFrom) {
		message(LOG_CRIT, "Out of memory");
		exit(1);
	    }
	}
	break;
#ifdef USE_SSL
    case 'q':
	if (++argi >= argc) {
	    message(LOG_ERR, "Illegal Option: -q without <SSL>");
	    exit(1);
	}
	argi = sslopts(argc, argi, argv, &ClientOpts, 0);
	break;
    case 'z':
	if (++argi >= argc) {
	    message(LOG_ERR, "Illegal Option: -z without <SSL>");
	    exit(1);
	}
	argi = sslopts(argc, argi, argv, &ServerOpts, 1);
	break;
#endif
#ifdef CPP
    case 'P':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires preprocessor <command>",
		    opt);
	    exit(1);
	}
	CppCommand = strdup(argv[argi]);
	break;
    case 'Q':
	if (++argi >= argc) {
	    message(LOG_ERR, "option -%c requires <options> for preprocessor",
		    opt);
	    exit(1);
	}
	CppOptions = strdup(argv[argi]);
	break;
#endif
    default:
	return -1;
    }
    return argi;
}

#ifdef NT_SERVICE
int quoteToken(char *dst, char *src) {
    char buf[STRMAX+1];
    int len;
    if (strchr(src, ' ')) {
	snprintf(buf, STRMAX, "\"%s\"", src);
	len = strlen(buf);
	if (dst) strncpy(dst, buf, len);
    } else {
	len = strlen(src);
	if (dst) strncpy(dst, src, len);
    }
    return len;
}

void installService(int argc, char *argv[]) {
    SC_HANDLE scManager;
    SC_HANDLE scService;
    char exeName[STRMAX+1];
    char *command;
    int commax, len;
    int i;
    int state;
    char *p;
    if (!GetModuleFileName(0, exeName, sizeof(exeName))) {
	message(LOG_ERR, "Can't determine exe name err=%d",
		(int)GetLastError());
	exit(1);
    }
    scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
	message(LOG_ERR, "Can't open service control manager err=%d",
		(int)GetLastError());
	exit(1);
    }
    len = strlen(exeName);
    for (i=1; i < argc; i++) {
	len += 1 + quoteToken(NULL, argv[i]);
    }
    commax = len;
    len++;	/* for '\0' */
    command = malloc(len);
    if (!command) {
	message(LOG_CRIT, "Out of memory");
	exit(1);
    }
    strcpy(command, exeName);
    len = strlen(command);
    state = 0;
    for (i=1; i < argc; i++) {
	p = argv[i];
	switch(state) {
	case 0:
	    if (!strcmp(p, "-M")) state++;
	    break;
	case 1:
	    if (!strcmp(p, "install"))
		p = "run_svc";	/* assume same length */
	    break;
	}
	command[len++] = ' ';
	len += quoteToken(command+len, p);
    }
    command[len] = '\0';
    if (Debug > 1) message(LOG_DEBUG, "install: %s", command);
    scService
	= CreateService(scManager, NTServiceName,
			NTServiceDisplayName,
			SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
			SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
			command, NULL, NULL, "TcpIp\0\0",
			NULL, NULL);
    if (!scService) {
	message(LOG_ERR, "Can't install service: %s err=%d",
		NTServiceName, (int)GetLastError());
	CloseServiceHandle(scManager);
	exit(1);
    }
    message(LOG_INFO, "service installed: %s", NTServiceName);
    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
}

void removeService(void) {
    SC_HANDLE scManager;
    SC_HANDLE scService;
    scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
	message(LOG_ERR, "Can't open service control manager err=%d",
		(int)GetLastError());
	exit(1);
    }
    scService = OpenService(scManager, NTServiceName,
			    SERVICE_ALL_ACCESS);
    if (!scService) {
	message(LOG_ERR, "Can't open service: %s err=%d",
		NTServiceName, (int)GetLastError());
	CloseServiceHandle(scManager);
	exit(1);
    }
    if (ControlService(scService, SERVICE_CONTROL_STOP, &NTServiceStatus)) {
	do {
	    usleep(1000);
	} while (QueryServiceStatus(scService, &NTServiceStatus),
		 NTServiceStatus.dwCurrentState == SERVICE_STOP_PENDING);
	if (NTServiceStatus.dwCurrentState == SERVICE_STOPPED) {
	    message(LOG_INFO, "%s stopped", NTServiceName);
	} else {
	    message(LOG_ERR, "failed to stop %s", NTServiceName);
	}
    }
    if (!DeleteService(scService)) {
	message(LOG_ERR, "failed to remove service: %s err=%d",
		NTServiceName, (int)GetLastError());
	CloseServiceHandle(scService);
	CloseServiceHandle(scManager);
	exit(1);
    }
    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    message(LOG_INFO, "service removed: %s", NTServiceName);
}

void addEventSource(char *name) {
    HKEY hk;
    char key[LONGSTRMAX+1];
    char exeName[STRMAX+1];
    DWORD data;
    snprintf(key, LONGSTRMAX, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", name);
    if (RegCreateKey(HKEY_LOCAL_MACHINE, key, &hk)) return;
    if (!GetModuleFileName(0, exeName, sizeof(exeName))) return;
    if (RegSetValueEx(hk, "EventMessageFile", 0, REG_EXPAND_SZ,
		      exeName, strlen(exeName)+1)) return;
    data = (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
	    EVENTLOG_INFORMATION_TYPE);
    if (RegSetValueEx(hk, "TypesSupported", 0, REG_DWORD,
		      (LPBYTE)&data, sizeof(DWORD))) return;
    RegCloseKey(hk);
}
#endif

int doopts(int argc, char *argv[]) {
    int i;
    char *p;
    for (i=1; i < argc; i++) {
	p = argv[i];
	if (*p == '-') {
	    p++;
	    while(*p) {
		int ret = dohyphen(*p, argc, argv, i);
		if (ret >= 0) {
		    i = ret;
		} else switch(*p) {
		case '-':	/* end of global options */
		    return i+1;
		case 'h':
		    help(argv[0], argv[i+1]);
		    exit(1);
		    break;
		case 'N':
		    DryRun = 1;
		    break;
#ifdef NT_SERVICE
		case 'M':
		    i++;
		    if (i+1 >= argc) {
			message(LOG_ERR, "Illegal Option: -M without args");
			exit(1);
		    }
		    NTServiceName = strdup(argv[i+1]);
		    NTServiceDisplayName
			= malloc(strlen(NTServiceName)
				 + strlen(NTServiceDisplayPrefix) + 1);
		    if (!NTServiceDisplayName) {
			message(LOG_CRIT, "Out of memory");
			exit(1);
		    }
		    strcpy(NTServiceDisplayName, NTServiceDisplayPrefix);
		    strcat(NTServiceDisplayName, NTServiceName);
		    if (!strcmp(argv[i], "install")) {
			installService(argc, argv);
			exit(0);
		    } else if (!strcmp(argv[i], "remove")) {
			removeService();
			exit(0);
		    } else if (!strcmp(argv[i], "run_svc")) {
			addEventSource(NTServiceName);
			NTServiceLog
			    = RegisterEventSource(NULL, NTServiceName);
		    } else {
			message(LOG_ERR, "Illegal Option: -M %s %s",
				argv[i], argv[i+1]);
			exit(1);
		    }
		    i++;
		    break;
#endif
		case 'C':
		    if (!ConfigFile) {
			i++;
			ConfigFile = malloc(strlen(argv[i]) + 1);
			if (ConfigFile == NULL) {
			    message(LOG_CRIT, "Out of memory");
			    exit(1);
			}
			strcpy(ConfigFile, argv[i]);
			break;
		    }	/* drop through */
		default:
		    message(LOG_ERR, "Invalid Option: %s", argv[i]);
		    help(argv[0], "opt");
		    exit(1);
		}
		p++;
	    }
	} else break;
    }
    return i;
}

void doargs(int argc, int i, char *argv[]) {
    Stone *stone;
    char *host, *shost;
    char *serv, *sserv;
    int proto, sproto, dproto;
    char *p;
    int j, k;
    proto = sproto = dproto = 0;	/* default: TCP */
    if (argc - i < 1) {
	help(argv[0], NULL);
	exit(1);
    }
    for (; i < argc; i++) {
	p = argv[i];
	if (*p == '-') {
	    p++;
	    while(*p) {
		int ret = dohyphen(*p, argc, argv, i);
		if (ret >= 0) {
		    i = ret;
		} else {
		    message(LOG_ERR, "Invalid Option: %s", argv[i]);
		    help(argv[0], "opt");
		    exit(1);
		}
		p++;
	    }
	    continue;
	}
	host = strdup(argv[i]);
	j = getdist(host, &dproto);
	if (j > 0) {	/* with hostname */
	    i++;
	    if (j > 1) serv = host + j; else serv = NULL;
	    if (argc <= i) {
		help(argv[0], NULL);
		exit(1);
	    }
	    shost = strdup(argv[i]);
	    j = getdist(shost, &sproto);
	    if (j > 0) {
		if (j > 1) sserv = shost + j; else sserv = NULL;
	    } else if (j == 0) {
		sserv = shost;
		shost = NULL;
	    } else {
		message(LOG_ERR, "Invalid <sport>: %s", argv[i]);
		exit(1);
	    }
	} else {
	    message(LOG_ERR, "Invalid <host>:<port>: %s", argv[i]);
	    exit(1);
	}
	i++;
	j = 0;
	k = i;
	for (; i < argc; i++, j++) if (!strcmp(argv[i], "--")) break;
	if ((sproto & proto_udp)) {
	    proto |= proto_udp_s;
	    if (sproto & proto_v6) proto |= proto_v6_s;
	    if (sproto & proto_ip_only) proto |= proto_ip_only_s;
	} else {
	    if (sproto & proto_ohttp) proto |= proto_ohttp_s;
	    if (sproto & proto_ssl) proto |= proto_ssl_s;
	    if (sproto & proto_v6) proto |= proto_v6_s;
	    if (sproto & proto_ip_only) proto |= proto_ip_only_s;
	    if (sproto & proto_unix) proto |= proto_unix_s;
	    if (sproto & proto_block) proto |= proto_block_s;
	    if (sproto & proto_base) proto |= proto_base_s;
	    if (sproto & proto_ident) proto |= proto_ident;
	}
	if ((dproto & proto_udp)) {
	    proto |= proto_udp_d;
	    if (dproto & proto_v6) proto |= proto_v6_d;
	    if (dproto & proto_ip_only) proto |= proto_ip_only_d;
	} else {
	    if ((dproto & proto_command) == command_proxy) {
		proto &= ~proto_command;
		proto |= command_proxy;
#ifdef USE_POP
	    } else if ((dproto & proto_command) == command_pop) {
		proto &= ~proto_command;
		proto |= command_pop;
#endif
	    } else if (dproto & proto_ohttp) {
		proto |= proto_ohttp_d;
		goto extra_arg;
	    } else if ((dproto & proto_command) == command_ihead) {
		proto &= ~proto_command;
		proto |= command_ihead;
	      extra_arg:
		p = argv[k++];
		j--;
		if (k > argc || j < 0) {
		    help(argv[0], NULL);
		    exit(1);
		}
	    } else if ((dproto & proto_command) == command_iheads) {
		proto &= ~proto_command;
		proto |= command_iheads;
		goto extra_arg;
	    } else if ((dproto & proto_command) == command_health) {
		proto &= ~proto_command;
		proto |= command_health;
	    } else if ((dproto & proto_command) == command_identd) {
		proto &= ~proto_command;
		proto |= command_identd;
	    }
	    if (dproto & proto_ssl) proto |= proto_ssl_d;
	    if (dproto & proto_v6) proto |= proto_v6_d;
	    if (dproto & proto_ip_only) proto |= proto_ip_only_d;
	    if (dproto & proto_unix) proto |= proto_unix_d;
	    if (dproto & proto_block) proto |= proto_block_d;
	    if (dproto & proto_base) proto |= proto_base_d;
	    if (dproto & proto_nobackup) proto |= proto_nobackup;
	}
	if (!(proto & proto_udp_s) ^ !(proto & proto_udp_d)) {
	    message(LOG_ERR, "UDP TCP transform is not implemented yet");
	    exit(1);
	}
	stone = mkstone(host, serv, shost, sserv, j, &argv[k], proto);
	if (proto & proto_udp_s) {
	    Origin *origin = (Origin*)malloc(sizeof(Origin));
	    if (origin == NULL) {
	    memerr:
		message(LOG_CRIT, "Out of memory");
		exit(1);
	    }
	    bzero(origin, sizeof(Origin));
	    origin->stone = stone;
	    origin->common = type_origin;
	    origin->sd = INVALID_SOCKET;
	    origin->from = NULL;
	    origin->next = OriginTop;
	    OriginTop = origin;
	    stone->p = (char*)origin;
	} else if (proto & proto_ohttp_d) {
	    stone->p = strdup(p);
	} else if (((proto & proto_command) == command_ihead) ||
		   ((proto & proto_command) == command_iheads)) {
	    stone->p = strdup(p);
	}
	if (!(proto & proto_udp_s) || !(proto & proto_udp_d)) {
	    stone->pairs = newPair();
	    if (!stone->pairs) goto memerr;
	    stone->pairs->clock = -1;	/* top */
	    stone->pairs->stone = stone;
	    stone->pairs->next = PairTop;
	    if (PairTop) PairTop->prev = stone->pairs;
	    PairTop = stone->pairs;
	}
	stone->next = stones;
	stones = stone;
	proto = sproto = dproto = 0;	/* default: TCP */
    }
#ifndef USE_EPOLL
    for (stone=stones; stone != NULL; stone=stone->next) {
	FdSet(stone->sd, &rin);
	FdSet(stone->sd, &ein);
    }
#endif
}

#ifdef FD_SET_BUG
void checkFdSetBug(void) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(0, &set);
    FD_SET(0, &set);
    FD_CLR(0, &set);
    if (FD_ISSET(0, &set)) {
	if (Debug > 0)
	    message(LOG_DEBUG, "FD_SET bug detected");
	FdSetBug = 1;
    }
}
#endif

#ifndef WINDOWS
static void handler(int sig) {
    int i;
    switch(sig) {
    case SIGHUP:
	if (Debug > 4) message(LOG_DEBUG, "SIGHUP");
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    if (ConfigFile && !oldstones) {
	        oldstones = stones;
		stones = NULL;
		OldConfigArgc = ConfigArgc;
		OldConfigArgv = ConfigArgv;
		Debug = 0;
		getconfig();	/* reconfigure */
		i = doopts(ConfigArgc, ConfigArgv);
		doargs(ConfigArgc, i, ConfigArgv);
		for (i=0; i < NForks; i++) {
		    kill(Pid[i], SIGHUP);
		    kill(Pid[i], SIGINT);
		}
	    }
	} else {	/* child process */
#endif
	    message_pairs(LOG_INFO);
	    message_origins(LOG_INFO);
	    message_conns(LOG_INFO);
#ifndef NO_FORK
	}
#endif
	if (LogFileName) {
	    fclose(LogFp);
	    LogFp = fopen(LogFileName, "a");
	    if (LogFp == NULL) {
		LogFp = stderr;
		message(LOG_ERR, "Can't re-create log file: %s err=%d",
			LogFileName, errno);
		exit(1);
	    }
	    setbuf(LogFp, NULL);
	}
	if (AccFileName) {
	    fclose(AccFp);
	    AccFp = fopen(AccFileName, "a");
	    if (AccFp == NULL) {
		message(LOG_ERR, "Can't re-create account log file: %s err=%d",
			AccFileName, errno);
		exit(1);
	    }
	    setbuf(AccFp, NULL);
	}
	signal(SIGHUP, handler);
	break;
    case SIGTERM:
#ifdef IGN_SIGTERM
	Debug = 0;
	message(LOG_INFO, "SIGTERM. clear Debug level");
	signal(SIGTERM, handler);
	break;
#endif
    case SIGINT:
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    message(LOG_INFO, "SIGTERM/INT. killing children and exiting");
	    for (i=0; i < NForks; i++) kill(Pid[i], sig);
	} else
#endif
	    message(LOG_INFO, "SIGTERM/INT. exiting");  /* child process */
	exit(1);
    case SIGUSR1:
	Debug++;
	message(LOG_INFO, "SIGUSR1. increase Debug level to %d", Debug);
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    for (i=0; i < NForks; i++) kill(Pid[i], sig);
	} else {
#endif
	    message_pairs(LOG_INFO);
	    message_origins(LOG_INFO);
	    message_conns(LOG_INFO);
#ifndef NO_FORK
	}
#endif
	signal(SIGUSR1, handler);
	break;
    case SIGUSR2:
	if (Debug > 0) Debug--;
	message(LOG_INFO, "SIGUSR2. decrease Debug level to %d", Debug);
#ifndef NO_FORK
	if (NForks) {	/* mother process */
	    for (i=0; i < NForks; i++) kill(Pid[i], sig);
	}
#endif
	signal(SIGUSR2, handler);
	break;
    case SIGPIPE:
	if (Debug > 0) message(LOG_DEBUG, "SIGPIPE");
	signal(SIGPIPE, handler);
	break;
    case SIGSEGV:
    case SIGBUS:
    case SIGILL:
    case SIGFPE:
	if (CoreDumpDir) {
	    message(LOG_ERR, "Signal %d, core dumping to %s",
		    sig, CoreDumpDir);
	    if (chdir(CoreDumpDir) < 0) {
		message(LOG_ERR, "Can't chdir to %s err=%d",
			CoreDumpDir, errno);
	    } else {
		abort();
	    }
	} else {
	    message(LOG_ERR, "Signal %d, exiting", sig);
	}
	exit(1);
	break;
    default:
	message(LOG_INFO, "signal %d. Debug level: %d", sig, Debug);
    }
}
#endif

#ifdef UNIX_DAEMON
void daemonize(void) {
    pid_t pid;
    pid = fork();
    if (pid < 0) {
	message(LOG_ERR, "Can't create daemon err=%d", errno);
	exit(1);
    } 
    if (pid > 0) _exit(0);
    MyPid = getpid();
    if (setsid() < 0)
	message(LOG_WARNING, "Can't create new session err=%d", errno);
    if (chdir("/") < 0)
	message(LOG_WARNING, "Can't change directory to / err=%d", errno);
    umask(0022);
    if (close(0) != 0)
	message(LOG_WARNING, "Can't close stdin err=%d", errno);
    if (close(1) != 0)
	message(LOG_WARNING, "Can't close stdout err=%d", errno);
#ifndef NO_SYSLOG
    if (Syslog > 1) Syslog = 1;
#endif
    if (!LogFileName) LogFp = NULL;
    if (close(2) != 0)
	message(LOG_WARNING, "Can't close stderr err=%d", errno);
}
#endif

void initialize(int argc, char *argv[]) {
    int i, j;
#ifdef WINDOWS
    WSADATA WSAData;
    if (WSAStartup(MAKEWORD(1, 1), &WSAData)) {
	message(LOG_ERR, "Can't find winsock");
	exit(1);
    }
    atexit((void(*)(void))WSACleanup);
#endif
    MyPid = getpid();
    LogFp = stderr;
    setbuf(stderr, NULL);
#ifdef USE_SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    PairIndex = SSL_get_ex_new_index(0, "Pair index", NULL, NULL, NULL);
    MatchIndex = SSL_SESSION_get_ex_new_index(0, "Match index",
					      newMatch, NULL, freeMatch);
    RAND_poll();
    if (!RAND_status()) {
	message(LOG_WARNING, "Can't collect enough random seeds");
	srand(time(NULL));
	do {
	    u_short rnd = (u_short)rand();
	    RAND_seed(&rnd, sizeof(rnd));
	} while (!RAND_status());
    }
    sslopts_default(&ServerOpts, 1);
    sslopts_default(&ClientOpts, 0);
#endif
    XHostsTrue = malloc(XHostsBaseSize + sizeof(struct sockaddr_storage));
    if (!XHostsTrue) {
	message(LOG_CRIT, "Out of memory");
	exit(1);
    }
    XHostsTrue->next = NULL;
    XHostsTrue->mbits = 0;
    XHostsTrue->mode = 0;
    XHostsTrue->xhost.len = sizeof(struct sockaddr_storage);
    bzero(&XHostsTrue->xhost.addr, XHostsTrue->xhost.len);
    XHostsTrue->xhost.addr.sa_family = AF_UNSPEC;
    i = doopts(argc, argv);
    if (ConfigFile) {
	getconfig();
	j = doopts(ConfigArgc, ConfigArgv);
    }
#ifdef UNIX_DAEMON
    if (DaemonMode) daemonize();
#endif
    if (!DryRun && PidFile) {
	FILE *fp = fopen(PidFile, "w");
	if (fp) {
	    fprintf(fp, "%d\n", MyPid);
	    fclose(fp);
	}
    }
#ifndef NO_SYSLOG
    if (Syslog) {
	snprintf(SyslogName, STRMAX, "stone[%d]", MyPid);
	SyslogName[STRMAX] = '\0';
	openlog(SyslogName, 0, LOG_DAEMON);
	if (Syslog > 1) setbuf(stdout, NULL);
    }
#endif
    message(LOG_INFO, "start (%s) [%d]", VERSION, MyPid);
    if (Debug > 0) {
	message(LOG_DEBUG, "Debug level: %d", Debug);
    }
    trash.next = NULL;
    conns.next = NULL;
#ifndef USE_EPOLL
#ifdef FD_SET_BUG
    checkFdSetBug();
#endif
    FD_ZERO(&rin);
    FD_ZERO(&win);
    FD_ZERO(&ein);
#endif
    if (ConfigFile && ConfigArgc > j) {
	if (argc > i) doargs(argc, i, argv);
	doargs(ConfigArgc, j, ConfigArgv);
    } else {
	doargs(argc, i, argv);
    }
#ifndef WINDOWS
    signal(SIGHUP, handler);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
    signal(SIGPIPE, handler);
    signal(SIGUSR1, handler);
    signal(SIGUSR2, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    signal(SIGILL, handler);
    signal(SIGFPE, handler);
#endif
#ifndef NO_FORK
    if (!DryRun && NForks) {
	Pid = malloc(sizeof(pid_t) * NForks);
	if (!Pid) {
	    message(LOG_CRIT, "Out of memory");
	    exit(1);
	}
	for (i=0; i < NForks; i++) {
	    Pid[i] = fork();
	    if (!Pid[i]) break;
	}
	if (i >= NForks) {	/* the mother process */
	    pid_t id;
	    for (;;) {
		int status;
		id = wait(&status);
		if (id < 0) continue;
		message(LOG_WARNING, "Process died pid=%d, status=%x",
			id, status);
		for (i=0; i < NForks; i++) {
		    if (Pid[i] == id) break;
		}
		if (i < NForks) {
		    id = fork();
		    if (!id) break;	/* respawned child */
		    else Pid[i] = id;
		} else {
		    message(LOG_ERR, "This can't happen pid=%d", id);
		}
	    }
	}
	free(Pid);	/* child process */
	Pid = NULL;
	NForks = 0;
	MyPid = getpid();
#ifndef NO_SYSLOG
	if (Syslog) {
	    closelog();
	    snprintf(SyslogName, STRMAX, "stone[%d]", MyPid);
	    SyslogName[STRMAX] = '\0';
	    openlog(SyslogName, 0, LOG_DAEMON);
	}
#endif
	message(LOG_INFO, "child start (%s) [%d]", VERSION, MyPid);
    }
#endif
#ifdef PTHREAD
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#endif
#ifdef WINDOWS
    PairMutex = ConnMutex = OrigMutex = AsyncMutex = NULL;
    if (!(PairMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(ConnMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(OrigMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(AsyncMutex=CreateMutex(NULL, FALSE, NULL)) ||
#ifndef USE_EPOLL
	!(FdRinMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FdWinMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FdEinMutex=CreateMutex(NULL, FALSE, NULL)) ||
#endif
	!(ExBufMutex=CreateMutex(NULL, FALSE, NULL)) ||
	!(FPairMutex=CreateMutex(NULL, FALSE, NULL)) ||
#ifdef ADDRCACHE
	!(HashMutex=CreateMutex(NULL, FALSE, NULL)) ||
#endif
	!(PkBufMutex=CreateMutex(NULL, FALSE, NULL)) ) {
	message(LOG_ERR, "Can't create Mutex err=%d", (int)GetLastError());
    }
#endif
#ifdef OS2
    PairMutex = ConnMutex = OrigMutex = AsyncMutex = NULLHANDLE;
    if ((j=DosCreateMutexSem(NULL, &PairMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &ConnMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &OrigMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &AsyncMutex, 0, FALSE)) ||
#ifndef USE_EPOLL
	(j=DosCreateMutexSem(NULL, &FdRinMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FdWinMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FdEinMutex, 0, FALSE)) ||
#endif
	(j=DosCreateMutexSem(NULL, &ExBufMutex, 0, FALSE)) ||
	(j=DosCreateMutexSem(NULL, &FPairMutex, 0, FALSE)) ||
#ifdef ADDRCACHE
	(j=DosCreateMutexSem(NULL, &HashMutex, 0, FALSE)) ||
#endif
	(j=DosCreateMutexSem(NULL, &PkBufMutex, 0, FALSE)) ) {
	message(LOG_ERR, "Can't create Mutex err=%d", j);
    }
#endif
#ifndef NO_THREAD
#ifdef USE_SSL
    if (sslthread_initialize() < 0) {
	message(LOG_ERR, "Fail to initialize SSL callback");
    }
#endif
#endif
#ifndef NO_CHROOT
    if (RootDir) {
	char cwd[BUFMAX];
	int len = strlen(RootDir);
	getcwd(cwd, BUFMAX-1);
	if (strncmp(cwd, RootDir, len) != 0) len = -1;
	if (chroot(RootDir) < 0) {
	    message(LOG_WARNING, "Can't change root directory to %s", RootDir);
	} else if (len <= 0) {
	    if (Debug > 0)
		message(LOG_DEBUG, "cwd=%s is outside chroot=%s, so chdir /",
			cwd, RootDir);
	    if (chdir("/") < 0) {
		message(LOG_WARNING,
			"Can't change directory to chroot / err=%d", errno);
	    }
	}
    }
#endif
#ifndef NO_SETUID
    if (SetUID || SetGID) {
	if (AccFileName) fchown(fileno(AccFp), SetUID, SetGID);
	if (LogFileName) fchown(fileno(LogFp), SetUID, SetGID);
    }
    if (SetGID) if (setgid(SetGID) < 0 || setgroups(1, &SetGID) < 0) {
	message(LOG_WARNING, "Can't set gid err=%d", errno);
    }
    if (SetUID) if (setuid(SetUID) < 0) {
	message(LOG_WARNING, "Can't set uid err=%d", errno);
    }
#endif
#ifdef PR_SET_DUMPABLE
    if (CoreDumpDir && (SetUID || SetGID)) {
	if (prctl(PR_SET_DUMPABLE, 1) < 0) {
	    message(LOG_ERR, "prctl err=%d", errno);
	}
    }
#endif
    if (MinInterval > 0) {
	if (Debug > 1) message(LOG_DEBUG, "MinInterval: %d", MinInterval);
    }
    time(&lastEstablished);
    lastReadWrite = lastEstablished;
#ifdef USE_EPOLL
    /* ePollFd must be created in each process */
    ePollFd = epoll_create(BACKLOG_MAX);
    if (ePollFd < 0) {
	message(LOG_CRIT, "Can't create epoll err=%d", errno);
	exit(1);
    } else {
	Stone *stone;
	for (stone=stones; stone != NULL; stone=stone->next) {
	    struct epoll_event ev;
	    ev.events = (EPOLLIN | EPOLLPRI);
	    ev.data.ptr = stone;
	    if (Debug > 6)
		message(LOG_DEBUG, "stone %d: epoll_ctl %d ADD %x",
			stone->sd, ePollFd, (int)ev.data.ptr);
	    if (epoll_ctl(ePollFd, EPOLL_CTL_ADD, stone->sd, &ev) < 0) {
		message(LOG_CRIT, "stone %d: epoll_ctl %d ADD err=%d",
			stone->sd, ePollFd, errno);
		exit(1);
	    }
	}
    }
#endif
}

#ifdef NT_SERVICE
void scReportStatus(DWORD curState, DWORD exitCode, DWORD hint) {
    static DWORD checkPoint = 1;
    if (curState == SERVICE_START_PENDING)
	NTServiceStatus.dwControlsAccepted = 0;
    else
	NTServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    NTServiceStatus.dwCurrentState = curState;
    NTServiceStatus.dwWin32ExitCode = exitCode;
    NTServiceStatus.dwWaitHint = hint;
    if ((curState == SERVICE_RUNNING) || (curState == SERVICE_STOPPED))
	NTServiceStatus.dwCheckPoint = 0;
    else
	NTServiceStatus.dwCheckPoint = checkPoint++;
    SetServiceStatus(NTServiceStatusHandle, &NTServiceStatus);
}

void WINAPI serviceCtrl(DWORD code) {
    switch(code) {
    case SERVICE_CONTROL_STOP:
	scReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
	message(LOG_INFO, "Service stopping..");
	if (WaitForSingleObject(NTServiceThreadHandle, 1000) == WAIT_TIMEOUT)
	    TerminateThread(NTServiceThreadHandle, 0);
	break;
    default:
	break;
    }
}

DWORD WINAPI serviceThread(LPVOID lpParms) {
    do {
	repeater();
    } while (NTServiceStatus.dwCurrentState == SERVICE_RUNNING);
    ExitThread(0);
    return 0;
}

void WINAPI serviceMain(DWORD argc, LPTSTR *argv) {
    DWORD thid;
    NTServiceStatusHandle
	= RegisterServiceCtrlHandler(NTServiceName, serviceCtrl);
    if (!NTServiceStatusHandle) {
	message(LOG_ERR, "Can't register ServiceCtrlHandler");
	return;
    }
    NTServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    NTServiceStatus.dwServiceSpecificExitCode = 0;
    scReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    message(LOG_INFO, "Service started");
    scReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    NTServiceThreadHandle = CreateThread(0, 0, serviceThread, NULL, 0, &thid);
    if (NTServiceThreadHandle) {
	WaitForSingleObject(NTServiceThreadHandle, INFINITE);
	CloseHandle(NTServiceThreadHandle);
    }
    message(LOG_INFO, "Service stopped");
    scReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}
#endif

#ifdef CLEAR_ARGS
static void clear_args(int argc, char *argv[]) {
    char *argend = argv[argc-1] + strlen(argv[argc-1]);
    char *p;
    for (p=argv[1]; p < argend; p++) *p = '\0';	/* clear args */
}
#endif

int main(int argc, char *argv[]) {
    initialize(argc, argv);
    if (DryRun) return 0;
#ifdef NT_SERVICE
    if (NTServiceName) {
	SERVICE_TABLE_ENTRY dispatchTable[] =
	    {
		{ NTServiceName, (LPSERVICE_MAIN_FUNCTION)serviceMain },
		{ NULL, NULL }
	    };
	if (!StartServiceCtrlDispatcher(dispatchTable))
	    message(LOG_ERR, "StartServiceCtrlDispatcher failed");
	return 0;
    }
#endif
#ifdef CLEAR_ARGS
    clear_args(argc, argv);
#endif
#ifdef MEMLEAK_CHECK
    mtrace();
#endif
    for (;;) repeater();
    return 0;
}

/*
  For Gnu Emacs.
  Local Variables:
  tab-width: 8
  c-basic-offset: 4
  End:
*/
