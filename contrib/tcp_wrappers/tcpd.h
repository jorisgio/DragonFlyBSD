 /*
  * @(#) tcpd.h 1.5 96/03/19 16:22:24
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  *
  * $FreeBSD: src/contrib/tcp_wrappers/tcpd.h,v 1.2 2000/02/03 10:26:59 shin Exp $
  * $DragonFly: src/contrib/tcp_wrappers/tcpd.h,v 1.5 2005/09/24 02:34:11 sephe Exp $
  */

#ifndef _LIBWRAP_TCPD_H
#define _LIBWRAP_TCPD_H

#include <sys/cdefs.h>
#include <stdio.h>

/* Structure to describe one communications endpoint. */

#define STRING_LENGTH	128		/* hosts, users, processes */

struct host_info {
    char    name[STRING_LENGTH];	/* access via eval_hostname(host) */
    char    addr[STRING_LENGTH];	/* access via eval_hostaddr(host) */
#ifdef INET6
    struct sockaddr *sin;		/* socket address or 0 */
#else
    struct sockaddr_in *sin;		/* socket address or 0 */
#endif
    struct t_unitdata *unit;		/* TLI transport address or 0 */
    struct request_info *request;	/* for shared information */
};

/* Structure to describe what we know about a service request. */

struct request_info {
    int     fd;				/* socket handle */
    char    user[STRING_LENGTH];	/* access via eval_user(request) */
    char    daemon[STRING_LENGTH];	/* access via eval_daemon(request) */
    char    pid[10];			/* access via eval_pid(request) */
    struct host_info client[1];		/* client endpoint info */
    struct host_info server[1];		/* server endpoint info */
    void  (*sink) (int);		/* datagram sink function or 0 */
    void  (*hostname)			/* address to printable hostname */
	  (struct host_info *);
    void  (*hostaddr)			/* address to printable address */
	  (struct host_info *);
    void  (*cleanup) (void);		/* cleanup function or 0 */
    struct netconfig *config;		/* netdir handle */
};

/* Common string operations. Less clutter should be more readable. */

#define STRN_CPY(d,s,l)	{ strncpy((d),(s),(l)); (d)[(l)-1] = 0; }

#define STRN_EQ(x,y,l)	(strncasecmp((x),(y),(l)) == 0)
#define STRN_NE(x,y,l)	(strncasecmp((x),(y),(l)) != 0)
#define STR_EQ(x,y)	(strcasecmp((x),(y)) == 0)
#define STR_NE(x,y)	(strcasecmp((x),(y)) != 0)

 /*
  * Initially, all above strings have the empty value. Information that
  * cannot be determined at runtime is set to "unknown", so that we can
  * distinguish between `unavailable' and `not yet looked up'. A hostname
  * that we do not believe in is set to "paranoid".
  */

#define STRING_UNKNOWN	"unknown"	/* lookup failed */
#define STRING_PARANOID	"paranoid"	/* hostname conflict */

__BEGIN_DECLS
extern char unknown[];
extern char paranoid[];
__END_DECLS

#define HOSTNAME_KNOWN(s) (STR_NE((s),unknown) && STR_NE((s),paranoid))

#define NOT_INADDR(s) (s[strspn(s,"01234567890./")] != 0)

/* Global functions. */

__BEGIN_DECLS
#define fromhost sock_host

int		hosts_access(struct request_info *);/* access control */
int		hosts_ctl(char *, char *, char *, char *);/* limited interface to the hosts_access() routine */
void		shell_cmd(char *);		/* execute shell command */
char		*percent_x(char *, int, char *, struct request_info *);/* do %<char> expansion */
void		rfc931(struct sockaddr *, struct sockaddr *, char *);/* client name from RFC 931 daemon */
void		clean_exit(struct request_info *);/* clean up and exit */
void		refuse(struct request_info *);	/* clean up and exit */
char		*xgets(char *, int, FILE *);	/* fgets() on steroids */
char		*split_at(char *, int);		/* strchr() and split */
unsigned long	dot_quad_addr(char *);		/* restricted inet_addr() */

/* Global variables. */

extern int allow_severity;		/* for connection logging */
extern int deny_severity;		/* for connection logging */
extern char *hosts_allow_table;		/* for verification mode redirection */
extern char *hosts_deny_table;		/* for verification mode redirection */
extern int hosts_access_verbose;	/* for verbose matching mode */
extern int rfc931_timeout;		/* user lookup timeout */
extern int resident;			/* > 0 if resident process */

 /*
  * Routines for controlled initialization and update of request structure
  * attributes. Each attribute has its own key.
  */

struct request_info	*request_init(struct request_info *,...);/* initialize request */
struct request_info	*request_set(struct request_info *,...);/* update request structure */

#define RQ_FILE		1		/* file descriptor */
#define RQ_DAEMON	2		/* server process (argv[0]) */
#define RQ_USER		3		/* client user name */
#define RQ_CLIENT_NAME	4		/* client host name */
#define RQ_CLIENT_ADDR	5		/* client host address */
#define RQ_CLIENT_SIN	6		/* client endpoint (internal) */
#define RQ_SERVER_NAME	7		/* server host name */
#define RQ_SERVER_ADDR	8		/* server host address */
#define RQ_SERVER_SIN	9		/* server endpoint (internal) */

 /*
  * Routines for delayed evaluation of request attributes. Each attribute
  * type has its own access method. The trivial ones are implemented by
  * macros. The other ones are wrappers around the transport-specific host
  * name, address, and client user lookup methods. The request_info and
  * host_info structures serve as caches for the lookup results.
  */

char	*eval_user(struct request_info *);	/* client user */
char	*eval_hostname(struct host_info *);	/* printable hostname */
char	*eval_hostaddr(struct host_info *);	/* printable host address */
char	*eval_hostinfo(struct host_info *);	/* host name or address */
char	*eval_client(struct request_info *);	/* whatever is available */
char	*eval_server(struct request_info *);	/* whatever is available */
#define eval_daemon(r)	((r)->daemon)	/* daemon process name */
#define eval_pid(r)	((r)->pid)	/* process id */

/* Socket-specific methods, including DNS hostname lookups. */

void	sock_host(struct request_info *);	/* look up endpoint addresses */
void	sock_hostname(struct host_info *);	/* translate address to hostname */
void	sock_hostaddr(struct host_info *);	/* address to printable address */
#define sock_methods(r) \
	{ (r)->hostname = sock_hostname; (r)->hostaddr = sock_hostaddr; }

 /*
  * Problem reporting interface. Additional file/line context is reported
  * when available. The jump buffer (tcpd_buf) is not declared here, or
  * everyone would have to include <setjmp.h>.
  */

void	tcpd_warn(const char *, ...) __printflike(1, 2);/* report problem and proceed */
void	tcpd_jump(const char *, ...) __printflike(1, 2);/* report problem and jump */
__END_DECLS

struct tcpd_context {
    char   *file;			/* current file */
    int     line;			/* current line */
};
__BEGIN_DECLS
extern struct tcpd_context tcpd_context;
__END_DECLS

 /*
  * While processing access control rules, error conditions are handled by
  * jumping back into the hosts_access() routine. This is cleaner than
  * checking the return value of each and every silly little function. The
  * (-1) returns are here because zero is already taken by longjmp().
  */

#define AC_PERMIT	1		/* permit access */
#define AC_DENY		(-1)		/* deny_access */
#define AC_ERROR	AC_DENY		/* XXX */

__BEGIN_DECLS
 /*
  * In verification mode an option function should just say what it would do,
  * instead of really doing it. An option function that would not return
  * should clear the dry_run flag to inform the caller of this unusual
  * behavior.
  */

void	process_options(char *, struct request_info *);	/* execute options */
void	fix_options(struct request_info *);		/* get rid of IP-level socket options */

extern int dry_run;			/* verification flag */
__END_DECLS

#endif	/* !_LIBWRAP_TCPD_H */
