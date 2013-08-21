/*
 * Copyright (c) 2005 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/usr.sbin/dntpd/socket.c,v 1.4 2007/06/25 21:33:36 dillon Exp $
 */

#include "defs.h"

struct socket_msg {
	int result;
	struct sockaddr_storage addr;
};

#define ILOG_DNS_ERROR 1
#define IIGNORE_DNS_ERROR 0

static inline int
policy_enum_to_int(dns_error_policy_t policy);

static inline int
policy_enum_to_int(dns_error_policy_t policy)
{
	switch (policy) {
	case LOG_DNS_ERROR:
		return 1;
	case IGNORE_DNS_ERROR:
		return 0;
	}
}

struct request_msg {
	int index;
	int dns_error_policy;
};


static void
send_udp_socket_fd(int socket, int fd, struct sockaddr_storage *addr);

int
send_udp_socket_request(int socket, int index, dns_error_policy_t dns_error_policy)
{
	ssize_t n;
	struct request_msg request_msg;

	request_msg.index = index;
	request_msg.dns_error_policy = policy_enum_to_int(dns_error_policy);

	if ((n = send(socket, &request_msg, sizeof(struct request_msg), MSG_EOR))== -1) {
		logerr("cannot send request to privilege process");
		return (-1);
	}

	if (n < sizeof(struct request_msg)) {
		logerrstr("cannot send request to privilege process : request truncated");
		return (-1);
	}
	return (0);
}

void
receive_udp_socket_request(int socket, int nservers, struct server_name **server_name)
{
	ssize_t n;
	struct request_msg request_msg;
	struct sockaddr_storage addr;
	int fd;

	for (;;) {
		fd = -1;

		if ((n = recv(socket, &request_msg, sizeof(struct request_msg), 0))== -1) {
			logerr("cannot receive request to privilege process");
			return;
		}

		if (n == 0 ) {
			close(socket);
			exit(0);
		}

		if (n < sizeof(struct request_msg)) {
			logerrstr("cannot receive request to privilege process : request truncated");
			return;
		}


		if (request_msg.index >= nservers || request_msg.index < 0) {
			logerrstr("Invalid server number : %d (nservers = %d)",
			    request_msg.index, nservers);
		} else {
			fd = udp_socket(server_name[request_msg.index]->target,
			    123, (struct sockaddr *)&addr, request_msg.dns_error_policy);
		}

		send_udp_socket_fd(socket, fd, &addr);
		close(fd);
	}
}

static void
send_udp_socket_fd(int socket, int fd, struct sockaddr_storage *addr)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov;

	struct socket_msg reply;
	ssize_t n;

	bzero(&msg, sizeof(msg));
	bzero(&reply, sizeof(reply));

	if (fd >= 0) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = CMSG_LEN(sizeof(int));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *)CMSG_DATA(cmsg) = fd;
		bcopy(addr, &reply.addr, sizeof(struct sockaddr_storage));
	} else {
		reply.result = -1;
	}

	iov.iov_base = &reply;
	iov.iov_len = sizeof (struct socket_msg);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(socket, &msg, 0)) == -1)
		logerr("Error sending descriptor to worker process");

	if (n != sizeof (struct socket_msg))
		logerrstr("Truncate message sending descriptor to worker process");
}

int
receive_udp_socket_fd(int socket, server_info_t info)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov;

	struct socket_msg reply;
	ssize_t n;

	const char *ipstr;

	bzero(&msg,sizeof(msg));
	bzero(&reply, sizeof(reply));

	iov.iov_base = &reply;
	iov.iov_len = sizeof(struct socket_msg);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if ((n = recvmsg(socket, &msg, 0)) == -1) {
		logerr("Cannot receive udp socket from privileged process");
		return (-1);
	}

	if (n != sizeof(struct socket_msg)) {
		logerrstr("Truncate message receiving descriptor to worker process");
		return (-1);
	}

	if (reply.result == 0) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL) {
			logerrstr("No message header when receiving socket");
			return (-1);
		}
		if (cmsg->cmsg_type != SCM_RIGHTS)
			logerrstr("Receing fd : expected cmsg type %d (SCM_RIGHTS) but got %d",
			    SCM_RIGHTS, cmsg->cmsg_type);


		info->fd = (*(int *)CMSG_DATA(cmsg));
		ipstr = myaddr2ascii((struct sockaddr *)&reply.addr);
		info->ipstr = strdup(ipstr);
		return (0);
	} else {
		info->fd = -1;
		return (reply.result);
	}
}


int
udp_socket(const char *target, int port, struct sockaddr *sam,
	   dns_error_policy_t dns_error_policy)
{
    struct addrinfo hints, *res, *res0;
    char servname[128];
    const char *cause = NULL;
    int error;
    int fd;
    int tos;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(servname, sizeof(servname), "%d", port);
    error = getaddrinfo(target, servname, &hints, &res0);
    if (error) {
	if (dns_error_policy == ILOG_DNS_ERROR)
	    logerrstr("getaddrinfo (%s) init error: %s", target,
		gai_strerror(error));
        return(-1);
    }

    fd = -1;
    for (res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype,
        res->ai_protocol);
        if (fd < 0) {
           cause = "socket";
           continue;
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
            logerr("%s: unable to set non-blocking mode", target);
            close(fd);
            fd = -1;
            continue;
        }

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
           cause = "connect";
           close(fd);
           fd = -1;
           continue;
        }

	cap_rights_limit(fd, CAP_SEND | CAP_RECV);

        break;  /* okay we got one */
    }

    if (fd < 0) {
        logerr("Unable to establish a connection with %s: %s", target, cause);
        return(-1);
    }
    memcpy(sam, res->ai_addr, res->ai_addr->sa_len);
    freeaddrinfo(res0);

#ifdef IPTOS_LOWDELAY
    tos = IPTOS_LOWDELAY;
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#if 0
#ifdef IP_PORTRANGE
    tos = IP_PORTRANGE_HIGH;
    setsockopt(fd, IPPROTO_IP, IP_PORTRANGE, &tos, sizeof(tos));
#endif
#endif
    return(fd);
}
