/*
 * Copyright (c) 2007 The DragonFly Project.  All rights reserved.
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
 * $DragonFly: src/test/syslink/test1.c,v 1.1 2007/05/28 05:28:12 dillon Exp $
 */
#include <sys/types.h>
#include <sys/syslink.h>
#include <sys/syslink_msg.h>
#include <errno.h>
#include <string.h>

static void reader(int fd);
static void writer(int fd);

int
main(int ac, char **av)
{
	union syslink_info_all info;
	int fd1;
	int fd2;

	bzero(&info, sizeof(info));
	if (syslink(SYSLINK_CMD_NEW, &info.head, sizeof(info)) < 0) {
		perror("syslink");
		exit(1);
	}
	printf("fds %d %d\n", info.cmd_new.fds[0], info.cmd_new.fds[1]);
	if (fork() == 0) {
		reader(info.cmd_new.fds[0]);
	} else {
		writer(info.cmd_new.fds[1]);
	}
	while (wait(NULL) > 0)
		;
	return(0);
}

static
void
writer(int fd)
{
	union syslink_small_msg cmd;
	union syslink_small_msg rep;
	int n;
	int wcount = 10;

	bzero(&cmd, sizeof(cmd));
	cmd.msg.sm_bytes = sizeof(struct syslink_msg);
	cmd.msg.sm_proto = SMPROTO_BSDVFS;
	cmd.msg.sm_head.se_cmd = 0;
	cmd.msg.sm_head.se_bytes = sizeof(cmd.msg.sm_head);
	for (;;) {
		++cmd.msg.sm_msgid;
		n = write(fd, &cmd, cmd.msg.sm_bytes);
		if (n < 0) {
			printf("write error %s\n", strerror(errno));
		} else if (wcount) {
			printf("write n = %d %lld\n", n, cmd.msg.sm_msgid);
			--wcount;
		} else {
			printf("write n = %d %lld\n", n, cmd.msg.sm_msgid);
			n = read(fd, &rep, sizeof(rep));
			printf("read-reply %d %lld\n", n, rep.msg.sm_msgid);
		}
	}
}

static
void
reader(int fd)
{
	union syslink_small_msg cmd;
	union syslink_small_msg rep;
	int n;

	bzero(&rep, sizeof(rep));
	rep.msg.sm_bytes = sizeof(struct syslink_msg);
	rep.msg.sm_proto = SMPROTO_BSDVFS | SM_PROTO_REPLY;
	rep.msg.sm_msgid = 1;
	rep.msg.sm_head.se_cmd = 0;
	rep.msg.sm_head.se_bytes = sizeof(rep.msg.sm_head);

	for (;;) {
		n = read(fd, &cmd, sizeof(cmd));
		if (n < 0 && errno == ENOSPC) {
			printf("no space\n");
			exit(1);
		}
		if (n < 0) {
			printf("read error %s\n", strerror(errno));
		} else {
			printf("read n = %d\n", n);
			rep.msg.sm_msgid = cmd.msg.sm_msgid;
			n = write(fd, &rep, rep.msg.sm_bytes);
			if (n < 0) {
				printf("reply error %s\n", strerror(errno));
			} else {
				printf("reply ok\n");
			}
		}
		if (n < 0)
			break;
		/*sleep(1);*/
	}
}

