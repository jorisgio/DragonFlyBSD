/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#)vsnprintf.c	8.1 (Berkeley) 6/4/93
 * $FreeBSD: src/lib/libc/stdio/vsnprintf.c,v 1.24 2008/04/17 22:17:54 jhb Exp $
 * $DragonFly: src/lib/libc/stdio/vsnprintf.c,v 1.9 2008/05/15 03:59:59 dillon Exp $
 */

#include <limits.h>
#include <stdio.h>
#include "local.h"
#include "priv_stdio.h"

int
vsnprintf(char * __restrict str, size_t n, const char * __restrict fmt,
	  __va_list ap)
{
	size_t on;
	int ret;
	char dummy[2];
	FILE f;

	on = n;
	if (n != 0)
		n--;
	if (n > INT_MAX)
		n = INT_MAX;
	/* Stdio internals do not deal correctly with zero length buffer */
	if (n == 0) {
		if (on > 0)
			*str = '\0';
		str = dummy;
		n = 1;
	}
	f.pub._fileno = -1;
	f.pub._flags = __SWR | __SSTR;
	f._bf._base = f.pub._p = (unsigned char *)str;
	f._bf._size = f.pub._w = n;
	memset(WCIO_GET(&f), 0, sizeof(struct wchar_io_data));
	ret = __vfprintf(&f, fmt, ap);
	if (on > 0)
		*f.pub._p = '\0';
	return (ret);
}
