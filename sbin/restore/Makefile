#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: src/sbin/restore/Makefile,v 1.13.2.3 2002/07/17 19:08:22 ru Exp $
# $DragonFly: src/sbin/restore/Makefile,v 1.5 2006/10/17 00:55:43 pavalos Exp $

PROG=	restore
LINKS=	${BINDIR}/restore ${BINDIR}/rrestore
CFLAGS+=-DRRESTORE
CFLAGS+=-I${.CURDIR}/../../libexec/rlogind
SRCS=	main.c interactive.c restore.c dirs.c symtab.c tape.c utilities.c \
	dumprmt.c
MAN=	restore.8
WARNS?= 0
MLINKS+=restore.8 rrestore.8
.PATH:	${.CURDIR}/../dump

.include <bsd.prog.mk>
