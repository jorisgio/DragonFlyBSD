# $Id: Makefile.inc,v 1.1 2000/07/14 18:16:22 iwasaki Exp $
# $FreeBSD: src/usr.sbin/acpi/Makefile.inc,v 1.8 2003/08/07 16:51:50 njl Exp $
# $DragonFly: src/usr.sbin/acpi/Makefile.inc,v 1.4 2006/06/14 15:50:09 y0netan1 Exp $

SYSDIR?= ${.CURDIR}/../../../sys
.include "${SYSDIR}/conf/acpi.mk"

.PATH:		${.OBJDIR}				\
		${ACPICA_UTIL_PATHS}

CFLAGS+=	-I${.OBJDIR}				\
		-I${SYSDIR}/${OSACPI_MI_DIR}		\
		-I${SYSDIR}/${ACPICA_DIR}/include	\
		-I${SYSDIR}/${ACPICA_DIR}/compiler

SRCS+=		${.OBJDIR}/acpi.h ${.OBJDIR}/platform/acenv.h

CLEANFILES+=	${.OBJDIR}/acpi.h
CLEANDIRS+=	${.OBJDIR}/platform

CSTD?=		gnu89
WARNS?=		1

.if exists(${.CURDIR}/../../Makefile.inc)
.include "${.CURDIR}/../../Makefile.inc"
.endif
